//! Scalar syntax is read without evaluating imports, helpers or interpolation.
//! Findings contain offsets and rules only; decoded strings are zeroized.
use std::ops::Range;
use std::sync::LazyLock;

use base64::Engine;
use regex::Regex;
use zeroize::Zeroizing;

use super::ExposureRule;

pub(super) struct Detection {
    pub(super) range: Range<usize>,
    pub(super) rule: ExposureRule,
}

static ASSIGNMENTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>"(?:[^"\\]|\\.){1,256}"|'[^']{1,256}'|[A-Za-z_][A-Za-z0-9_./:-]{0,255})
        [\t\x20]* [=:] [\t\x20]*
        (?P<value>"""(?s:.*?)"""|'''(?s:.*?)'''|"(?:[^"\\]|\\.)*"|'[^']*'
          |(?i:Bearer|Basic)[\t\x20]+[A-Za-z0-9._~+/-]+=*
          |(?:\$\{[^}\r\n]*\}|[^\s,;{}\[\]"'])+)
        "#,
    )
    .expect("static assignment pattern")
});

static TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        \b(?:
          gh[pousr]_[A-Za-z0-9]{36,}
          |github_pat_[A-Za-z0-9_]{40,}
          |sk-(?:ant-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{20,})
          |(?:sk|rk)_live_[A-Za-z0-9]{16,}
          |glpat-[A-Za-z0-9_-]{20,}
          |npm_[A-Za-z0-9]{36,}
          |xox[baprs]-[A-Za-z0-9-]{20,}
          |AIza[A-Za-z0-9_-]{35}
          |eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}
        )\b",
    )
    .expect("static token pattern")
});

static URLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>]+"#).expect("static URL pattern")
});

static BEARER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bBearer[\t ]+([A-Za-z0-9._~+/-]{8,}=*)"#).expect("static bearer pattern")
});

static PRIVATE_KEYS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[\t ]*-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
        .expect("static private key pattern")
});

pub(super) fn detect(
    text: &str,
    limit: usize,
    stopped: &mut impl FnMut() -> bool,
) -> (Vec<Detection>, bool) {
    let mut detections: Vec<Detection> = Vec::new();
    let mut incomplete = false;
    // One occurrence can match its field name, token shape and Bearer context.
    // Count it once, keeping the more specific rule seen first.
    fn add(
        detections: &mut Vec<Detection>,
        range: Range<usize>,
        rule: ExposureRule,
        limit: usize,
    ) -> bool {
        if detections
            .iter()
            .any(|found| found.range.start < range.end && range.start < found.range.end)
        {
            return true;
        }
        if detections.len() >= limit {
            return false;
        }
        detections.push(Detection { range, rule });
        true
    }
    'scan: {
        macro_rules! record {
            ($range:expr, $rule:expr) => {
                if stopped() || !add(&mut detections, $range, $rule, limit) {
                    incomplete = true;
                    break 'scan;
                }
            };
        }
        for found in PRIVATE_KEYS.find_iter(text) {
            // Traditional encrypted PEM uses a plaintext RSA/EC header.
            let following = &text[found.end()..];
            let encrypted = following
                .lines()
                .take(4)
                .any(|line| line.trim().eq_ignore_ascii_case("Proc-Type: 4,ENCRYPTED"));
            let openssh_plain = found.as_str().trim() != "-----BEGIN OPENSSH PRIVATE KEY-----"
                || openssh_is_plain(following);
            if !encrypted && openssh_plain {
                record!(found.range(), ExposureRule::PrivateKeyHeader);
            }
        }
        for found in TOKENS.find_iter(text) {
            if plausible_value(found.as_str()) {
                record!(found.range(), ExposureRule::TokenPattern);
            }
        }
        for found in URLS.find_iter(text) {
            if connection_password(found.as_str()) {
                record!(found.range(), ExposureRule::ConnectionString);
            }
        }
        for captures in BEARER.captures_iter(text) {
            let value = captures.get(1).expect("bearer capture");
            if plausible_value(value.as_str()) {
                record!(value.range(), ExposureRule::TokenPattern);
            }
        }
        for captures in ASSIGNMENTS.captures_iter(text) {
            if stopped() {
                incomplete = true;
                break;
            }
            let matched_key = captures.name("key").expect("key capture");
            let key = decoded(matched_key.as_str());
            let matched = captures.name("value").expect("value capture");
            if matched.as_str().starts_with('#') {
                continue;
            }
            let mut range = matched.range();
            if matches!(matched.as_str(), "|" | ">" | "|-" | ">-" | "|+" | ">+") {
                let Some(block) = yaml_block(text, matched_key.start(), matched.end()) else {
                    continue;
                };
                range = block;
            }
            let value = decoded(&text[range.clone()]);
            if !plausible_value(&value) {
                continue;
            }
            if value.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                || value.contains("Proc-Type: 4,ENCRYPTED")
                || value
                    .split_once("-----BEGIN OPENSSH PRIVATE KEY-----")
                    .is_some_and(|(_, following)| !openssh_is_plain(following))
            {
                continue;
            }
            let rule = if PRIVATE_KEYS.is_match(&value) {
                Some(ExposureRule::PrivateKeyHeader)
            } else if connection_password(&value) {
                Some(ExposureRule::ConnectionString)
            } else if TOKENS.is_match(&value) || BEARER.is_match(&value) {
                Some(ExposureRule::TokenPattern)
            } else if credential_key(&key) {
                Some(ExposureRule::CredentialAssignment)
            } else if high_entropy(&value) {
                Some(ExposureRule::HighEntropyValue)
            } else {
                None
            };
            if let Some(rule) = rule {
                record!(range, rule);
            }
        }
    }
    detections.sort_by_key(|found| found.range.start);
    (detections, incomplete)
}

fn yaml_block(text: &str, key_offset: usize, value_end: usize) -> Option<Range<usize>> {
    let line_start = text[..key_offset].rfind('\n').map_or(0, |at| at + 1);
    let indent = text[line_start..]
        .bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count();
    let start = value_end + text[value_end..].find('\n')? + 1;
    let mut end = start;
    for line in text[start..].split_inclusive('\n') {
        let leading = line
            .bytes()
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        if !line.trim().is_empty() && leading <= indent {
            break;
        }
        end += line.len();
    }
    (end > start && !text[start..end].trim().is_empty()).then_some(start..end)
}

fn openssh_is_plain(following: &str) -> bool {
    let body = following
        .split("-----END OPENSSH PRIVATE KEY-----")
        .next()
        .unwrap_or("");
    // The cipher name is near the start. Never copy/decode the private key body.
    let prefix = Zeroizing::new(
        body.chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .take(128)
            .collect::<String>(),
    );
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(prefix.as_bytes()) else {
        return false;
    };
    let bytes = Zeroizing::new(bytes);
    bytes.starts_with(b"openssh-key-v1\0\0\0\0\x04none")
}

fn decoded(value: &str) -> Zeroizing<String> {
    if value.starts_with('"') && value.ends_with('"') {
        if let Ok(decoded) = serde_json::from_str::<String>(value) {
            return Zeroizing::new(decoded);
        }
    }
    Zeroizing::new(value.trim_matches(['"', '\'']).to_owned())
}

fn credential_key(key: &str) -> bool {
    let key = Zeroizing::new(key.to_ascii_lowercase().replace('-', "_"));
    let compact = Zeroizing::new(key.replace('_', ""));
    [
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "accesskey",
        "privatekey",
    ]
    .iter()
    .any(|suffix| compact.ends_with(suffix))
        || matches!(key.as_str(), "authorization" | "_auth" | "credential")
}

fn plausible_value(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.len() > 16 * 1024 {
        return false;
    }
    let lower = Zeroizing::new(value.to_ascii_lowercase());
    let environment_reference = value.strip_prefix('$').is_some_and(|name| {
        name.bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    });
    !(environment_reference
        || value.starts_with("$(")
        || lower.contains(concat!("$", "{"))
        || lower.contains("{{")
        || (lower.starts_with('<') && lower.ends_with('>'))
        || lower.starts_with("your_")
        || lower.starts_with("your-")
        || lower.starts_with("your ")
        || lower.starts_with("replace_")
        || lower.starts_with("insert_")
        || matches!(
            lower.as_str(),
            "null"
                | "none"
                | "true"
                | "false"
                | "changeme"
                | "change_me"
                | "placeholder"
                | "example"
                | "dummy"
                | "redacted"
        )
        || lower.chars().all(|ch| matches!(ch, 'x' | '*' | '-')))
}

fn connection_password(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once("://") else {
        return false;
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or("");
    let Some((credentials, host)) = authority.rsplit_once('@') else {
        return false;
    };
    let Some((_, password)) = credentials.split_once(':') else {
        return false;
    };
    !host.is_empty() && plausible_value(password)
}

fn high_entropy(value: &str) -> bool {
    if !(24..=256).contains(&value.len())
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || !value.bytes().any(|byte| byte.is_ascii_lowercase())
        || !value.bytes().any(|byte| byte.is_ascii_uppercase())
        || !value.bytes().any(|byte| byte.is_ascii_digit())
        || value.contains("://")
        || value.contains('/')
        || value.contains('\\')
    {
        return false;
    }
    let mut frequencies = [0usize; 128];
    for byte in value.bytes() {
        frequencies[usize::from(byte)] += 1;
    }
    let entropy: f64 = frequencies
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / value.len() as f64;
            -probability * probability.log2()
        })
        .sum();
    entropy >= 4.3
}
