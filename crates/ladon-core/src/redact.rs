use std::{collections::VecDeque, mem};

use base64::{Engine, engine::general_purpose};
use memchr::memmem;
use zeroize::Zeroizing;

use crate::{FieldName, LadonError, SecretId, SensitiveBytes};

pub const DEFAULT_OUTPUT_LIMIT_BYTES: usize = 512 * 1024;
pub const MAX_OUTPUT_LIMIT_BYTES: usize = 2 * 1024 * 1024;
pub const MIN_OUTPUT_LIMIT_BYTES: usize = 128;
const REDACTION_MARKER: &str = "[REDACTED]";

pub struct RedactionSecret {
    value: SensitiveBytes,
}

impl RedactionSecret {
    #[must_use]
    pub fn new(_id: SecretId, _field: FieldName, value: SensitiveBytes) -> Self {
        Self { value }
    }
}

struct Pattern {
    needle: SensitiveBytes,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RedactedOutput {
    pub text: String,
    pub redaction_count: u64,
    pub truncated: bool,
    pub omitted_bytes: u64,
    pub suppressed: bool,
}

pub struct StreamingRedactor {
    patterns: Vec<Pattern>,
    maximum_pattern_bytes: usize,
    pending: Zeroizing<Vec<u8>>,
    marker: &'static str,
    utf8: Utf8Escaper,
    capture: BoundedCapture,
    redaction_count: u64,
    suppressed: bool,
}

impl StreamingRedactor {
    pub fn new(
        secrets: Vec<RedactionSecret>,
        output_limit_bytes: usize,
    ) -> Result<Self, LadonError> {
        if !(MIN_OUTPUT_LIMIT_BYTES..=MAX_OUTPUT_LIMIT_BYTES).contains(&output_limit_bytes) {
            return Err(LadonError::InvalidOutputLimit);
        }

        let mut patterns = Vec::new();
        let mut suppressed = false;
        for secret in secrets {
            secret.value.expose(|value| {
                if value.is_empty() {
                    return;
                }
                if value.len() < 4 {
                    suppressed = true;
                }
                add_pattern(&mut patterns, value.to_vec());
                add_pattern(&mut patterns, encode_hex(value, false));
                add_pattern(&mut patterns, encode_hex(value, true));
                add_pattern(
                    &mut patterns,
                    general_purpose::STANDARD.encode(value).into_bytes(),
                );
                add_pattern(
                    &mut patterns,
                    general_purpose::STANDARD_NO_PAD.encode(value).into_bytes(),
                );
                add_pattern(
                    &mut patterns,
                    general_purpose::URL_SAFE.encode(value).into_bytes(),
                );
                add_pattern(
                    &mut patterns,
                    general_purpose::URL_SAFE_NO_PAD.encode(value).into_bytes(),
                );
                if let Ok(text) = std::str::from_utf8(value) {
                    if let Ok(json) = serde_json::to_string(text) {
                        let json = Zeroizing::new(json);
                        add_pattern(&mut patterns, json.as_bytes()[1..json.len() - 1].to_vec());
                    }
                    add_pattern(&mut patterns, percent_encode(value, false));
                    add_pattern(&mut patterns, percent_encode(value, true));
                }
            });
        }
        patterns.sort_by_key(|pattern| std::cmp::Reverse(pattern.needle.len()));
        let maximum_pattern_bytes = patterns
            .iter()
            .map(|pattern| pattern.needle.len())
            .max()
            .unwrap_or(1);
        let marker = if contains_pattern(REDACTION_MARKER.as_bytes(), &patterns) {
            ""
        } else {
            REDACTION_MARKER
        };

        Ok(Self {
            patterns,
            maximum_pattern_bytes,
            pending: Zeroizing::new(Vec::new()),
            marker,
            utf8: Utf8Escaper::default(),
            capture: BoundedCapture::new(output_limit_bytes),
            redaction_count: 0,
            suppressed,
        })
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if self.suppressed {
            return;
        }
        self.pending.extend_from_slice(bytes);
        self.process(false);
    }

    #[must_use]
    pub fn finish(mut self) -> RedactedOutput {
        if self.suppressed {
            return RedactedOutput {
                text: String::new(),
                redaction_count: 0,
                truncated: false,
                omitted_bytes: 0,
                suppressed: true,
            };
        }
        self.process(true);
        self.utf8.finish(&mut self.capture);
        let (text, truncated, omitted_bytes) = self.capture.finish();
        if contains_pattern(text.as_bytes(), &self.patterns) {
            return RedactedOutput {
                text: String::new(),
                redaction_count: self.redaction_count,
                truncated,
                omitted_bytes,
                suppressed: true,
            };
        }
        RedactedOutput {
            text,
            redaction_count: self.redaction_count,
            truncated,
            omitted_bytes,
            suppressed: false,
        }
    }

    fn process(&mut self, finishing: bool) {
        let buffer = mem::take(&mut self.pending);
        let safe_end = if finishing {
            buffer.len()
        } else {
            buffer
                .len()
                .saturating_sub(self.maximum_pattern_bytes.saturating_sub(1))
        };
        let mut position = 0;

        while position < safe_end {
            let next = find_next(&buffer, position, safe_end, &self.patterns);
            let Some((start, pattern_index)) = next else {
                self.utf8
                    .push(&buffer[position..safe_end], &mut self.capture);
                position = safe_end;
                break;
            };
            self.utf8.push(&buffer[position..start], &mut self.capture);
            let pattern = &self.patterns[pattern_index];
            self.utf8.push(self.marker.as_bytes(), &mut self.capture);
            position = start + pattern.needle.len();
            self.redaction_count = self.redaction_count.saturating_add(1);
        }

        self.pending.extend_from_slice(&buffer[position..]);
    }
}

fn contains_pattern(haystack: &[u8], patterns: &[Pattern]) -> bool {
    patterns.iter().any(|pattern| {
        pattern
            .needle
            .expose(|needle| memmem::find(haystack, needle).is_some())
    })
}

fn find_next(
    buffer: &[u8],
    position: usize,
    safe_end: usize,
    patterns: &[Pattern],
) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    for (index, pattern) in patterns.iter().enumerate() {
        let Some(found) = pattern
            .needle
            .expose(|needle| memmem::find(&buffer[position..], needle))
        else {
            continue;
        };
        let start = position + found;
        if start >= safe_end {
            continue;
        }
        match best {
            None => best = Some((start, index)),
            Some((best_start, best_index))
                if start < best_start
                    || (start == best_start
                        && pattern.needle.len() > patterns[best_index].needle.len()) =>
            {
                best = Some((start, index));
            }
            _ => {}
        }
    }
    best
}

fn add_pattern(patterns: &mut Vec<Pattern>, bytes: Vec<u8>) {
    let needle = SensitiveBytes::new(bytes);
    if needle.is_empty()
        || patterns.iter().any(|pattern| {
            pattern
                .needle
                .expose(|existing| needle.expose(|candidate| existing == candidate))
        })
    {
        return;
    }
    patterns.push(Pattern { needle });
}

fn encode_hex(value: &[u8], uppercase: bool) -> Vec<u8> {
    let alphabet = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut output = Vec::with_capacity(value.len() * 2);
    for byte in value {
        output.push(alphabet[(byte >> 4) as usize]);
        output.push(alphabet[(byte & 0x0f) as usize]);
    }
    output
}

fn percent_encode(value: &[u8], lowercase: bool) -> Vec<u8> {
    let alphabet = if lowercase {
        b"0123456789abcdef"
    } else {
        b"0123456789ABCDEF"
    };
    let mut output = Vec::with_capacity(value.len() * 3);
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(*byte);
        } else {
            output.push(b'%');
            output.push(alphabet[(byte >> 4) as usize]);
            output.push(alphabet[(byte & 0x0f) as usize]);
        }
    }
    output
}

#[derive(Default)]
struct Utf8Escaper {
    pending: Zeroizing<Vec<u8>>,
}

impl Utf8Escaper {
    fn push(&mut self, bytes: &[u8], capture: &mut BoundedCapture) {
        let mut buffer = mem::take(&mut self.pending);
        buffer.extend_from_slice(bytes);
        let mut position = 0;
        while position < buffer.len() {
            match std::str::from_utf8(&buffer[position..]) {
                Ok(valid) => {
                    capture.push_str(valid);
                    position = buffer.len();
                }
                Err(error) => {
                    let valid_end = position + error.valid_up_to();
                    if let Ok(valid) = std::str::from_utf8(&buffer[position..valid_end]) {
                        capture.push_str(valid);
                    }
                    let Some(invalid_bytes) = error.error_len() else {
                        self.pending.extend_from_slice(&buffer[valid_end..]);
                        position = buffer.len();
                        continue;
                    };
                    for byte in &buffer[valid_end..valid_end + invalid_bytes] {
                        capture.push_str(&format!("\\x{byte:02x}"));
                    }
                    position = valid_end + invalid_bytes;
                }
            }
        }
    }

    fn finish(&mut self, capture: &mut BoundedCapture) {
        let pending = mem::take(&mut self.pending);
        for byte in pending.iter() {
            capture.push_str(&format!("\\x{byte:02x}"));
        }
    }
}

struct BoundedCapture {
    limit: usize,
    head_capacity: usize,
    tail_capacity: usize,
    head: Vec<u8>,
    tail: VecDeque<u8>,
    tail_started: bool,
    total_bytes: u64,
}

impl BoundedCapture {
    fn new(limit: usize) -> Self {
        let head_capacity = limit / 2;
        Self {
            limit,
            head_capacity,
            tail_capacity: limit - head_capacity,
            head: Vec::with_capacity(head_capacity),
            tail: VecDeque::with_capacity(limit - head_capacity),
            tail_started: false,
            total_bytes: 0,
        }
    }

    fn push_str(&mut self, value: &str) {
        for character in value.chars() {
            let mut encoded = [0; 4];
            let bytes = character.encode_utf8(&mut encoded).as_bytes();
            self.total_bytes = self.total_bytes.saturating_add(bytes.len() as u64);
            if !self.tail_started && self.head.len() + bytes.len() <= self.head_capacity {
                self.head.extend_from_slice(bytes);
            } else {
                self.tail_started = true;
                self.tail.extend(bytes);
                while self.tail.len() > self.tail_capacity {
                    pop_front_character(&mut self.tail);
                }
            }
        }
    }

    fn finish(mut self) -> (String, bool, u64) {
        let captured = self.head.len() + self.tail.len();
        if self.total_bytes <= self.limit as u64 && captured == self.total_bytes as usize {
            let mut bytes = self.head;
            bytes.extend(self.tail);
            return (String::from_utf8_lossy(&bytes).into_owned(), false, 0);
        }

        loop {
            let omitted = self
                .total_bytes
                .saturating_sub((self.head.len() + self.tail.len()) as u64);
            let marker = format!("\n...[{omitted} bytes omitted]...\n");
            if self.head.len() + marker.len() + self.tail.len() <= self.limit {
                let mut bytes = self.head;
                bytes.extend_from_slice(marker.as_bytes());
                bytes.extend(self.tail);
                return (String::from_utf8_lossy(&bytes).into_owned(), true, omitted);
            }
            pop_front_character(&mut self.tail);
        }
    }
}

fn pop_front_character(bytes: &mut VecDeque<u8>) {
    let Some(first) = bytes.front().copied() else {
        return;
    };
    let width = match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    for _ in 0..width {
        bytes.pop_front();
    }
}
