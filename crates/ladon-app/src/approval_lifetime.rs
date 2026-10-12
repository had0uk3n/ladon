use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "gui")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ApprovalLifetime {
    #[default]
    ThirtyMinutes,
    EndOfDay,
    Session,
}

#[cfg(feature = "gui")]
impl ApprovalLifetime {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ThirtyMinutes => "30 minutes",
            Self::EndOfDay => "Until end of day",
            Self::Session => "Until session ends",
        }
    }

    pub(crate) fn approve(
        self,
        broker: &crate::LocalBrokerHandle,
        approval_id: uuid::Uuid,
    ) -> Result<(), ladon_core::LadonError> {
        match self {
            Self::ThirtyMinutes => broker.approve_for(approval_id, Duration::from_secs(30 * 60)),
            Self::EndOfDay => broker.approve_until(approval_id, local_day_end()?),
            Self::Session => broker.approve_session(approval_id),
        }
    }
}

#[cfg(feature = "gui")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum UnattendedLifetime {
    #[default]
    ThirtyMinutes,
    TwoHours,
    EightHours,
    TwelveHours,
    Custom,
}

#[cfg(feature = "gui")]
impl UnattendedLifetime {
    pub(crate) fn deadline_at(self, now: SystemTime) -> Result<SystemTime, ladon_core::LadonError> {
        let seconds = match self {
            Self::ThirtyMinutes => 30 * 60,
            Self::TwoHours => 2 * 3600,
            Self::EightHours => 8 * 3600,
            Self::TwelveHours => 12 * 3600,
            Self::Custom => return Err(ladon_core::LadonError::InvalidRequest),
        };
        now.checked_add(Duration::from_secs(seconds))
            .ok_or(ladon_core::LadonError::InvalidRequest)
    }
}

#[cfg(feature = "gui")]
fn local_time(now: SystemTime) -> Result<libc::tm, ladon_core::LadonError> {
    let timestamp = libc::time_t::try_from(
        now.duration_since(UNIX_EPOCH)
            .map_err(|_| ladon_core::LadonError::InvalidRequest)?
            .as_secs(),
    )
    .map_err(|_| ladon_core::LadonError::InvalidRequest)?;
    let mut local = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::localtime_r(&timestamp, local.as_mut_ptr()) }.is_null() {
        return Err(ladon_core::LadonError::InvalidRequest);
    }
    Ok(unsafe { local.assume_init() })
}

#[cfg(feature = "gui")]
pub(crate) fn local_deadline_at(
    value: &str,
    now: SystemTime,
) -> Result<SystemTime, ladon_core::LadonError> {
    let invalid = || ladon_core::LadonError::InvalidRequest;
    let bytes = value.as_bytes();
    if bytes.len() != 5
        || bytes[2] != b':'
        || ![bytes[0], bytes[1], bytes[3], bytes[4]]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return Err(invalid());
    }
    let hour = i32::from(bytes[0] - b'0') * 10 + i32::from(bytes[1] - b'0');
    let minute = i32::from(bytes[3] - b'0') * 10 + i32::from(bytes[4] - b'0');
    if hour >= 24 || minute >= 60 {
        return Err(invalid());
    }
    let mut local = local_time(now)?;
    for _ in 0..2 {
        local.tm_hour = hour;
        local.tm_min = minute;
        local.tm_sec = 0;
        local.tm_isdst = -1;
        let mut candidate = local;
        let timestamp = unsafe { libc::mktime(&mut candidate) };
        if candidate.tm_hour != hour || candidate.tm_min != minute {
            return Err(invalid());
        }
        let deadline = UNIX_EPOCH
            .checked_add(Duration::from_secs(
                u64::try_from(timestamp).map_err(|_| invalid())?,
            ))
            .ok_or_else(invalid)?;
        if let Ok(duration) = deadline.duration_since(now) {
            if !duration.is_zero() && duration <= Duration::from_secs(24 * 3600) {
                return Ok(deadline);
            }
        }
        local.tm_mday += 1;
    }
    Err(invalid())
}

#[cfg(feature = "gui")]
pub(crate) fn format_local_time(now: SystemTime) -> String {
    match local_time(now) {
        Ok(local) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} local",
            local.tm_year + 1900,
            local.tm_mon + 1,
            local.tm_mday,
            local.tm_hour,
            local.tm_min,
            local.tm_sec
        ),
        Err(_) => "Unavailable".to_owned(),
    }
}

/// Time remaining until the next local calendar day, including daylight-saving changes.
#[cfg(feature = "gui")]
pub(crate) fn local_day_end() -> Result<SystemTime, ladon_core::LadonError> {
    let now = SystemTime::now();
    Ok(now + until_local_day_end_at(now)?)
}

fn until_local_day_end_at(now: SystemTime) -> Result<Duration, ladon_core::LadonError> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ladon_core::LadonError::InvalidRequest)?;
    let timestamp = libc::time_t::try_from(elapsed.as_secs())
        .map_err(|_| ladon_core::LadonError::InvalidRequest)?;
    // localtime_r initializes the output on success. mktime normalizes the incremented
    // calendar date and resolves its UTC offset, rather than assuming a 24-hour day.
    let mut local = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::localtime_r(&timestamp, local.as_mut_ptr()) }.is_null() {
        return Err(ladon_core::LadonError::InvalidRequest);
    }
    let mut local = unsafe { local.assume_init() };
    local.tm_mday += 1;
    local.tm_hour = 0;
    local.tm_min = 0;
    local.tm_sec = 0;
    local.tm_isdst = -1;
    let midnight = unsafe { libc::mktime(&mut local) };
    let midnight = u64::try_from(midnight).map_err(|_| ladon_core::LadonError::InvalidRequest)?;
    Duration::from_secs(midnight)
        .checked_sub(elapsed)
        .ok_or(ladon_core::LadonError::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "gui")]
    #[test]
    fn unattended_deadlines_are_fixed_and_custom_time_is_within_one_day() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(
            UnattendedLifetime::EightHours.deadline_at(now).unwrap(),
            now + Duration::from_secs(8 * 3600)
        );
        assert!(local_deadline_at("25:00", now).is_err());
        assert!(local_deadline_at("12:60", now).is_err());
        assert!(local_deadline_at("tomorrow", now).is_err());
        let deadline = local_deadline_at("12:30", now).unwrap();
        assert!(deadline > now);
        assert!(deadline.duration_since(now).unwrap() <= Duration::from_secs(24 * 3600));
    }

    #[test]
    fn local_day_end_handles_midnight_month_end_and_dst() {
        // Each child owns its timezone, avoiding environment changes in a parallel harness.
        if let Ok(case) = std::env::var("LADON_DAY_END_TEST") {
            let (timestamp, seconds) = match case.as_str() {
                "utc" => (1_769_903_999, 1),            // 2026-01-31 23:59:59 UTC
                "spring" => (1_772_946_000, 23 * 3600), // New York, Mar 8 midnight
                "fall" => (1_793_505_600, 25 * 3600),   // New York, Nov 1 midnight
                _ => panic!("unknown fixture"),
            };
            assert_eq!(
                until_local_day_end_at(UNIX_EPOCH + Duration::from_secs(timestamp)).unwrap(),
                Duration::from_secs(seconds)
            );
            return;
        }
        for (case, timezone) in [
            ("utc", "UTC"),
            ("spring", "America/New_York"),
            ("fall", "America/New_York"),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "approval_lifetime::tests::local_day_end_handles_midnight_month_end_and_dst",
                    "--nocapture",
                ])
                .env("TZ", timezone)
                .env("LADON_DAY_END_TEST", case)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }
}
