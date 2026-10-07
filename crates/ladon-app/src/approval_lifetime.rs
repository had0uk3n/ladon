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
