use std::{collections::VecDeque, time::Duration};

use crate::{FieldName, SecretId};

const MAX_ACTIVITY_ENTRIES: usize = 100;
const MAX_ACTIVITY_REFERENCES: usize = 16;

pub trait MonotonicClock {
    fn now_millis(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Locked,
    UnlockPending,
    Unlocked,
    Running,
    Locking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerDecision {
    NoChange,
    PromptUnlock,
    Authorized,
    Busy,
    Denied,
    UnlockTimedOut,
    CancelRunBeforeLock,
    Locked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockReason {
    Manual,
    Mcp,
    ScreenLock,
    Suspend,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityOutcome {
    Succeeded,
    Failed,
    Denied,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferencedField {
    pub secret_id: SecretId,
    pub field: FieldName,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityEntry {
    pub client_label: String,
    pub executable: Option<String>,
    pub referenced_fields: Vec<ReferencedField>,
    pub timestamp_millis: u64,
    pub outcome: ActivityOutcome,
    pub redaction_count: u64,
}

enum State {
    Locked,
    UnlockPending { deadline_millis: u64 },
    Unlocked { last_activity_millis: u64 },
    Running,
    Locking,
}

pub struct BrokerState<C> {
    clock: C,
    idle_timeout_millis: u64,
    state: State,
    activities: VecDeque<ActivityEntry>,
}

impl<C: MonotonicClock> BrokerState<C> {
    #[must_use]
    pub fn new(clock: C, idle_timeout: Duration) -> Self {
        Self {
            clock,
            idle_timeout_millis: duration_millis(idle_timeout),
            state: State::Locked,
            activities: VecDeque::with_capacity(MAX_ACTIVITY_ENTRIES),
        }
    }

    #[must_use]
    pub const fn status(&self) -> SessionStatus {
        match self.state {
            State::Locked => SessionStatus::Locked,
            State::UnlockPending { .. } => SessionStatus::UnlockPending,
            State::Unlocked { .. } => SessionStatus::Unlocked,
            State::Running => SessionStatus::Running,
            State::Locking => SessionStatus::Locking,
        }
    }

    pub fn request_secret_access(&mut self) -> BrokerDecision {
        match self.state {
            State::Locked => {
                let deadline_millis = self.clock.now_millis().saturating_add(120_000);
                self.state = State::UnlockPending { deadline_millis };
                BrokerDecision::PromptUnlock
            }
            State::Unlocked { .. } => BrokerDecision::Authorized,
            State::UnlockPending { .. } | State::Running | State::Locking => BrokerDecision::Busy,
        }
    }

    pub fn complete_unlock(&mut self, approved: bool) -> BrokerDecision {
        let State::UnlockPending { deadline_millis } = self.state else {
            return BrokerDecision::Denied;
        };
        if self.clock.now_millis() >= deadline_millis {
            self.state = State::Locked;
            return BrokerDecision::UnlockTimedOut;
        }
        if approved {
            self.state = State::Unlocked {
                last_activity_millis: self.clock.now_millis(),
            };
            BrokerDecision::Authorized
        } else {
            self.state = State::Locked;
            BrokerDecision::Denied
        }
    }

    pub fn secret_activity(&mut self) {
        if let State::Unlocked {
            last_activity_millis,
        } = &mut self.state
        {
            *last_activity_millis = self.clock.now_millis();
        }
    }

    pub fn start_run(&mut self) -> BrokerDecision {
        if matches!(self.state, State::Unlocked { .. }) {
            self.state = State::Running;
            BrokerDecision::Authorized
        } else {
            BrokerDecision::Busy
        }
    }

    pub fn finish_run(&mut self) -> BrokerDecision {
        match self.state {
            State::Running => {
                self.state = State::Unlocked {
                    last_activity_millis: self.clock.now_millis(),
                };
                BrokerDecision::NoChange
            }
            State::Locking => {
                self.state = State::Locked;
                BrokerDecision::Locked
            }
            _ => BrokerDecision::NoChange,
        }
    }

    pub fn request_lock(&mut self, _reason: LockReason) -> BrokerDecision {
        if matches!(self.state, State::Running) {
            self.state = State::Locking;
            BrokerDecision::CancelRunBeforeLock
        } else {
            self.state = State::Locked;
            BrokerDecision::Locked
        }
    }

    pub fn tick(&mut self) -> BrokerDecision {
        let now = self.clock.now_millis();
        match self.state {
            State::UnlockPending { deadline_millis } if now >= deadline_millis => {
                self.state = State::Locked;
                BrokerDecision::UnlockTimedOut
            }
            State::Unlocked {
                last_activity_millis,
            } if now.saturating_sub(last_activity_millis) >= self.idle_timeout_millis => {
                self.state = State::Locked;
                BrokerDecision::Locked
            }
            _ => BrokerDecision::NoChange,
        }
    }

    pub fn record_activity(&mut self, mut entry: ActivityEntry) {
        entry.referenced_fields.truncate(MAX_ACTIVITY_REFERENCES);
        truncate_utf8(&mut entry.client_label, 64);
        if let Some(executable) = &mut entry.executable {
            truncate_utf8(executable, 32 * 1024);
        }
        if self.activities.len() == MAX_ACTIVITY_ENTRIES {
            self.activities.pop_front();
        }
        self.activities.push_back(entry);
    }

    #[must_use]
    pub const fn activities(&self) -> &VecDeque<ActivityEntry> {
        &self.activities
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn truncate_utf8(value: &mut String, maximum_bytes: usize) {
    if value.len() <= maximum_bytes {
        return;
    }
    let mut boundary = maximum_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}
