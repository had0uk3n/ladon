#[cfg(unix)]
mod agent_broker;
mod approval;
#[cfg(feature = "gui")]
mod desktop;
#[cfg(unix)]
mod ipc;
mod session_auth;
mod supervisor;
mod touch_id;
mod ui;

#[cfg(unix)]
pub use agent_broker::LocalBrokerHandle;
pub use approval::{ApprovalCoordinator, ApprovalSecret, GrantTicket, PendingApproval};
#[cfg(feature = "gui")]
pub use desktop::run_desktop;
#[cfg(unix)]
pub use ipc::{LocalClient, LocalServer, default_endpoint_path};
pub use session_auth::SessionPin;
pub use supervisor::{RunCancellation, RunResult, RunTermination, Supervisor};
pub use touch_id::TouchIdAuthenticator;
pub use ui::{
    AddSecretDraft, ClipboardLease, DraftField, PendingRequestView, RevealLease, SensitiveText,
    VaultController, VaultUiPhase, validate_new_passphrase,
};
