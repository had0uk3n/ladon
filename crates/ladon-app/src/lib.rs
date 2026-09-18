#[cfg(unix)]
mod agent_broker;
mod approval;
#[cfg(feature = "gui")]
mod clipboard;
#[cfg(feature = "gui")]
mod desktop;
#[cfg(unix)]
mod ipc;
mod secret_editor;
mod session_auth;
mod supervisor;
mod touch_id;
mod ui;

#[cfg(unix)]
pub use agent_broker::LocalBrokerHandle;
pub use approval::{
    ActiveGrantSnapshot, AppAccessState, ApprovalCoordinator, ApprovalSecret, GrantTicket,
    PendingApproval,
};
#[cfg(feature = "gui")]
pub use desktop::run_desktop;
#[cfg(unix)]
pub use ipc::{LocalClient, LocalServer, default_endpoint_path};
pub use secret_editor::{EditSecretDraft, EditableField, EditableValue};
pub use session_auth::{PinVerification, SessionConfirmation, SessionPin};
pub use supervisor::{RunCancellation, RunResult, RunTermination, Supervisor};
pub use touch_id::TouchIdAuthenticator;
pub use ui::{
    AddSecretDraft, DetailMode, DetailStateError, DraftField, LocalAuthAttempt, NavigationResult,
    NavigationTarget, PendingRequestView, SecretDetailState, SensitiveText, VaultController,
    VaultUiPhase, validate_new_passphrase,
};
