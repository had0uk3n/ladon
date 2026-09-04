#[cfg(feature = "gui")]
mod desktop;
#[cfg(unix)]
mod ipc;
mod supervisor;
mod ui;

#[cfg(feature = "gui")]
pub use desktop::run_desktop;
#[cfg(unix)]
pub use ipc::{LocalClient, LocalServer, default_endpoint_path};
pub use supervisor::{RunCancellation, RunResult, RunTermination, Supervisor};
pub use ui::{
    AddSecretDraft, ClipboardLease, DraftField, PendingRequestView, RevealLease, SensitiveText,
    VaultController, VaultUiPhase, validate_new_passphrase,
};
