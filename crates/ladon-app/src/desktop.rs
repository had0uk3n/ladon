use std::{
    env,
    fs::{self, File, OpenOptions},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use eframe::egui::{
    self, Align, Color32, FontFamily, FontId, Frame, Layout, Margin, RichText, Stroke, TextEdit,
    Vec2,
};
use ladon_core::{LadonError, SecretId};

#[cfg(unix)]
use crate::LocalBrokerHandle;
use crate::{AddSecretDraft, SensitiveText, Supervisor, VaultController, VaultUiPhase};

const CANVAS: Color32 = Color32::from_rgb(244, 247, 251);
const INK: Color32 = Color32::from_rgb(23, 35, 60);
const MUTED: Color32 = Color32::from_rgb(100, 113, 137);
const COBALT: Color32 = Color32::from_rgb(49, 94, 251);
const AMBER: Color32 = Color32::from_rgb(216, 144, 0);
const DANGER: Color32 = Color32::from_rgb(197, 59, 59);
const PANEL: Color32 = Color32::from_rgb(255, 255, 255);
const BORDER: Color32 = Color32::from_rgb(218, 225, 236);

pub fn run_desktop() -> Result<(), &'static str> {
    let path = default_vault_path().ok_or("Ladon cannot resolve the per-user data directory")?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([720.0, 520.0]),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "Ladon",
        options,
        Box::new(move |context| {
            let app = LadonDesktop::new(context, path)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(app))
        }),
    )
    .map_err(|_| "Ladon could not open its native window")
}

struct LadonDesktop {
    _instance_lock: InstanceLock,
    controller: Arc<Mutex<VaultController>>,
    #[cfg(unix)]
    broker: Option<LocalBrokerHandle>,
    passphrase: SensitiveText,
    confirmation: SensitiveText,
    draft: AddSecretDraft,
    notice: Option<Notice>,
    selected: Option<SecretId>,
    pending_delete: Option<SecretId>,
    last_phase: VaultUiPhase,
}

struct Notice {
    text: &'static str,
    danger: bool,
}

impl LadonDesktop {
    fn new(context: &eframe::CreationContext<'_>, path: PathBuf) -> Result<Self, LadonError> {
        configure_style(&context.egui_ctx);
        let instance_lock = acquire_runtime(&path, &Supervisor::temporary_root_path())?;
        let controller = Arc::new(Mutex::new(VaultController::new(path)));
        let last_phase = controller
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?
            .phase();
        #[cfg(unix)]
        let broker = Some(LocalBrokerHandle::start(Arc::clone(&controller))?);
        Ok(Self {
            _instance_lock: instance_lock,
            controller,
            #[cfg(unix)]
            broker,
            passphrase: SensitiveText::default(),
            confirmation: SensitiveText::default(),
            draft: AddSecretDraft::new(),
            notice: None,
            selected: None,
            pending_delete: None,
            last_phase,
        })
    }

    fn show_first_run(&mut self, ui: &mut egui::Ui) {
        centered_column(ui, |ui| {
            ui.label(
                RichText::new("Create your local vault")
                    .size(28.0)
                    .color(INK),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Choose a passphrase you can remember. Ladon cannot recover it.")
                    .color(AMBER),
            );
            ui.add_space(22.0);
            password_field(ui, &mut self.passphrase, "Passphrase (12+ characters)");
            ui.add_space(10.0);
            password_field(ui, &mut self.confirmation, "Repeat passphrase");
            ui.add_space(18.0);
            if primary_button(ui, "Create vault").clicked() {
                let result = with_controller(&self.controller, |controller| {
                    controller.create(&self.passphrase, &self.confirmation)
                });
                self.clear_unlock_fields();
                self.notice_from(result, "Vault created on this device");
            }
            self.show_notice(ui);
        });
    }

    fn show_locked(&mut self, ui: &mut egui::Ui) {
        centered_column(ui, |ui| {
            ui.label(RichText::new("Vault locked").size(28.0).color(INK));
            ui.add_space(8.0);
            ui.label(RichText::new("Unlock it for 30 minutes of secret activity.").color(MUTED));
            ui.add_space(22.0);
            let response = password_field(ui, &mut self.passphrase, "Passphrase");
            let submit =
                response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            ui.add_space(18.0);
            if primary_button(ui, "Unlock").clicked() || submit {
                let result = with_controller(&self.controller, |controller| {
                    controller.unlock(&self.passphrase)
                });
                self.clear_unlock_fields();
                self.notice_from(result, "Vault unlocked");
            }
            self.show_notice(ui);
        });
    }

    fn show_recovery(&mut self, ui: &mut egui::Ui) {
        centered_column(ui, |ui| {
            ui.label(RichText::new("Backup available").size(28.0).color(INK));
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "Ladon found an authenticated backup that is newer or safer to restore.",
                )
                .color(MUTED),
            );
            ui.add_space(18.0);
            if primary_button(ui, "Restore authenticated backup").clicked() {
                let result = with_controller(&self.controller, VaultController::restore_backup);
                self.notice_from(result, "Backup restored");
            }
            let can_continue = with_controller(&self.controller, |controller| {
                Ok(controller.can_continue_with_primary())
            })
            .unwrap_or(false);
            if can_continue && quiet_button(ui, "Continue with current vault").clicked() {
                let result = with_controller(&self.controller, |controller| {
                    controller.continue_with_primary()
                });
                self.notice_from(result, "Current vault kept");
            }
            self.show_notice(ui);
        });
    }

    fn show_unlocked(&mut self, context: &egui::Context) {
        self.show_secret_rail(context);
        egui::CentralPanel::default()
            .frame(Frame::new().fill(CANVAS).inner_margin(Margin::same(38)))
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Add a secret").size(28.0).color(INK));
                        ui.label(
                            RichText::new(
                                "One name, one value — add more fields only when needed.",
                            )
                            .color(MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if quiet_button(ui, "Lock now").clicked() {
                            #[cfg(unix)]
                            let result = if let Some(broker) = &self.broker {
                                broker.cancel_active_run_and_lock(&self.controller)
                            } else {
                                with_controller(&self.controller, |controller| {
                                    controller.lock();
                                    Ok(())
                                })
                            };
                            #[cfg(not(unix))]
                            let result = with_controller(&self.controller, |controller| {
                                controller.lock();
                                Ok(())
                            });
                            if result.is_ok() {
                                self.clear_sensitive_state();
                                self.notice = None;
                            } else {
                                self.notice_from(result, "Vault locked");
                            }
                        }
                    });
                });
                ui.add_space(28.0);
                Frame::new()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0_f32, BORDER))
                    .corner_radius(10)
                    .inner_margin(Margin::same(24))
                    .show(ui, |ui| {
                        ui.set_max_width(570.0);
                        field_label(ui, "Name");
                        ui.add(
                            TextEdit::singleline(self.draft.name_mut())
                                .hint_text("e.g. production-api")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(18.0);
                        for (index, field) in self.draft.fields_mut().iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    field_label(
                                        ui,
                                        if index == 0 {
                                            "Field"
                                        } else {
                                            "Additional field"
                                        },
                                    );
                                    ui.add(
                                        TextEdit::singleline(field.name_mut())
                                            .hint_text("field_name")
                                            .desired_width(180.0),
                                    );
                                });
                                ui.add_space(10.0);
                                ui.vertical(|ui| {
                                    field_label(ui, "Secret value");
                                    sensitive_text_field(
                                        ui,
                                        field.value_mut(),
                                        "kept out of chat and command arguments",
                                        350.0,
                                    );
                                });
                            });
                            ui.add_space(12.0);
                        }
                        ui.horizontal(|ui| {
                            if quiet_button(ui, "+ Add field").clicked() {
                                self.draft.add_field();
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if primary_button(ui, "Save secret").clicked() {
                                    let result = with_controller(&self.controller, |controller| {
                                        controller.add_secret(&mut self.draft)
                                    });
                                    self.notice_from(result.map(|_| ()), "Secret saved locally");
                                }
                            });
                        });
                    });
                self.show_notice(ui);
            });
    }

    fn show_secret_rail(&mut self, context: &egui::Context) {
        egui::SidePanel::left("secret-rail")
            .exact_width(248.0)
            .frame(Frame::new().fill(INK).inner_margin(Margin::same(18)))
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("LADON")
                            .strong()
                            .size(18.0)
                            .color(Color32::WHITE),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new("LOCAL")
                                .size(10.0)
                                .color(Color32::from_rgb(158, 176, 211)),
                        );
                    });
                });
                ui.add_space(18.0);
                let remaining = with_controller(&self.controller, |controller| {
                    Ok(controller.remaining_unlocked().unwrap_or_default())
                })
                .unwrap_or_default();
                ui.label(RichText::new("●  UNLOCKED").strong().color(COBALT));
                ui.label(
                    RichText::new(format_remaining(remaining))
                        .size(12.0)
                        .color(Color32::from_rgb(173, 187, 214)),
                );
                ui.add_space(28.0);
                ui.label(
                    RichText::new("SECRETS")
                        .size(11.0)
                        .color(Color32::from_rgb(158, 176, 211)),
                );
                ui.add_space(8.0);

                let secrets =
                    with_controller(&self.controller, |controller| Ok(controller.secrets()))
                        .unwrap_or_default();
                if secrets.is_empty() {
                    ui.label(
                        RichText::new("No secrets yet").color(Color32::from_rgb(173, 187, 214)),
                    );
                }
                for secret in &secrets {
                    let selected = self.selected == Some(secret.id);
                    if ui
                        .selectable_label(
                            selected,
                            RichText::new(&secret.name).color(Color32::WHITE),
                        )
                        .clicked()
                    {
                        self.selected = Some(secret.id);
                        self.pending_delete = None;
                    }
                    ui.label(
                        RichText::new(secret.field_names.join(", "))
                            .size(11.0)
                            .color(Color32::from_rgb(158, 176, 211)),
                    );
                    ui.add_space(8.0);
                }

                if let Some(selected) = self.selected {
                    ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                        if self.pending_delete == Some(selected) {
                            ui.horizontal(|ui| {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("Confirm delete").color(DANGER),
                                        )
                                        .frame(false),
                                    )
                                    .clicked()
                                {
                                    let result = with_controller(&self.controller, |controller| {
                                        controller.delete_secret(selected)
                                    });
                                    if result.is_ok() {
                                        self.selected = None;
                                    }
                                    self.pending_delete = None;
                                    self.notice_from(result, "Secret deleted");
                                }
                                if ui.button("Cancel").clicked() {
                                    self.pending_delete = None;
                                }
                            });
                        } else if ui
                            .add(
                                egui::Button::new(RichText::new("Delete selected").color(DANGER))
                                    .frame(false),
                            )
                            .clicked()
                        {
                            self.pending_delete = Some(selected);
                            self.notice = Some(Notice {
                                text: "Delete this secret permanently?",
                                danger: true,
                            });
                        }
                    });
                }
            });
    }

    fn clear_unlock_fields(&mut self) {
        self.passphrase.clear();
        self.confirmation.clear();
    }

    fn clear_sensitive_state(&mut self) {
        self.clear_unlock_fields();
        self.draft = AddSecretDraft::new();
        self.selected = None;
        self.pending_delete = None;
    }

    fn synchronize_phase(&mut self, phase: VaultUiPhase) {
        if self.last_phase == VaultUiPhase::Unlocked && phase != VaultUiPhase::Unlocked {
            self.clear_sensitive_state();
        }
        self.last_phase = phase;
    }

    fn notice_from(&mut self, result: Result<(), LadonError>, success: &'static str) {
        self.notice = Some(match result {
            Ok(()) => Notice {
                text: success,
                danger: false,
            },
            Err(error) => Notice {
                text: error.safe_message(),
                danger: true,
            },
        });
    }

    fn show_notice(&self, ui: &mut egui::Ui) {
        if let Some(notice) = &self.notice {
            ui.add_space(16.0);
            ui.label(RichText::new(notice.text).color(if notice.danger { DANGER } else { COBALT }));
        }
    }
}

struct InstanceLock {
    file: File,
}

impl InstanceLock {
    fn acquire(vault_path: &std::path::Path) -> Result<Self, LadonError> {
        let parent = vault_path.parent().ok_or(LadonError::StorageFailure)?;
        fs::create_dir_all(parent).map_err(|_| LadonError::StorageFailure)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|_| LadonError::StorageFailure)?;
        }
        let path = parent.join(".instance.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| LadonError::StorageFailure)?;
        lock_instance_file(&file)?;
        Ok(Self { file })
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        unlock_instance_file(&self.file);
    }
}

fn acquire_runtime(
    vault_path: &std::path::Path,
    temp_root: &std::path::Path,
) -> Result<InstanceLock, LadonError> {
    let instance_lock = InstanceLock::acquire(vault_path)?;
    Supervisor::cleanup_stale_temp_directories_at(temp_root)?;
    Ok(instance_lock)
}

#[cfg(unix)]
fn lock_instance_file(file: &File) -> Result<(), LadonError> {
    use std::os::fd::AsRawFd;
    // SAFETY: file owns a valid descriptor for the duration of the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EWOULDBLOCK) => Err(LadonError::AlreadyRunning),
        _ => Err(LadonError::StorageFailure),
    }
}

#[cfg(unix)]
fn unlock_instance_file(file: &File) {
    use std::os::fd::AsRawFd;
    // SAFETY: file owns a valid descriptor for the duration of the call.
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}

#[cfg(windows)]
fn lock_instance_file(file: &File) -> Result<(), LadonError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::ERROR_LOCK_VIOLATION,
        Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx},
        System::IO::OVERLAPPED,
    };
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: file owns a valid handle and overlapped remains alive for the synchronous call.
    if unsafe {
        LockFileEx(
            file.as_raw_handle().cast(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    } != 0
    {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(code) if code == ERROR_LOCK_VIOLATION as i32 => Err(LadonError::AlreadyRunning),
        _ => Err(LadonError::StorageFailure),
    }
}

#[cfg(windows)]
fn unlock_instance_file(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Storage::FileSystem::UnlockFileEx, System::IO::OVERLAPPED};
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: file owns a valid handle and overlapped remains alive for the synchronous call.
    unsafe {
        UnlockFileEx(file.as_raw_handle().cast(), 0, 1, 0, &mut overlapped);
    }
}

impl eframe::App for LadonDesktop {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        #[cfg(unix)]
        let auto_locked = if let Some(broker) = &self.broker {
            broker
                .auto_lock_controller_if_idle(&self.controller)
                .unwrap_or(false)
        } else {
            with_controller(&self.controller, |controller| {
                Ok(controller.auto_lock_if_idle())
            })
            .unwrap_or(false)
        };
        #[cfg(not(unix))]
        let auto_locked = with_controller(&self.controller, |controller| {
            Ok(controller.auto_lock_if_idle())
        })
        .unwrap_or(false);
        if auto_locked {
            self.clear_sensitive_state();
            self.notice = Some(Notice {
                text: "Vault locked after 30 minutes without secret activity",
                danger: false,
            });
        }
        context.request_repaint_after(Duration::from_secs(1));

        let phase = with_controller(&self.controller, |controller| Ok(controller.phase()))
            .unwrap_or(VaultUiPhase::Locked);
        self.synchronize_phase(phase);
        match phase {
            VaultUiPhase::FirstRun => shell(context, |ui| self.show_first_run(ui)),
            VaultUiPhase::Locked => shell(context, |ui| self.show_locked(ui)),
            VaultUiPhase::RecoveryRequired => shell(context, |ui| self.show_recovery(ui)),
            VaultUiPhase::Unlocked => self.show_unlocked(context),
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        #[cfg(unix)]
        let _ = if let Some(broker) = &self.broker {
            broker.cancel_active_run_and_lock(&self.controller)
        } else {
            with_controller(&self.controller, |controller| {
                controller.lock();
                Ok(())
            })
        };
        #[cfg(not(unix))]
        let _ = with_controller(&self.controller, |controller| {
            controller.lock();
            Ok(())
        });
        self.clear_sensitive_state();
    }
}

fn with_controller<T>(
    controller: &Arc<Mutex<VaultController>>,
    operation: impl FnOnce(&mut VaultController) -> Result<T, LadonError>,
) -> Result<T, LadonError> {
    let mut controller = controller.lock().map_err(|_| LadonError::ProcessFailure)?;
    operation(&mut controller)
}

fn configure_style(context: &egui::Context) {
    let mut style = (*context.style()).clone();
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = CANVAS;
    style.visuals.window_fill = PANEL;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, COBALT);
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(14.0, 8.0);
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(15.0, FontFamily::Proportional),
    );
    context.set_style(style);
}

fn shell(context: &egui::Context, content: impl FnOnce(&mut egui::Ui)) {
    egui::CentralPanel::default()
        .frame(Frame::new().fill(CANVAS).inner_margin(Margin::same(36)))
        .show(context, content);
}

fn centered_column(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui)) {
    ui.with_layout(Layout::top_down(Align::Center), |ui| {
        ui.add_space(90.0);
        ui.set_max_width(430.0);
        content(ui);
    });
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(12.0).strong().color(INK));
}

fn password_field(ui: &mut egui::Ui, value: &mut SensitiveText, hint: &str) -> egui::Response {
    sensitive_text_field(ui, value, hint, 430.0)
}

fn sensitive_text_field(
    ui: &mut egui::Ui,
    value: &mut SensitiveText,
    hint: &str,
    width: f32,
) -> egui::Response {
    let mut output = TextEdit::singleline(value)
        .password(true)
        .hint_text(hint)
        .desired_width(width)
        .show(ui);
    // egui stores ordinary Strings for undo. Password mode blocks copy/accessibility output,
    // and clearing the undoer immediately prevents those copies surviving in widget state.
    output.state.clear_undoer();
    output.state.store(ui.ctx(), output.response.id);
    output.response
}

fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(COBALT)
            .stroke(Stroke::NONE)
            .corner_radius(6),
    )
}

fn quiet_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(INK))
            .fill(PANEL)
            .stroke(Stroke::new(1.0_f32, BORDER))
            .corner_radius(6),
    )
}

fn format_remaining(remaining: Duration) -> String {
    let seconds = remaining.as_secs();
    format!("locks in {:02}:{:02}", seconds / 60, seconds % 60)
}

fn default_vault_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = env::var_os("APPDATA").map(PathBuf::from);

    #[cfg(target_os = "macos")]
    let base = env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("Library").join("Application Support"));

    #[cfg(all(unix, not(target_os = "macos")))]
    let base = env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| {
        env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".local/share"))
    });

    base.map(|base| base.join("Ladon").join("vault.ladon"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn vault_instance_lock_is_exclusive_and_recoverable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.ladon");
        let first = InstanceLock::acquire(&path).unwrap();
        assert!(matches!(
            InstanceLock::acquire(&path),
            Err(LadonError::AlreadyRunning)
        ));
        drop(first);
        assert!(InstanceLock::acquire(&path).is_ok());
    }

    #[test]
    fn sensitive_widget_does_not_retain_undo_history() {
        let context = egui::Context::default();
        let mut value = SensitiveText::from("fake-passphrase-value");
        let mut widget_id = None;
        let _ = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| {
                widget_id = Some(sensitive_text_field(ui, &mut value, "Passphrase", 300.0).id);
            });
        });
        let state = TextEdit::load_state(&context, widget_id.unwrap()).unwrap();
        let current = (
            state.cursor.char_range().unwrap_or_default(),
            value.as_str().to_owned(),
        );
        let undoer = state.undoer();

        assert!(!undoer.has_undo(&current));
        assert!(!undoer.is_in_flux());
    }

    #[test]
    fn leaving_unlocked_clears_gui_owned_secret_drafts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.ladon");
        let controller = Arc::new(Mutex::new(VaultController::new(path.clone())));
        let passphrase = SensitiveText::from("correct horse");
        {
            let mut state = controller.lock().unwrap();
            state.create(&passphrase, &passphrase).unwrap();
        }
        let mut draft = AddSecretDraft::new();
        draft.set_name("unsaved");
        draft.fields_mut()[0].value_mut().push_str("fake-secret");
        let mut app = LadonDesktop {
            _instance_lock: InstanceLock::acquire(&path).unwrap(),
            controller: Arc::clone(&controller),
            #[cfg(unix)]
            broker: None,
            passphrase: SensitiveText::default(),
            confirmation: SensitiveText::default(),
            draft,
            notice: None,
            selected: None,
            pending_delete: None,
            last_phase: VaultUiPhase::Unlocked,
        };

        controller.lock().unwrap().lock();
        app.synchronize_phase(VaultUiPhase::Locked);

        assert!(app.draft.name().is_empty());
        assert!(app.draft.fields()[0].value().as_str().is_empty());
    }

    #[test]
    fn runtime_cleanup_happens_after_the_instance_lock_is_acquired() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data").join("vault.ladon");
        let temp_root = directory.path().join("runtime");
        let stale = temp_root.join("run-stale");
        fs::create_dir_all(&stale).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp_root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(stale.join(".ladon-owner"), Uuid::new_v4().to_string()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                stale.join(".ladon-owner"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }

        let _guard = acquire_runtime(&path, &temp_root).unwrap();

        assert!(!stale.exists());
        assert!(matches!(
            InstanceLock::acquire(&path),
            Err(LadonError::AlreadyRunning)
        ));
    }
}
