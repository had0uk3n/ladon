use std::{
    env,
    fs::{self, File, OpenOptions},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use eframe::egui::{
    self, Align, Color32, FontFamily, FontId, Frame, Layout, Margin, RichText, Stroke, TextEdit,
    Vec2,
};
use ladon_core::{LadonError, SecretId, SecretMetadata, SensitiveBytes};

#[cfg(unix)]
use crate::agent_broker::{AgentGrantView, AppLockAttempt, LocalBrokerHandle};
use crate::clipboard::SecretClipboard;
use crate::touch_id::TouchIdAttempt;
#[cfg(unix)]
use crate::ui::sanitize_untrusted;
use crate::{
    AddSecretDraft, DetailMode, LocalAuthAttempt, NavigationResult, NavigationTarget,
    PendingRequestView, PinVerification, SecretDetailState, SensitiveText, SessionConfirmation,
    SessionPin, Supervisor, TouchIdAuthenticator, VaultController, VaultUiPhase,
};
use crate::{
    EditableValue,
    ui::{AddDraftValidationError, ReadOnlySensitiveText},
};

const CANVAS: Color32 = Color32::from_rgb(244, 247, 251);
const INK: Color32 = Color32::from_rgb(23, 35, 60);
const MUTED: Color32 = Color32::from_rgb(100, 113, 137);
const COBALT: Color32 = Color32::from_rgb(49, 94, 251);
const AMBER: Color32 = Color32::from_rgb(216, 144, 0);
const DANGER: Color32 = Color32::from_rgb(197, 59, 59);
const PANEL: Color32 = Color32::from_rgb(255, 255, 255);
const BORDER: Color32 = Color32::from_rgb(218, 225, 236);
const AUTH_WINDOW_SIZE: [f32; 2] = [500.0, 380.0];
const MANAGER_WINDOW_SIZE: [f32; 2] = [640.0, 420.0];
const WINDOW_MIN_SIZE: [f32; 2] = [480.0, 340.0];
const SECRET_RAIL_WIDTH: f32 = 180.0;
const SECRET_ROW_TEXT_SIZE: f32 = 13.0;
const SECRET_ROW_HEIGHT: f32 = 30.0;
const SECRET_ROW_LEADING_INSET: f32 = 6.0;
const NEW_SECRET_TEXT_SIZE: f32 = SECRET_ROW_TEXT_SIZE;
const NEW_SECRET_ROW_HEIGHT: f32 = SECRET_ROW_HEIGHT;
#[cfg(unix)]
const AGENT_ACCESS_MAX_HEIGHT: f32 = 160.0;
const WORKSPACE_CARD_WIDTH: f32 = 380.0;
const AUTH_FORM_WIDTH: f32 = 340.0;
const SENSITIVE_FIELD_HEIGHT: f32 = 34.0;
const REMOVE_BUTTON_HEIGHT: f32 = SENSITIVE_FIELD_HEIGHT;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DesktopLockState {
    #[default]
    Active,
    Locking {
        epoch: u64,
    },
    Locked {
        epoch: u64,
    },
}

pub fn run_desktop() -> Result<(), &'static str> {
    let path = default_vault_path().ok_or("Ladon cannot resolve the per-user data directory")?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(AUTH_WINDOW_SIZE)
            .with_min_inner_size(WINDOW_MIN_SIZE),
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
    #[cfg(unix)]
    agent_grants: Vec<AgentGrantView>,
    #[cfg(unix)]
    agent_grants_session: Option<uuid::Uuid>,
    #[cfg(unix)]
    agent_grants_error_shown: bool,
    passphrase: SensitiveText,
    confirmation: SensitiveText,
    session_pin: SensitiveText,
    session_pin_confirmation: SensitiveText,
    local_pin: SensitiveText,
    session_confirmation: Option<SessionConfirmation>,
    desktop_lock: DesktopLockState,
    desktop_lock_epoch: u64,
    #[cfg(unix)]
    pending_app_lock: Option<AppLockAttempt>,
    app_unlock_pin_visible: bool,
    pending_touch_id: Option<PendingTouchId>,
    focused_approval: Option<uuid::Uuid>,
    draft: AddSecretDraft,
    add_form_error: Option<AddDraftValidationError>,
    notice: Option<Notice>,
    clipboard: SecretClipboard,
    ui_clock_started: Instant,
    clipboard_clear_notice_shown: bool,
    detail: SecretDetailState,
    unlock_confirmation: bool,
    discard_confirmation: bool,
    pending_delete: Option<SecretId>,
    last_phase: VaultUiPhase,
    manager_window_active: bool,
}

enum ApprovalAction {
    Approve(ConfirmationAction),
    Deny,
}

struct PendingTouchId {
    authentication: TouchIdAttempt,
    target: TouchIdTarget,
}

enum TouchIdTarget {
    AppUnlock {
        vault_session_id: uuid::Uuid,
        lock_epoch: u64,
    },
    Secret {
        attempt: LocalAuthAttempt,
        vault_session_id: uuid::Uuid,
    },
    #[cfg(unix)]
    Approval {
        approval_id: uuid::Uuid,
        vault_session_id: uuid::Uuid,
    },
}

#[derive(Clone, Copy)]
enum DetailAction {
    Show,
    Hide,
    Edit,
    Save,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedActionSet {
    Unlock,
    Hidden,
    Revealed,
    Editing,
}

#[derive(Clone, Copy)]
enum DeleteAction {
    Request,
    Confirm,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfirmationAction {
    TouchId,
    Pin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppUnlockStart {
    TouchId,
    Pin,
    HardLock,
}

fn app_unlock_start(touch_id_available: bool, pin_configured: bool) -> AppUnlockStart {
    match (touch_id_available, pin_configured) {
        (true, _) => AppUnlockStart::TouchId,
        (false, true) => AppUnlockStart::Pin,
        (false, false) => AppUnlockStart::HardLock,
    }
}

fn can_finish_session_setup(touch_id_available: bool, pin_configured: bool) -> bool {
    touch_id_available || pin_configured
}

fn confirmation_actions(touch_id_available: bool, pin_configured: bool) -> Vec<ConfirmationAction> {
    let mut actions = Vec::with_capacity(2);
    if touch_id_available {
        actions.push(ConfirmationAction::TouchId);
    }
    if pin_configured {
        actions.push(ConfirmationAction::Pin);
    }
    actions
}

fn selected_action_set(authorized: bool, mode: &DetailMode) -> SelectedActionSet {
    match (authorized, mode) {
        (_, DetailMode::Editing { .. }) => SelectedActionSet::Editing,
        (false, _) => SelectedActionSet::Unlock,
        (true, DetailMode::Hidden) => SelectedActionSet::Hidden,
        (true, DetailMode::Revealed(_)) => SelectedActionSet::Revealed,
    }
}

fn selected_action_labels(actions: SelectedActionSet) -> (&'static [&'static str], &'static str) {
    let primary: &[&str] = match actions {
        SelectedActionSet::Unlock => &["Unlock this secret"],
        SelectedActionSet::Hidden => &["Show", "Edit"],
        SelectedActionSet::Revealed => &["Hide", "Edit"],
        SelectedActionSet::Editing => &[],
    };
    (primary, "Delete")
}

struct FieldNameSummary<'a> {
    primary: Option<&'a str>,
    additional_count: usize,
    additional_hover: String,
}

fn summarize_field_names(field_names: &[String]) -> FieldNameSummary<'_> {
    FieldNameSummary {
        primary: field_names.first().map(String::as_str),
        additional_count: field_names.len().saturating_sub(1),
        additional_hover: field_names.get(1..).unwrap_or_default().join("\n"),
    }
}

fn secret_row_fill(selected: bool) -> Color32 {
    if selected {
        COBALT
    } else {
        Color32::TRANSPARENT
    }
}

fn window_size(manager_active: bool) -> [f32; 2] {
    if manager_active {
        MANAGER_WINDOW_SIZE
    } else {
        AUTH_WINDOW_SIZE
    }
}

fn manager_rendering_allowed(phase: VaultUiPhase, desktop_lock: DesktopLockState) -> bool {
    phase == VaultUiPhase::Unlocked && desktop_lock == DesktopLockState::Active
}

struct Notice {
    text: String,
    danger: bool,
}

fn copyable_text(value: &EditableValue) -> Option<&str> {
    match value {
        EditableValue::Text(text) => Some(text.as_str()),
        EditableValue::Binary { .. } => None,
    }
}

fn set_clipboard_notice(notice: &mut Option<Notice>, text: &'static str) {
    if !notice.as_ref().is_some_and(|notice| notice.danger) {
        *notice = Some(Notice {
            text: text.to_owned(),
            danger: false,
        });
    }
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
        let broker = {
            let repaint = context.egui_ctx.clone();
            Some(LocalBrokerHandle::start_for_desktop(
                Arc::clone(&controller),
                Arc::new(move || repaint.request_repaint()),
            )?)
        };
        Ok(Self {
            _instance_lock: instance_lock,
            controller,
            #[cfg(unix)]
            broker,
            #[cfg(unix)]
            agent_grants: Vec::new(),
            #[cfg(unix)]
            agent_grants_session: None,
            #[cfg(unix)]
            agent_grants_error_shown: false,
            passphrase: SensitiveText::default(),
            confirmation: SensitiveText::default(),
            session_pin: SensitiveText::default(),
            session_pin_confirmation: SensitiveText::default(),
            local_pin: SensitiveText::default(),
            session_confirmation: None,
            desktop_lock: DesktopLockState::default(),
            desktop_lock_epoch: 0,
            #[cfg(unix)]
            pending_app_lock: None,
            app_unlock_pin_visible: false,
            pending_touch_id: None,
            focused_approval: None,
            draft: AddSecretDraft::new(),
            add_form_error: None,
            notice: None,
            clipboard: SecretClipboard::default(),
            ui_clock_started: Instant::now(),
            clipboard_clear_notice_shown: false,
            detail: SecretDetailState::default(),
            unlock_confirmation: false,
            discard_confirmation: false,
            pending_delete: None,
            last_phase,
            manager_window_active: false,
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

    fn show_session_auth_setup(&mut self, ui: &mut egui::Ui) {
        centered_column(ui, |ui| {
            ui.label(
                RichText::new("Confirm protected actions")
                    .size(24.0)
                    .color(INK),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "Use Touch ID when available, and optionally add a session PIN. Nothing is saved to the system keychain.",
                )
                .color(MUTED),
            );
            ui.add_space(14.0);

            let touch_id_available = TouchIdAuthenticator::is_available();
            let can_continue_with_touch_id = can_finish_session_setup(touch_id_available, false);
            if can_continue_with_touch_id && primary_button(ui, "Continue with Touch ID").clicked()
            {
                self.session_pin.clear();
                self.session_pin_confirmation.clear();
                self.session_confirmation = Some(SessionConfirmation::touch_id_only());
                self.notice = Some(Notice {
                    text: "Touch ID will confirm protected actions".to_owned(),
                    danger: false,
                });
            }

            if touch_id_available {
                ui.add_space(12.0);
                ui.label(RichText::new("Optional session PIN").color(MUTED));
                ui.add_space(8.0);
            }
            password_field(ui, &mut self.session_pin, "PIN (4–12 digits)");
            ui.add_space(8.0);
            password_field(ui, &mut self.session_pin_confirmation, "Repeat PIN");
            ui.add_space(12.0);
            if primary_button(ui, "Set PIN and continue").clicked() {
                match SessionPin::new(&self.session_pin, &self.session_pin_confirmation) {
                    Ok(pin) => {
                        self.session_confirmation = Some(SessionConfirmation::with_pin(pin));
                        self.notice = Some(Notice {
                            text: "Session PIN set; it will be forgotten when the vault locks"
                                .to_owned(),
                            danger: false,
                        });
                    }
                    Err(error) => {
                        self.notice = Some(Notice {
                            text: error.safe_message().to_owned(),
                            danger: true,
                        });
                    }
                }
                self.session_pin.clear();
                self.session_pin_confirmation.clear();
            }
            self.show_notice(ui);
        });
    }

    fn synchronize_window_size(&mut self, context: &egui::Context, manager_active: bool) {
        if self.manager_window_active == manager_active {
            return;
        }
        self.manager_window_active = manager_active;
        let size = window_size(manager_active);
        context.send_viewport_cmd(egui::ViewportCommand::InnerSize(size.into()));
    }

    fn show_unlocked(&mut self, context: &egui::Context) -> bool {
        self.show_secret_rail(context);
        let selected_metadata = self.selected_metadata();
        egui::CentralPanel::default()
            .frame(Frame::new().fill(CANVAS).inner_margin(Margin::same(20)))
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        if let Some(secret) = &selected_metadata {
                            ui.label(RichText::new(&secret.name).size(24.0).color(INK));
                            ui.label(
                                RichText::new(format!("ID: {}", secret.id))
                                    .size(11.0)
                                    .color(MUTED),
                            );
                        } else {
                            ui.label(RichText::new("Add a secret").size(24.0).color(INK));
                            ui.label(
                                RichText::new("One name, one value. Add fields when needed.")
                                    .color(MUTED),
                            );
                        }
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if quiet_button(ui, "Lock app").clicked() {
                            self.lock_app();
                            context.request_repaint();
                        }
                    });
                });
                ui.add_space(16.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    if let Some(secret) = &selected_metadata {
                        self.show_selected_workspace(ui, secret);
                    } else {
                        self.show_add_workspace(ui);
                    }
                    self.show_notice(ui);
                });
            });

        let phase = with_controller(&self.controller, |controller| Ok(controller.phase()))
            .unwrap_or(VaultUiPhase::Locked);
        if !manager_rendering_allowed(phase, self.desktop_lock) {
            self.synchronize_window_size(context, false);
            self.show_lock_overlay(context, phase);
            return false;
        }

        if self.unlock_confirmation {
            if let Some(secret) = self.selected_metadata() {
                self.show_secret_confirmation(context, &secret);
            } else {
                self.unlock_confirmation = false;
                self.local_pin.clear();
            }
        }
        if self.discard_confirmation {
            self.show_discard_confirmation(context);
        }
        true
    }

    fn show_lock_overlay(&mut self, context: &egui::Context, phase: VaultUiPhase) {
        let rect = context.screen_rect();
        let overlay_id = egui::Id::new("app-lock-content");
        context
            .layer_painter(egui::LayerId::new(egui::Order::Foreground, overlay_id))
            .rect_filled(rect, 0.0, CANVAS);
        egui::Area::new(overlay_id)
            .order(egui::Order::Foreground)
            .fixed_pos(rect.min)
            .show(context, |ui| {
                ui.set_min_size(rect.size());
                match phase {
                    VaultUiPhase::Locked => self.show_locked(ui),
                    VaultUiPhase::Unlocked => match self.desktop_lock {
                        DesktopLockState::Locking { .. } => self.show_app_locking(ui),
                        DesktopLockState::Locked { .. } => self.show_app_locked(ui),
                        DesktopLockState::Active => {}
                    },
                    VaultUiPhase::FirstRun | VaultUiPhase::RecoveryRequired => {}
                }
            });
    }

    fn show_add_workspace(&mut self, ui: &mut egui::Ui) {
        Frame::new()
            .fill(PANEL)
            .stroke(Stroke::new(1.0_f32, BORDER))
            .corner_radius(10)
            .inner_margin(Margin::same(18))
            .show(ui, |ui| {
                ui.set_width(WORKSPACE_CARD_WIDTH);
                field_label(ui, "Name");
                let mut changed = ui
                    .add(
                        TextEdit::singleline(self.draft.name_mut())
                            .hint_text("e.g. production-api")
                            .desired_width(f32::INFINITY),
                    )
                    .changed();
                ui.add_space(18.0);
                let current_error = self.add_form_error;
                let mut remove_index = None;
                for (index, field) in self.draft.fields_mut().iter_mut().enumerate() {
                    ui.allocate_ui_with_layout(
                        Vec2::new(ui.available_width(), SENSITIVE_FIELD_HEIGHT),
                        Layout::left_to_right(Align::Max),
                        |ui| {
                            ui.vertical(|ui| {
                                field_label(
                                    ui,
                                    if index == 0 {
                                        "Field"
                                    } else {
                                        "Additional field"
                                    },
                                );
                                changed |= ui
                                    .add_sized(
                                        [104.0, SENSITIVE_FIELD_HEIGHT],
                                        TextEdit::singleline(field.name_mut())
                                            .hint_text("field_name")
                                            .desired_width(104.0),
                                    )
                                    .changed();
                            });
                            ui.add_space(10.0);
                            ui.vertical(|ui| {
                                field_label(ui, "Secret value");
                                changed |= visible_sensitive_text_field(
                                    ui,
                                    field.value_mut(),
                                    "Secret value",
                                    210.0,
                                )
                                .changed();
                            });
                            if index > 0
                                && remove_field_button(ui)
                                    .on_hover_text("Remove field")
                                    .clicked()
                            {
                                remove_index = Some(index);
                            }
                        },
                    );
                    if let Some(error) = current_error.filter(|error| error.field_index() == index)
                    {
                        ui.label(RichText::new(add_form_error_text(error)).color(DANGER));
                    }
                    ui.add_space(12.0);
                }
                if let Some(index) = remove_index {
                    changed |= self.draft.remove_field(index);
                }
                if changed {
                    self.add_form_error = None;
                    self.notice = None;
                }
                ui.horizontal(|ui| {
                    let add_field = ui.add_enabled(
                        self.draft.can_add_field(),
                        egui::Button::new(RichText::new("+ Add field").color(INK))
                            .fill(PANEL)
                            .stroke(Stroke::new(1.0_f32, BORDER))
                            .corner_radius(6),
                    );
                    if add_field.clicked() {
                        self.draft.add_field();
                        self.add_form_error = None;
                        self.notice = None;
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if primary_button(ui, "Save secret").clicked() {
                            match self.draft.validate_fields() {
                                Ok(()) => {
                                    let result = with_controller(&self.controller, |controller| {
                                        controller.add_secret(&mut self.draft)
                                    });
                                    self.handle_add_result(result);
                                }
                                Err(error) => {
                                    self.add_form_error = Some(error);
                                    self.notice = None;
                                }
                            }
                        }
                    });
                });
            });
    }

    fn show_selected_workspace(&mut self, ui: &mut egui::Ui, secret: &SecretMetadata) {
        let session_id = self.vault_session_id().ok();
        let authorized = session_id.is_some_and(|id| self.detail.is_authorized(id));
        let mut action = None;
        let mut delete_action = None;
        let mut copy_request = None;
        let editing = self.detail.is_editing();
        let action_set = selected_action_set(authorized, self.detail.mode());
        let (primary_labels, delete_label) = selected_action_labels(action_set);
        Frame::new()
            .fill(PANEL)
            .stroke(Stroke::new(1.0_f32, BORDER))
            .corner_radius(10)
            .inner_margin(Margin::same(18))
            .show(ui, |ui| {
                ui.set_width(WORKSPACE_CARD_WIDTH);
                if !editing {
                    ui.horizontal(|ui| {
                        match action_set {
                            SelectedActionSet::Unlock => {
                                if primary_button(ui, primary_labels[0]).clicked() {
                                    self.unlock_confirmation = true;
                                    self.local_pin.clear();
                                }
                            }
                            SelectedActionSet::Hidden | SelectedActionSet::Revealed => {
                                let revealed = action_set == SelectedActionSet::Revealed;
                                let response = if revealed {
                                    quiet_button(ui, primary_labels[0])
                                } else {
                                    primary_button(ui, primary_labels[0])
                                };
                                if response.clicked() {
                                    action = Some(if revealed {
                                        DetailAction::Hide
                                    } else {
                                        DetailAction::Show
                                    });
                                }
                                if quiet_button(ui, primary_labels[1]).clicked() {
                                    action = Some(DetailAction::Edit);
                                }
                            }
                            SelectedActionSet::Editing => {}
                        }
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if self.pending_delete == Some(secret.id) {
                                if quiet_button(ui, "Cancel").clicked() {
                                    delete_action = Some(DeleteAction::Cancel);
                                }
                                if danger_button(ui, delete_label).clicked() {
                                    delete_action = Some(DeleteAction::Confirm);
                                }
                            } else if danger_button(ui, delete_label).clicked() {
                                delete_action = Some(DeleteAction::Request);
                            }
                        });
                    });
                    ui.add_space(14.0);
                }
                if !authorized {
                    for field_name in &secret.field_names {
                        field_label(ui, field_name);
                        ui.label(RichText::new("••••••••").color(MUTED));
                        ui.add_space(14.0);
                    }
                    return;
                }

                match self.detail.mode_mut() {
                    DetailMode::Hidden => {
                        for field_name in &secret.field_names {
                            field_label(ui, field_name);
                            ui.label(RichText::new("••••••••").color(MUTED));
                            ui.add_space(14.0);
                        }
                    }
                    DetailMode::Revealed(draft) => {
                        for field in draft.fields() {
                            field_label(ui, field.name());
                            match field.value() {
                                EditableValue::Text(value) => {
                                    ui.horizontal(|ui| {
                                        let width = (ui.available_width() - 60.0).max(24.0);
                                        let mut buffer = ReadOnlySensitiveText::new(value);
                                        ui.add_sized(
                                            [width, SENSITIVE_FIELD_HEIGHT],
                                            TextEdit::singleline(&mut buffer)
                                                .interactive(false)
                                                .desired_width(width),
                                        );
                                        copy_value_button(ui, field.value(), &mut copy_request);
                                    });
                                }
                                EditableValue::Binary { bytes, .. } => {
                                    ui.label(
                                        RichText::new(format!("Binary · {} bytes", bytes.len()))
                                            .color(MUTED),
                                    );
                                }
                            }
                            ui.add_space(14.0);
                        }
                    }
                    DetailMode::Editing { draft, dirty } => {
                        field_label(ui, "Name");
                        if ui
                            .add(
                                TextEdit::singleline(draft.name_mut()).desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            *dirty = true;
                        }
                        ui.add_space(16.0);
                        let mut remove_index = None;
                        let can_remove = draft.fields().len() > 1;
                        for (index, field) in draft.fields_mut().iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                if ui
                                    .add_sized(
                                        [94.0, SENSITIVE_FIELD_HEIGHT],
                                        TextEdit::singleline(field.name_mut())
                                            .hint_text("field_name")
                                            .desired_width(94.0),
                                    )
                                    .changed()
                                {
                                    *dirty = true;
                                }
                                match field.value_mut() {
                                    EditableValue::Text(value) => {
                                        let width = (ui.available_width() - 98.0).max(24.0);
                                        if visible_sensitive_text_field(
                                            ui,
                                            value,
                                            "secret value",
                                            width,
                                        )
                                        .changed()
                                        {
                                            *dirty = true;
                                        }
                                    }
                                    EditableValue::Binary { bytes, .. } => {
                                        ui.label(
                                            RichText::new(format!(
                                                "Binary · {} bytes",
                                                bytes.len()
                                            ))
                                            .color(MUTED),
                                        );
                                    }
                                }
                                copy_value_button(ui, field.value(), &mut copy_request);
                                if ui
                                    .add_enabled_ui(can_remove, remove_field_button)
                                    .inner
                                    .on_hover_text("Remove field")
                                    .clicked()
                                {
                                    remove_index = Some(index);
                                }
                            });
                            ui.add_space(10.0);
                        }
                        if let Some(index) = remove_index
                            && draft.remove_field(index)
                        {
                            *dirty = true;
                        }
                        ui.horizontal(|ui| {
                            if quiet_button(ui, "Add field").clicked() {
                                draft.add_text_field();
                                *dirty = true;
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if primary_button(ui, "Save changes").clicked() {
                                    action = Some(DetailAction::Save);
                                }
                                if quiet_button(ui, "Cancel").clicked() {
                                    action = Some(DetailAction::Cancel);
                                }
                            });
                        });
                    }
                }
            });

        if let Some(value) = copy_request {
            let now = self.ui_clock_millis();
            match self.clipboard.copy(value, now) {
                Ok(()) => {
                    self.clipboard_clear_notice_shown = false;
                    set_clipboard_notice(
                        &mut self.notice,
                        "Copied; Ladon will clear it after 30 seconds if unchanged",
                    );
                }
                Err(_) => set_clipboard_notice(&mut self.notice, "Clipboard is unavailable"),
            }
        }

        match delete_action {
            Some(DeleteAction::Request) => {
                self.pending_delete = Some(secret.id);
                self.notice = Some(Notice {
                    text: "Delete this secret permanently?".to_owned(),
                    danger: true,
                });
            }
            Some(DeleteAction::Confirm) => {
                let result = self.delete_secret(secret.id);
                self.pending_delete = None;
                self.handle_delete_result(result);
            }
            Some(DeleteAction::Cancel) => {
                self.pending_delete = None;
            }
            None => {}
        }

        if let Some(action) = action {
            self.handle_detail_action(action);
        }
    }

    fn show_secret_rail(&mut self, context: &egui::Context) {
        egui::SidePanel::left("secret-rail")
            .exact_width(SECRET_RAIL_WIDTH)
            .frame(Frame::new().fill(INK).inner_margin(Margin::same(12)))
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
                ui.add_space(12.0);
                let remaining = with_controller(&self.controller, |controller| {
                    Ok(controller.remaining_unlocked().unwrap_or_default())
                })
                .unwrap_or_default();
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(8.0, 16.0), egui::Sense::hover());
                    let (center, radius) = status_dot_geometry(rect);
                    ui.painter().circle_filled(center, radius, COBALT);
                    ui.label(RichText::new("UNLOCKED").strong().color(COBALT));
                });
                ui.label(
                    RichText::new(format_remaining(remaining))
                        .size(12.0)
                        .color(Color32::from_rgb(173, 187, 214)),
                );
                #[cfg(unix)]
                self.show_agent_access(ui);
                ui.add_space(18.0);
                ui.label(
                    RichText::new("Secrets")
                        .size(12.0)
                        .color(Color32::from_rgb(158, 176, 211)),
                );
                ui.add_space(8.0);

                let new_secret =
                    secret_navigation_row(ui, "new-secret", false, NEW_SECRET_ROW_HEIGHT, |ui| {
                        ui.label(
                            RichText::new("+ New secret")
                                .size(NEW_SECRET_TEXT_SIZE)
                                .color(Color32::WHITE),
                        );
                    });
                if new_secret.clicked() {
                    self.request_navigation(NavigationTarget::Add);
                }
                ui.add_space(4.0);

                let secrets =
                    with_controller(&self.controller, |controller| Ok(controller.secrets()))
                        .unwrap_or_default();
                if secrets.is_empty() {
                    ui.label(
                        RichText::new("No secrets yet").color(Color32::from_rgb(173, 187, 214)),
                    );
                }
                for secret in &secrets {
                    let selected = self.detail.selected() == Some(secret.id);
                    let summary = summarize_field_names(&secret.field_names);
                    let metadata_color = if selected {
                        Color32::from_rgb(226, 234, 255)
                    } else {
                        Color32::from_rgb(173, 187, 214)
                    };
                    let response = secret_navigation_row(
                        ui,
                        ("secret-row", secret.id.to_string()),
                        selected,
                        SECRET_ROW_HEIGHT,
                        |ui| {
                            ui.allocate_ui_with_layout(
                                egui::vec2(74.0, 22.0),
                                Layout::left_to_right(Align::Center),
                                |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&secret.name)
                                                .size(SECRET_ROW_TEXT_SIZE)
                                                .color(Color32::WHITE),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(&secret.name);
                                },
                            );
                            if let Some(primary) = summary.primary {
                                ui.label(RichText::new(primary).size(10.0).color(metadata_color))
                                    .on_hover_text(primary);
                            }
                            if summary.additional_count > 0 {
                                ui.label(
                                    RichText::new(format!("+{}", summary.additional_count))
                                        .size(10.0)
                                        .strong()
                                        .color(metadata_color),
                                )
                                .on_hover_text(&summary.additional_hover);
                            }
                        },
                    );
                    if response.clicked() {
                        self.request_navigation(NavigationTarget::Secret(secret.id));
                    }
                    ui.add_space(4.0);
                }
            });
    }

    #[cfg(unix)]
    fn clear_agent_grants(&mut self) {
        self.agent_grants.clear();
        self.agent_grants_session = None;
        self.agent_grants_error_shown = false;
    }

    #[cfg(unix)]
    fn refresh_agent_grants(&mut self) {
        if self.desktop_lock != DesktopLockState::Active {
            self.clear_agent_grants();
            return;
        }
        let result = (|| {
            let session = self.vault_session_id()?;
            if self.agent_grants_session != Some(session) {
                self.clear_agent_grants();
                self.agent_grants_session = Some(session);
            }
            self.broker
                .as_ref()
                .ok_or(LadonError::EndpointUnavailable)
                .and_then(|broker| broker.agent_grants(&self.controller))
        })();
        match result {
            Ok(grants) => {
                self.agent_grants = grants;
                self.agent_grants_error_shown = false;
            }
            Err(LadonError::VaultLocked) => self.clear_agent_grants(),
            Err(error) if !self.agent_grants_error_shown => {
                self.notice_from(Err(error), "");
                self.agent_grants_error_shown = true;
            }
            Err(_) => {}
        }
    }

    #[cfg(unix)]
    fn revoke_agent_grant(&mut self, session: uuid::Uuid, secret: SecretId) {
        let result = self
            .broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)
            .and_then(|broker| broker.revoke_grant(session, secret));
        let revoked = result.is_ok();
        self.notice_from(result, "Agent access revoked");
        if revoked {
            self.refresh_agent_grants();
        }
    }

    #[cfg(unix)]
    fn revoke_all_agent_grants(&mut self) {
        let result = self
            .broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)
            .and_then(LocalBrokerHandle::revoke_grants);
        if result.is_ok() {
            self.clear_agent_grants();
        }
        self.notice_from(result, "Agent access revoked");
    }

    #[cfg(unix)]
    fn show_agent_access(&mut self, ui: &mut egui::Ui) {
        if self.agent_grants.is_empty() {
            return;
        }
        ui.add_space(10.0);
        ui.label(
            RichText::new(format!("Agent access · {}", self.agent_grants.len()))
                .size(12.0)
                .color(Color32::WHITE),
        );
        let mut revoke = None;
        egui::ScrollArea::vertical()
            .id_salt("agent-access")
            .max_height(AGENT_ACCESS_MAX_HEIGHT)
            .show(ui, |ui| {
                for grant in &self.agent_grants {
                    let label = sanitize_untrusted(grant.client_label());
                    let name = sanitize_untrusted(grant.secret_name());
                    let id = grant.client_session_id();
                    ui.push_id((id, grant.secret_id().to_string()), |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&label).size(11.0).color(Color32::WHITE),
                            )
                            .truncate(),
                        )
                        .on_hover_text(format!("{label} (reported)\nSession: {id}"));
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("(reported)")
                                    .size(10.0)
                                    .color(Color32::LIGHT_GRAY),
                            );
                            ui.label(
                                RichText::new(short_session_id(id))
                                    .monospace()
                                    .size(10.0)
                                    .color(Color32::LIGHT_GRAY),
                            )
                            .on_hover_text(id.to_string());
                        });
                        ui.add(
                            egui::Label::new(RichText::new(&name).size(12.0).color(Color32::WHITE))
                                .truncate(),
                        )
                        .on_hover_text(&name);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format_grant_remaining(grant.remaining()))
                                    .monospace()
                                    .size(11.0)
                                    .color(Color32::LIGHT_GRAY),
                            );
                            if grant.running() {
                                ui.label(
                                    RichText::new("Running")
                                        .size(10.0)
                                        .color(Color32::LIGHT_GRAY),
                                );
                            }
                            if ui.small_button("Revoke").clicked() {
                                revoke = Some((id, grant.secret_id()));
                            }
                        });
                        ui.add_space(6.0);
                    });
                }
            });
        if let Some((session, secret)) = revoke {
            self.revoke_agent_grant(session, secret);
        }
        if ui.small_button("Revoke all").clicked() {
            self.revoke_all_agent_grants();
        }
    }

    fn selected_metadata(&self) -> Option<SecretMetadata> {
        let selected = self.detail.selected()?;
        with_controller(&self.controller, |controller| Ok(controller.secrets()))
            .ok()?
            .into_iter()
            .find(|secret| secret.id == selected)
    }

    fn vault_session_id(&self) -> Result<uuid::Uuid, LadonError> {
        with_controller(&self.controller, |controller| {
            controller.session_id().ok_or(LadonError::VaultLocked)
        })
    }

    fn request_navigation(&mut self, target: NavigationTarget) {
        match self.detail.request_navigation(target) {
            NavigationResult::Applied => {
                self.finish_applied_navigation();
            }
            NavigationResult::ConfirmDiscard => {
                self.discard_confirmation = true;
            }
        }
    }

    fn finish_applied_navigation(&mut self) {
        self.pending_touch_id = None;
        self.unlock_confirmation = false;
        self.discard_confirmation = false;
        self.local_pin.clear();
        self.pending_delete = None;
        self.add_form_error = None;
        self.notice = None;
    }

    fn finish_discard_navigation(&mut self) -> bool {
        let closing = self.detail.pending_navigation() == Some(NavigationTarget::Close);
        self.detail.discard_pending_navigation();
        self.finish_applied_navigation();
        closing
    }

    fn show_secret_confirmation(&mut self, context: &egui::Context, secret: &SecretMetadata) {
        let touch_id_available = TouchIdAuthenticator::is_available();
        let pin_configured = self
            .session_confirmation
            .as_ref()
            .is_some_and(SessionConfirmation::has_pin);
        let actions = confirmation_actions(touch_id_available, pin_configured);
        let mut action = None;
        let mut cancel = false;
        egui::Modal::new("secret-confirmation".into())
            .frame(
                Frame::window(&context.style())
                    .fill(PANEL)
                    .inner_margin(Margin::same(18)),
            )
            .show(context, |ui| {
                ui.set_width(AUTH_FORM_WIDTH);
                ui.label(RichText::new("Unlock this secret").size(24.0).color(INK));
                ui.label(RichText::new("Confirm once for this selected secret.").color(MUTED));
                ui.add_space(18.0);
                if actions.contains(&ConfirmationAction::TouchId)
                    && primary_button(ui, "Confirm with Touch ID").clicked()
                {
                    action = Some(ConfirmationAction::TouchId);
                }
                if actions.contains(&ConfirmationAction::Pin) {
                    ui.add_space(14.0);
                    password_field(ui, &mut self.local_pin, "Session PIN");
                    if quiet_button(ui, "Confirm with PIN").clicked() {
                        action = Some(ConfirmationAction::Pin);
                    }
                }
                if actions.is_empty() {
                    ui.label(
                        RichText::new(
                            "Touch ID is unavailable and this session has no configured PIN.",
                        )
                        .color(AMBER),
                    );
                }
                ui.add_space(10.0);
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
                self.show_notice(ui);
            });

        if cancel {
            self.pending_touch_id = None;
            self.unlock_confirmation = false;
            self.local_pin.clear();
        } else if let Some(action) = action {
            self.authenticate_selected_secret(action, &secret.name);
        }
    }

    fn authenticate_selected_secret(&mut self, action: ConfirmationAction, secret_name: &str) {
        let Ok(captured_session_id) = self.vault_session_id() else {
            self.synchronize_phase(VaultUiPhase::Locked);
            return;
        };
        let Some(attempt) = self.detail.authentication_attempt(captured_session_id) else {
            self.unlock_confirmation = false;
            self.local_pin.clear();
            return;
        };

        match action {
            ConfirmationAction::TouchId => {
                if self.pending_touch_id.is_some() {
                    return;
                }
                match TouchIdAuthenticator::authenticate_secret(secret_name) {
                    Ok(authentication) => {
                        self.pending_touch_id = Some(PendingTouchId {
                            authentication,
                            target: TouchIdTarget::Secret {
                                attempt,
                                vault_session_id: captured_session_id,
                            },
                        });
                    }
                    Err(error) => self.notice_from(Err(error), ""),
                }
            }
            ConfirmationAction::Pin => {
                self.pending_touch_id = None;
                let verification = self
                    .session_confirmation
                    .as_mut()
                    .ok_or(LadonError::ApprovalAuthenticationFailed)
                    .and_then(|confirmation| confirmation.verify_pin(&self.local_pin));
                self.local_pin.clear();
                match verification {
                    Ok(PinVerification::Accepted) => {
                        let current_session_id = self.vault_session_id().ok();
                        if current_session_id == Some(captured_session_id)
                            && self
                                .detail
                                .accept_authentication(attempt, captured_session_id)
                        {
                            self.unlock_confirmation = false;
                            self.notice = Some(Notice {
                                text: "Secret unlocked for this selection".to_owned(),
                                danger: false,
                            });
                        } else {
                            self.reject_stale_authentication();
                        }
                    }
                    Ok(PinVerification::Rejected { remaining_attempts }) => {
                        self.notice = Some(Notice {
                            text: format!("PIN rejected; {remaining_attempts} attempts remain"),
                            danger: true,
                        });
                    }
                    Ok(PinVerification::LockVault) => self.lock_immediately(),
                    Err(error) => self.notice_from(Err(error), ""),
                }
            }
        }
    }

    fn reject_stale_authentication(&mut self) {
        self.pending_touch_id = None;
        let phase = with_controller(&self.controller, |controller| Ok(controller.phase()))
            .unwrap_or(VaultUiPhase::Locked);
        self.synchronize_phase(phase);
        self.unlock_confirmation = false;
        self.local_pin.clear();
        self.notice = Some(Notice {
            text: "Authentication expired because the selected context changed".to_owned(),
            danger: true,
        });
    }

    fn process_touch_id_result(&mut self) {
        let result = self
            .pending_touch_id
            .as_ref()
            .and_then(|pending| pending.authentication.try_result());
        let Some(result) = result else {
            return;
        };
        let Some(pending) = self.pending_touch_id.take() else {
            return;
        };
        self.local_pin.clear();
        match (pending.target, result) {
            (
                TouchIdTarget::AppUnlock {
                    vault_session_id,
                    lock_epoch,
                },
                Ok(()),
            ) => self.finish_app_unlock_touch_id(vault_session_id, lock_epoch),
            (
                TouchIdTarget::Secret {
                    attempt,
                    vault_session_id,
                },
                Ok(()),
            ) => self.finish_selected_touch_id(attempt, vault_session_id),
            #[cfg(unix)]
            (
                TouchIdTarget::Approval {
                    approval_id,
                    vault_session_id,
                },
                Ok(()),
            ) => self.finish_approval_touch_id(approval_id, vault_session_id),
            (_, Err(LadonError::ApprovalCancelled)) => {}
            (_, Err(error)) => self.notice_from(Err(error), ""),
        }
    }

    fn finish_selected_touch_id(
        &mut self,
        attempt: LocalAuthAttempt,
        captured_session_id: uuid::Uuid,
    ) {
        let current_session_id = self.vault_session_id().ok();
        if current_session_id == Some(captured_session_id)
            && self
                .detail
                .accept_authentication(attempt, captured_session_id)
        {
            if let Some(confirmation) = &mut self.session_confirmation {
                confirmation.record_touch_id_success();
            }
            self.unlock_confirmation = false;
            self.local_pin.clear();
            self.notice = Some(Notice {
                text: "Secret unlocked for this selection".to_owned(),
                danger: false,
            });
        } else {
            self.reject_stale_authentication();
        }
    }

    fn handle_detail_action(&mut self, action: DetailAction) {
        match action {
            DetailAction::Show | DetailAction::Edit => {
                let Some(selected) = self.detail.selected() else {
                    return;
                };
                let result = (|| {
                    let mut controller = self
                        .controller
                        .lock()
                        .map_err(|_| LadonError::ProcessFailure)?;
                    let session_id = controller.session_id().ok_or(LadonError::VaultLocked)?;
                    let draft = controller.load_secret(selected)?;
                    let transition = if matches!(action, DetailAction::Show) {
                        self.detail.begin_reveal(session_id, draft)
                    } else {
                        self.detail.begin_edit(session_id, draft)
                    };
                    Ok::<_, LadonError>(transition)
                })();
                match result {
                    Ok(state_result) => {
                        if state_result.is_err() {
                            self.notice = Some(Notice {
                                text: "The selected secret changed before it could be opened"
                                    .to_owned(),
                                danger: true,
                            });
                        }
                    }
                    Err(error) => self.handle_sensitive_operation_error(error),
                }
            }
            DetailAction::Hide | DetailAction::Cancel => self.detail.hide_values(),
            DetailAction::Save => {
                let result = match self.detail.mode() {
                    DetailMode::Editing { draft, .. } => self.update_secret(draft),
                    DetailMode::Hidden | DetailMode::Revealed(_) => Err(LadonError::InvalidRequest),
                };
                match result {
                    Ok(()) => {
                        self.detail.finish_save();
                        self.notice = Some(Notice {
                            text: "Secret changes saved locally".to_owned(),
                            danger: false,
                        });
                    }
                    Err(error) => self.handle_sensitive_operation_error(error),
                }
            }
        }
    }

    #[cfg(unix)]
    fn update_secret(&self, draft: &crate::EditSecretDraft) -> Result<(), LadonError> {
        self.broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)?
            .update_secret(&self.controller, draft)
    }

    #[cfg(not(unix))]
    fn update_secret(&self, draft: &crate::EditSecretDraft) -> Result<(), LadonError> {
        with_controller(&self.controller, |controller| {
            let update = controller.prepare_secret_update(draft)?;
            controller.apply_secret_update(update)
        })
    }

    #[cfg(unix)]
    fn delete_secret(&self, id: SecretId) -> Result<(), LadonError> {
        self.broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)?
            .delete_secret(&self.controller, id)
    }

    #[cfg(not(unix))]
    fn delete_secret(&self, id: SecretId) -> Result<(), LadonError> {
        with_controller(&self.controller, |controller| controller.delete_secret(id))
    }

    fn handle_add_result(&mut self, result: Result<SecretId, LadonError>) {
        match result {
            Ok(_) => {
                self.add_form_error = None;
                self.notice = Some(Notice {
                    text: "Secret saved locally".to_owned(),
                    danger: false,
                });
            }
            Err(error) => self.handle_sensitive_operation_error(error),
        }
    }

    fn handle_delete_result(&mut self, result: Result<(), LadonError>) {
        match result {
            Ok(()) => {
                self.pending_touch_id = None;
                self.detail.navigate_now(NavigationTarget::Add);
                self.unlock_confirmation = false;
                self.local_pin.clear();
                self.notice = Some(Notice {
                    text: "Secret deleted".to_owned(),
                    danger: false,
                });
            }
            Err(error) => self.handle_sensitive_operation_error(error),
        }
    }

    fn handle_sensitive_operation_error(&mut self, error: LadonError) {
        let phase = with_controller(&self.controller, |controller| Ok(controller.phase()))
            .unwrap_or(VaultUiPhase::Locked);
        self.synchronize_phase(phase);
        self.notice_from(Err(error), "");
    }

    fn show_discard_confirmation(&mut self, context: &egui::Context) {
        let mut continue_editing = false;
        let mut discard = false;
        egui::Modal::new("discard-confirmation".into())
            .frame(
                Frame::window(&context.style())
                    .fill(PANEL)
                    .inner_margin(Margin::same(18)),
            )
            .show(context, |ui| {
                ui.set_width(AUTH_FORM_WIDTH);
                ui.label(
                    RichText::new("Discard unsaved changes?")
                        .size(22.0)
                        .color(INK),
                );
                ui.label(RichText::new("Your current edits have not been saved.").color(MUTED));
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    if quiet_button(ui, "Continue editing").clicked() {
                        continue_editing = true;
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Discard changes").color(Color32::WHITE),
                            )
                            .fill(DANGER),
                        )
                        .clicked()
                    {
                        discard = true;
                    }
                });
            });
        if continue_editing {
            self.detail.cancel_pending_navigation();
            self.discard_confirmation = false;
        } else if discard {
            let closing = self.finish_discard_navigation();
            if closing {
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn lock_immediately(&mut self) {
        self.clear_clipboard();
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
        self.finish_immediate_lock(result);
    }

    fn lock_app(&mut self) {
        self.lock_app_with_touch_id_availability(TouchIdAuthenticator::is_available());
    }

    fn lock_app_with_touch_id_availability(&mut self, touch_id_available: bool) {
        self.clear_clipboard();
        let can_unlock = touch_id_available
            || self
                .session_confirmation
                .as_ref()
                .is_some_and(SessionConfirmation::has_pin);
        if !can_unlock {
            self.lock_immediately();
            return;
        }

        #[cfg(unix)]
        {
            let attempt = self
                .broker
                .as_ref()
                .ok_or(LadonError::EndpointUnavailable)
                .and_then(LocalBrokerHandle::begin_app_lock);
            match attempt {
                Ok(attempt) => {
                    let epoch = attempt.epoch();
                    self.desktop_lock_epoch = epoch;
                    self.desktop_lock = DesktopLockState::Locking { epoch };
                    self.pending_app_lock = Some(attempt);
                    self.clear_for_app_lock();
                }
                Err(_) => self.lock_immediately(),
            }
        }

        #[cfg(not(unix))]
        {
            let Some(epoch) = self.desktop_lock_epoch.checked_add(1) else {
                self.lock_immediately();
                return;
            };
            self.desktop_lock_epoch = epoch;
            self.desktop_lock = DesktopLockState::Locking { epoch };
            self.clear_for_app_lock();
            self.desktop_lock = DesktopLockState::Locked { epoch };
        }
    }

    #[cfg(unix)]
    fn process_app_lock_result(&mut self) {
        let completion = self
            .pending_app_lock
            .as_ref()
            .and_then(|attempt| attempt.try_result().map(|result| (attempt.epoch(), result)));
        let Some((epoch, result)) = completion else {
            return;
        };
        self.pending_app_lock = None;
        self.finish_app_lock_result(epoch, result);
    }

    #[cfg(unix)]
    fn finish_app_lock_result(&mut self, epoch: u64, result: Result<(), LadonError>) {
        let expected = self.desktop_lock == DesktopLockState::Locking { epoch }
            && self.desktop_lock_epoch == epoch;
        if result.is_ok() && expected {
            self.desktop_lock = DesktopLockState::Locked { epoch };
        } else {
            self.lock_immediately();
        }
    }

    fn show_app_locking(&mut self, ui: &mut egui::Ui) {
        centered_column(ui, |ui| {
            ui.label(RichText::new("Ladon").size(28.0).color(INK));
            ui.add_space(8.0);
            ui.label(RichText::new("Finishing active command cleanup…").color(MUTED));
        });
    }

    fn show_app_locked(&mut self, ui: &mut egui::Ui) {
        centered_column(ui, |ui| {
            ui.label(RichText::new("Ladon").size(28.0).color(INK));
            ui.add_space(8.0);
            ui.label(RichText::new("App locked").color(MUTED));
            ui.add_space(22.0);
            let mut focus_pin = false;
            if !self.app_unlock_pin_visible && primary_button(ui, "Unlock").clicked() {
                focus_pin = self.begin_app_unlock() == AppUnlockStart::Pin;
            }
            let pin_configured = self
                .session_confirmation
                .as_ref()
                .is_some_and(SessionConfirmation::has_pin);
            if pin_configured && !self.app_unlock_pin_visible {
                ui.add_space(10.0);
                if quiet_button(ui, "Use PIN instead").clicked() {
                    self.use_app_unlock_pin();
                    focus_pin = true;
                }
            }
            if self.app_unlock_pin_visible {
                ui.add_space(14.0);
                let response = password_field(ui, &mut self.local_pin, "Session PIN");
                if focus_pin {
                    response.request_focus();
                }
                let submit =
                    response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                ui.add_space(10.0);
                if primary_button(ui, "Unlock with PIN").clicked() || submit {
                    self.authenticate_app_pin();
                }
            }
            self.show_notice(ui);
            ui.add_space(10.0);
            if quiet_button(ui, "Lock vault completely").clicked() {
                self.lock_immediately();
            }
        });
    }

    fn begin_app_unlock(&mut self) -> AppUnlockStart {
        self.begin_app_unlock_with(
            TouchIdAuthenticator::is_available(),
            TouchIdAuthenticator::authenticate_app,
        )
    }

    fn begin_app_unlock_with(
        &mut self,
        touch_id_available: bool,
        authenticate: impl FnOnce() -> Result<TouchIdAttempt, LadonError>,
    ) -> AppUnlockStart {
        let pin_configured = self
            .session_confirmation
            .as_ref()
            .is_some_and(SessionConfirmation::has_pin);
        let start = app_unlock_start(touch_id_available, pin_configured);
        match start {
            AppUnlockStart::TouchId => {
                if self.pending_touch_id.is_some() {
                    return start;
                }
                let Some((vault_session_id, lock_epoch)) = self.current_app_unlock_context() else {
                    self.reject_stale_app_unlock();
                    return start;
                };
                self.app_unlock_pin_visible = false;
                self.local_pin.clear();
                match authenticate() {
                    Ok(authentication) => {
                        self.pending_touch_id = Some(PendingTouchId {
                            authentication,
                            target: TouchIdTarget::AppUnlock {
                                vault_session_id,
                                lock_epoch,
                            },
                        });
                    }
                    Err(error) => self.notice_from(Err(error), ""),
                }
            }
            AppUnlockStart::Pin => self.use_app_unlock_pin(),
            AppUnlockStart::HardLock => self.lock_immediately(),
        }
        start
    }

    fn use_app_unlock_pin(&mut self) {
        self.pending_touch_id = None;
        self.local_pin.clear();
        self.app_unlock_pin_visible = true;
        self.notice = None;
    }

    fn authenticate_app_pin(&mut self) {
        let Some((vault_session_id, lock_epoch)) = self.current_app_unlock_context() else {
            self.reject_stale_app_unlock();
            return;
        };
        self.authenticate_app_pin_for_context(vault_session_id, lock_epoch);
    }

    fn authenticate_app_pin_for_context(&mut self, vault_session_id: uuid::Uuid, lock_epoch: u64) {
        if !self.app_unlock_context_matches(vault_session_id, lock_epoch) {
            self.reject_stale_app_unlock();
            return;
        }
        self.pending_touch_id = None;
        let verification = self
            .session_confirmation
            .as_mut()
            .ok_or(LadonError::ApprovalAuthenticationFailed)
            .and_then(|confirmation| confirmation.verify_pin(&self.local_pin));
        self.local_pin.clear();
        match verification {
            Ok(PinVerification::Accepted) => self.finish_app_unlock(vault_session_id, lock_epoch),
            Ok(PinVerification::Rejected { remaining_attempts }) => {
                self.notice = Some(Notice {
                    text: format!("PIN rejected; {remaining_attempts} attempts remain"),
                    danger: true,
                });
            }
            Ok(PinVerification::LockVault) => self.lock_immediately(),
            Err(error) => self.notice_from(Err(error), ""),
        }
    }

    fn finish_app_unlock_touch_id(&mut self, vault_session_id: uuid::Uuid, lock_epoch: u64) {
        self.local_pin.clear();
        if !self.app_unlock_context_matches(vault_session_id, lock_epoch) {
            self.reject_stale_app_unlock();
            return;
        }
        let Some(confirmation) = &mut self.session_confirmation else {
            self.reject_stale_app_unlock();
            return;
        };
        confirmation.record_touch_id_success();
        self.finish_app_unlock(vault_session_id, lock_epoch);
    }

    fn finish_app_unlock(&mut self, vault_session_id: uuid::Uuid, lock_epoch: u64) {
        self.pending_touch_id = None;
        self.local_pin.clear();
        if !self.app_unlock_context_matches(vault_session_id, lock_epoch) {
            self.reject_stale_app_unlock();
            return;
        }

        #[cfg(unix)]
        let result = self
            .broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)
            .and_then(|broker| broker.unlock_app(lock_epoch));
        #[cfg(not(unix))]
        let result = Ok::<(), LadonError>(());

        match result {
            Ok(()) => {
                self.desktop_lock = DesktopLockState::Active;
                self.app_unlock_pin_visible = false;
                self.notice = Some(Notice {
                    text: "App unlocked".to_owned(),
                    danger: false,
                });
            }
            Err(error) => self.notice_from(Err(error), ""),
        }
    }

    fn current_app_unlock_context(&self) -> Option<(uuid::Uuid, u64)> {
        let DesktopLockState::Locked { epoch } = self.desktop_lock else {
            return None;
        };
        if self.desktop_lock_epoch != epoch {
            return None;
        }
        let controller = self.controller.lock().ok()?;
        if controller.phase() != VaultUiPhase::Unlocked {
            return None;
        }
        controller
            .session_id()
            .map(|vault_session_id| (vault_session_id, epoch))
    }

    fn app_unlock_context_matches(&self, vault_session_id: uuid::Uuid, lock_epoch: u64) -> bool {
        self.current_app_unlock_context() == Some((vault_session_id, lock_epoch))
    }

    fn reject_stale_app_unlock(&mut self) {
        self.pending_touch_id = None;
        self.local_pin.clear();
        self.notice = Some(Notice {
            text: "Authentication expired because the app lock context changed".to_owned(),
            danger: true,
        });
    }

    fn finish_immediate_lock(&mut self, result: Result<(), LadonError>) {
        self.clear_sensitive_state();
        match result {
            Ok(()) => self.notice = None,
            Err(error) => self.notice_from(Err(error), ""),
        }
    }

    fn finish_auto_lock(&mut self, auto_locked: bool) {
        if auto_locked {
            self.clear_sensitive_state();
            self.notice = Some(Notice {
                text: "Vault locked after 30 minutes without secret activity".to_owned(),
                danger: false,
            });
        }
    }

    #[cfg(unix)]
    fn process_external_lock(&mut self) {
        let pending = self
            .broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)
            .and_then(LocalBrokerHandle::pending_external_lock);
        match pending {
            Ok(Some(request_id)) => {
                self.clear_sensitive_state();
                self.last_phase = VaultUiPhase::Locked;
                let result = self
                    .broker
                    .as_ref()
                    .ok_or(LadonError::EndpointUnavailable)
                    .and_then(|broker| broker.acknowledge_external_lock(request_id));
                if let Err(error) = result {
                    self.notice_from(Err(error), "");
                }
            }
            Ok(None) => {}
            Err(error) => self.notice_from(Err(error), ""),
        }
    }

    fn clear_unlock_fields(&mut self) {
        self.passphrase.clear();
        self.confirmation.clear();
    }

    fn clear_for_app_lock(&mut self) {
        #[cfg(unix)]
        self.clear_agent_grants();
        self.clear_clipboard();
        self.clear_unlock_fields();
        self.session_pin.clear();
        self.session_pin_confirmation.clear();
        self.local_pin.clear();
        self.app_unlock_pin_visible = false;
        self.pending_touch_id = None;
        self.focused_approval = None;
        self.draft = AddSecretDraft::new();
        self.detail.clear_for_vault_lock();
        self.unlock_confirmation = false;
        self.discard_confirmation = false;
        self.pending_delete = None;
        self.add_form_error = None;
        self.notice = None;
    }

    fn clear_sensitive_state(&mut self) {
        self.clear_for_app_lock();
        self.session_confirmation = None;
        #[cfg(unix)]
        {
            self.pending_app_lock = None;
        }
        self.desktop_lock = DesktopLockState::Active;
    }

    fn ui_clock_millis(&self) -> u64 {
        u64::try_from(self.ui_clock_started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn poll_clipboard(&mut self) {
        if self.clipboard.poll_clear(self.ui_clock_millis()).is_err() {
            if !self.clipboard_clear_notice_shown {
                set_clipboard_notice(
                    &mut self.notice,
                    "Clipboard could not be cleared; Ladon will retry",
                );
                self.clipboard_clear_notice_shown = true;
            }
        } else {
            self.clipboard_clear_notice_shown = false;
        }
    }

    fn clear_clipboard(&mut self) {
        // Drop the lease even if the OS clipboard cannot be read or cleared at lock/exit.
        let mut clipboard = std::mem::take(&mut self.clipboard);
        let _ = clipboard.clear_if_owned();
        self.clipboard_clear_notice_shown = false;
    }

    fn synchronize_phase(&mut self, phase: VaultUiPhase) {
        if self.last_phase == VaultUiPhase::Unlocked && phase != VaultUiPhase::Unlocked {
            #[cfg(unix)]
            if let Some(broker) = &self.broker {
                let external_lock_in_progress = broker.external_lock_in_progress().unwrap_or(true);
                if !external_lock_in_progress {
                    let _ = broker.revoke_grants();
                }
            }
            self.clear_sensitive_state();
        }
        self.last_phase = phase;
    }

    fn notice_from(&mut self, result: Result<(), LadonError>, success: &'static str) {
        self.notice = Some(match result {
            Ok(()) => Notice {
                text: success.to_owned(),
                danger: false,
            },
            Err(error) => Notice {
                text: error.safe_message().to_owned(),
                danger: true,
            },
        });
    }

    fn show_notice(&self, ui: &mut egui::Ui) {
        if let Some(notice) = &self.notice {
            ui.add_space(16.0);
            ui.label(RichText::new(&notice.text).color(if notice.danger {
                DANGER
            } else {
                COBALT
            }));
        }
    }

    #[cfg(unix)]
    fn show_pending_approval(&mut self, context: &egui::Context) {
        let pending = match self
            .broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)
            .and_then(LocalBrokerHandle::pending_approval)
        {
            Ok(Some(pending)) => pending,
            Ok(None) => {
                self.cancel_stale_approval_touch_id(None);
                update_focused_approval(&mut self.focused_approval, &mut self.local_pin, None);
                return;
            }
            Err(error) => {
                self.cancel_stale_approval_touch_id(None);
                update_focused_approval(&mut self.focused_approval, &mut self.local_pin, None);
                self.notice_from(Err(error), "");
                return;
            }
        };
        self.cancel_stale_approval_touch_id(Some((pending.id(), pending.vault_session_id())));
        if update_focused_approval(
            &mut self.focused_approval,
            &mut self.local_pin,
            Some(pending.id()),
        ) {
            context.send_viewport_cmd(egui::ViewportCommand::Focus);
        }

        let view = PendingRequestView::from_approval(&pending, Duration::from_secs(2 * 60));
        let touch_id_available = TouchIdAuthenticator::is_available();
        let pin_configured = self
            .session_confirmation
            .as_ref()
            .is_some_and(SessionConfirmation::has_pin);
        let actions = confirmation_actions(touch_id_available, pin_configured);
        let mut action = None;
        egui::Modal::new("agent-approval".into())
            .frame(
                Frame::window(&context.style())
                    .fill(PANEL)
                    .inner_margin(Margin::same(24)),
            )
            .show(context, |ui| {
                ui.set_width(540.0);
                ui.label(
                    RichText::new(format!("Reported client: {}", view.client_label())).color(MUTED),
                );
                ui.add_space(16.0);
                for (name, fields) in view.secrets() {
                    ui.label(RichText::new(name).size(19.0).strong().color(INK));
                    ui.label(RichText::new(fields.join(", ")).color(COBALT));
                }
                ui.add_space(16.0);
                Frame::new()
                    .fill(CANVAS)
                    .corner_radius(6)
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.label(RichText::new(view.executable()).monospace().color(INK));
                        for argument in view.arguments() {
                            ui.label(RichText::new(argument).monospace().color(MUTED));
                        }
                        ui.label(
                            RichText::new(format!("in {}", view.working_directory()))
                                .size(12.0)
                                .color(MUTED),
                        );
                    });
                ui.add_space(12.0);
                ui.label(
                    RichText::new(
                        "Approval lasts 30 minutes for only this client session and these secrets.",
                    )
                    .color(AMBER),
                );
                ui.add_space(16.0);
                if actions.contains(&ConfirmationAction::TouchId)
                    && primary_button(ui, "Confirm with Touch ID").clicked()
                {
                    action = Some(ApprovalAction::Approve(ConfirmationAction::TouchId));
                }
                if actions.contains(&ConfirmationAction::Pin) {
                    ui.add_space(12.0);
                    password_field(ui, &mut self.local_pin, "Session PIN");
                    if quiet_button(ui, "Confirm with PIN").clicked() {
                        action = Some(ApprovalAction::Approve(ConfirmationAction::Pin));
                    }
                }
                if actions.is_empty() {
                    ui.label(
                        RichText::new(
                            "Touch ID is unavailable and this session has no configured PIN.",
                        )
                        .color(AMBER),
                    );
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(egui::Button::new(RichText::new("Deny").color(DANGER)).frame(false))
                        .clicked()
                    {
                        action = Some(ApprovalAction::Deny);
                    }
                });
                self.show_notice(ui);
            });

        match action {
            Some(ApprovalAction::Approve(method)) => {
                self.authenticate_pending_approval(method, &pending);
            }
            Some(ApprovalAction::Deny) => {
                self.pending_touch_id = None;
                self.local_pin.clear();
                let result = self
                    .broker
                    .as_ref()
                    .ok_or(LadonError::EndpointUnavailable)
                    .and_then(|broker| broker.deny(pending.id()));
                self.notice_from(result, "Agent request denied");
            }
            None => {}
        }
    }

    #[cfg(unix)]
    fn authenticate_pending_approval(
        &mut self,
        method: ConfirmationAction,
        pending: &crate::PendingApproval,
    ) {
        let captured_id = pending.id();
        let captured_session_id = pending.vault_session_id();
        if self.vault_session_id().ok() != Some(captured_session_id) {
            self.reject_stale_authentication();
            return;
        }

        if method == ConfirmationAction::TouchId {
            if self.pending_touch_id.is_some() {
                return;
            }
            match TouchIdAuthenticator::authenticate_agent_session() {
                Ok(authentication) => {
                    self.pending_touch_id = Some(PendingTouchId {
                        authentication,
                        target: TouchIdTarget::Approval {
                            approval_id: captured_id,
                            vault_session_id: captured_session_id,
                        },
                    });
                }
                Err(error) => self.notice_from(Err(error), ""),
            }
            return;
        }

        self.pending_touch_id = None;
        let authenticated = match method {
            ConfirmationAction::TouchId => {
                unreachable!("Touch ID starts asynchronously")
            }
            ConfirmationAction::Pin => {
                let verification = self
                    .session_confirmation
                    .as_mut()
                    .ok_or(LadonError::ApprovalAuthenticationFailed)
                    .and_then(|confirmation| confirmation.verify_pin(&self.local_pin));
                self.local_pin.clear();
                match verification {
                    Ok(PinVerification::Accepted) => Ok(true),
                    Ok(PinVerification::Rejected { remaining_attempts }) => {
                        self.notice = Some(Notice {
                            text: format!("PIN rejected; {remaining_attempts} attempts remain"),
                            danger: true,
                        });
                        Ok(false)
                    }
                    Ok(PinVerification::LockVault) => {
                        self.lock_immediately();
                        Ok(false)
                    }
                    Err(error) => Err(error),
                }
            }
        };
        let authenticated = match authenticated {
            Ok(authenticated) => authenticated,
            Err(error) => {
                self.notice_from(Err(error), "");
                return;
            }
        };
        if !authenticated {
            return;
        }

        self.finish_authenticated_approval(captured_id, captured_session_id, false);
    }

    #[cfg(unix)]
    fn cancel_stale_approval_touch_id(&mut self, current: Option<(uuid::Uuid, uuid::Uuid)>) {
        let stale = matches!(
            self.pending_touch_id.as_ref().map(|pending| &pending.target),
            Some(TouchIdTarget::Approval {
                approval_id,
                vault_session_id,
            }) if current != Some((*approval_id, *vault_session_id))
        );
        if stale {
            self.pending_touch_id = None;
        }
    }

    #[cfg(unix)]
    fn finish_approval_touch_id(
        &mut self,
        captured_id: uuid::Uuid,
        captured_session_id: uuid::Uuid,
    ) {
        self.finish_authenticated_approval(captured_id, captured_session_id, true);
    }

    #[cfg(unix)]
    fn finish_authenticated_approval(
        &mut self,
        captured_id: uuid::Uuid,
        captured_session_id: uuid::Uuid,
        touch_id_succeeded: bool,
    ) {
        let current_session_id = self.vault_session_id().ok();
        let current_pending = self
            .broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)
            .and_then(LocalBrokerHandle::pending_approval);
        let exact_request_is_pending = matches!(
            current_pending,
            Ok(Some(ref current))
                if current.id() == captured_id
                    && current.vault_session_id() == captured_session_id
        );
        if current_session_id != Some(captured_session_id) || !exact_request_is_pending {
            self.reject_stale_authentication();
            return;
        }

        let result = self
            .broker
            .as_ref()
            .ok_or(LadonError::EndpointUnavailable)
            .and_then(|broker| broker.approve(captured_id));
        if result.is_ok()
            && touch_id_succeeded
            && let Some(confirmation) = &mut self.session_confirmation
        {
            confirmation.record_touch_id_success();
        }
        self.local_pin.clear();
        self.notice_from(result, "Agent access allowed for 30 minutes");
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
        self.poll_clipboard();
        #[cfg(unix)]
        self.process_external_lock();

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
        self.finish_auto_lock(auto_locked);
        context.request_repaint_after(Duration::from_secs(1));

        #[cfg(unix)]
        self.process_app_lock_result();
        self.process_touch_id_result();

        let phase = with_controller(&self.controller, |controller| Ok(controller.phase()))
            .unwrap_or(VaultUiPhase::Locked);
        self.synchronize_phase(phase);
        #[cfg(unix)]
        self.refresh_agent_grants();
        self.synchronize_window_size(
            context,
            phase == VaultUiPhase::Unlocked
                && self.desktop_lock == DesktopLockState::Active
                && self.session_confirmation.is_some(),
        );
        if phase == VaultUiPhase::Unlocked
            && self.desktop_lock == DesktopLockState::Active
            && context.input(|input| input.viewport().close_requested())
            && self.detail.request_navigation(NavigationTarget::Close)
                == NavigationResult::ConfirmDiscard
        {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.discard_confirmation = true;
        }
        match phase {
            VaultUiPhase::FirstRun => shell(context, |ui| self.show_first_run(ui)),
            VaultUiPhase::Locked => shell(context, |ui| self.show_locked(ui)),
            VaultUiPhase::RecoveryRequired => shell(context, |ui| self.show_recovery(ui)),
            VaultUiPhase::Unlocked => match self.desktop_lock {
                DesktopLockState::Locking { .. } => {
                    shell(context, |ui| self.show_app_locking(ui));
                }
                DesktopLockState::Locked { .. } => {
                    shell(context, |ui| self.show_app_locked(ui));
                }
                DesktopLockState::Active if self.session_confirmation.is_none() => {
                    shell(context, |ui| self.show_session_auth_setup(ui));
                }
                DesktopLockState::Active => {
                    if self.show_unlocked(context) {
                        #[cfg(unix)]
                        self.show_pending_approval(context);
                    }
                }
            },
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.clear_clipboard();
        #[cfg(unix)]
        self.process_external_lock();

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

fn status_dot_geometry(rect: egui::Rect) -> (egui::Pos2, f32) {
    (
        rect.center(),
        3.0_f32.min(rect.width() / 2.0).min(rect.height() / 2.0),
    )
}

#[cfg(any(unix, test))]
fn short_session_id(id: uuid::Uuid) -> String {
    id.to_string()[..8].to_owned()
}

#[cfg(any(unix, test))]
fn format_grant_remaining(remaining: Duration) -> String {
    let seconds = remaining.as_secs();
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

fn secret_navigation_row(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    selected: bool,
    height: f32,
    contents: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    ui.painter()
        .rect_filled(rect, 6.0, secret_row_fill(selected));
    ui.scope_builder(
        egui::UiBuilder::new()
            .id_salt(id)
            .max_rect(rect.shrink2(egui::vec2(SECRET_ROW_LEADING_INSET, 0.0)))
            .layout(Layout::left_to_right(Align::Center)),
        contents,
    );
    response
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
        .frame(Frame::new().fill(CANVAS).inner_margin(Margin::same(24)))
        .show(context, content);
}

fn centered_column(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui)) {
    ui.with_layout(Layout::top_down(Align::Center), |ui| {
        ui.add_space(24.0);
        ui.set_max_width(AUTH_FORM_WIDTH);
        content(ui);
    });
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(12.0).strong().color(INK));
}

fn password_field(ui: &mut egui::Ui, value: &mut SensitiveText, hint: &str) -> egui::Response {
    sensitive_text_field(ui, value, hint, AUTH_FORM_WIDTH)
}

fn sensitive_text_field(
    ui: &mut egui::Ui,
    value: &mut SensitiveText,
    hint: &str,
    width: f32,
) -> egui::Response {
    sensitive_text_edit(ui, value, hint, width, true)
}

fn visible_sensitive_text_field(
    ui: &mut egui::Ui,
    value: &mut SensitiveText,
    hint: &str,
    width: f32,
) -> egui::Response {
    sensitive_text_edit(ui, value, hint, width, false)
}

fn sensitive_text_edit(
    ui: &mut egui::Ui,
    value: &mut SensitiveText,
    hint: &str,
    width: f32,
    password: bool,
) -> egui::Response {
    // Only the explicit Copy button may export a secret, through SecretClipboard.
    // Hide Copy/Cut while this widget handles input. egui can remove all IME
    // events on a focus change, so track their contribution to each saved index.
    let clipboard_events = ui.input_mut(|input| {
        let mut clipboard_events = Vec::new();
        let mut index = 0;
        let mut preceding_ime_events = 0;
        input.events.retain(|event| {
            let clipboard_event = matches!(event, egui::Event::Copy | egui::Event::Cut);
            if clipboard_event {
                clipboard_events.push((index, preceding_ime_events, event.clone()));
            }
            preceding_ime_events += usize::from(matches!(event, egui::Event::Ime(_)));
            index += 1;
            !clipboard_event
        });
        clipboard_events
    });
    let response = ui.add_sized(
        [width, SENSITIVE_FIELD_HEIGHT],
        TextEdit::singleline(value)
            .password(password)
            .hint_text(hint)
            .desired_width(width),
    );
    ui.input_mut(|input| {
        let ime_events_removed = !input
            .events
            .iter()
            .any(|event| matches!(event, egui::Event::Ime(_)));
        for (index, preceding_ime_events, event) in clipboard_events {
            let index = if ime_events_removed {
                index - preceding_ime_events
            } else {
                index
            };
            input.events.insert(index.min(input.events.len()), event);
        }
    });
    // egui stores ordinary Strings for undo. Password mode blocks copy/accessibility output,
    // and clearing the undoer immediately prevents those copies surviving in widget state.
    if let Some(mut state) = TextEdit::load_state(ui.ctx(), response.id) {
        state.clear_undoer();
        state.store(ui.ctx(), response.id);
    }
    response
}

fn remove_field_button(ui: &mut egui::Ui) -> egui::Response {
    ui.add_sized([30.0, REMOVE_BUTTON_HEIGHT], egui::Button::new("×"))
}

fn copy_value_button(
    ui: &mut egui::Ui,
    value: &EditableValue,
    request: &mut Option<SensitiveBytes>,
) {
    if let Some(text) = copyable_text(value)
        && ui
            .add_sized([52.0, SENSITIVE_FIELD_HEIGHT], egui::Button::new("Copy"))
            .clicked()
    {
        *request = Some(SensitiveBytes::new(text.as_bytes().to_vec()));
    }
}

fn add_form_error_text(error: AddDraftValidationError) -> String {
    let field = error.field_index() + 1;
    let detail = match error {
        AddDraftValidationError::MissingName { .. } => "enter a name or remove this field",
        AddDraftValidationError::InvalidName { .. } => {
            "start with a letter; then use letters, numbers, _ or -"
        }
        AddDraftValidationError::DuplicateName { .. } => "this name is already used",
        AddDraftValidationError::ValueTooLarge { .. } => "value exceeds 1 MiB",
    };
    format!("Field {field}: {detail}")
}

fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(COBALT)
            .stroke(Stroke::NONE)
            .corner_radius(6),
    )
}

fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(DANGER)
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

fn update_focused_approval(
    focused: &mut Option<uuid::Uuid>,
    approval_pin: &mut SensitiveText,
    next: Option<uuid::Uuid>,
) -> bool {
    if *focused == next {
        return false;
    }
    approval_pin.clear();
    *focused = next;
    true
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
    fn agent_access_formatting_is_stable_and_compact() {
        let id = Uuid::parse_str("a31f92c4-1111-2222-3333-444444444444").unwrap();
        assert_eq!(short_session_id(id), "a31f92c4");
        assert_eq!(format_grant_remaining(Duration::from_secs(1421)), "23:41");
        assert_eq!(format_grant_remaining(Duration::ZERO), "00:00");
        assert_eq!(format_grant_remaining(Duration::from_secs(5)), "00:05");
        assert_eq!(SECRET_ROW_TEXT_SIZE, NEW_SECRET_TEXT_SIZE);
        assert_eq!(SECRET_ROW_HEIGHT, NEW_SECRET_ROW_HEIGHT);
    }

    #[test]
    fn status_marker_is_a_centered_circle() {
        let rect = egui::Rect::from_min_size(egui::pos2(20.0, 30.0), egui::vec2(10.0, 20.0));
        let (center, radius) = status_dot_geometry(rect);
        assert_eq!(center, egui::pos2(25.0, 40.0));
        assert!(radius > 0.0 && radius <= 5.0);
    }

    #[test]
    #[cfg(unix)]
    fn secret_rail_names_share_the_new_secret_leading_edge() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        let mut draft = AddSecretDraft::new();
        draft.set_name("A");
        draft.fields_mut()[0].value_mut().push_str("unused");
        app.controller
            .lock()
            .unwrap()
            .add_secret(&mut draft)
            .unwrap();
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |context| {
            app.show_secret_rail(context)
        });
        assert_eq!(
            text_position(&output.shapes, "A").x,
            text_position(&output.shapes, "+ New secret").x
        );
        assert!(output.shapes.iter().any(|shape| matches!(&shape.shape, egui::epaint::Shape::Circle(circle) if circle.fill == COBALT)));
    }

    #[cfg(unix)]
    fn grant_desktop_access(app: &LadonDesktop, endpoint: &std::path::Path, id: Uuid, label: &str) {
        use ladon_core::{BindingTarget, RpcMethod, RpcRequest, RpcResult, SecretBindingRequest};
        let request = RpcRequest {
            version: 2,
            request_id: Uuid::new_v4(),
            client_session_id: id,
            client_label: label.to_owned(),
            method: RpcMethod::Run {
                executable: "/bin/echo".to_owned(),
                arguments: vec![],
                working_directory: "/tmp".to_owned(),
                bindings: app
                    .controller
                    .lock()
                    .unwrap()
                    .secrets()
                    .into_iter()
                    .enumerate()
                    .map(|(index, secret)| SecretBindingRequest {
                        secret_ref: secret.name,
                        field: "value".to_owned(),
                        target: BindingTarget::Environment {
                            name: format!("TOKEN_{index}"),
                        },
                    })
                    .collect(),
                timeout_ms: 5_000,
                output_limit_bytes: 1024,
            },
        };
        let client = crate::LocalClient::new(endpoint);
        let running = std::thread::spawn(move || client.call(&request));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(pending) = app.broker.as_ref().unwrap().pending_approval().unwrap() {
                app.broker.as_ref().unwrap().approve(pending.id()).unwrap();
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(
            running.join().unwrap().unwrap().result(),
            Some(RpcResult::Run { .. })
        ));
    }

    #[test]
    #[cfg(unix)]
    fn agent_access_cache_preserves_rows_on_errors_and_revokes_only_the_requested_pair() {
        let (mut app, endpoint, _directory) = app_with_sensitive_detail(false);
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        grant_desktop_access(&app, &endpoint, second, "same label");
        grant_desktop_access(&app, &endpoint, first, "same label");
        app.refresh_agent_grants();
        assert_eq!(app.agent_grants.len(), 2);
        assert_eq!(app.agent_grants[0].client_session_id(), first);
        let secret = app.agent_grants[0].secret_id();
        let broker = app.broker.take();
        app.refresh_agent_grants();
        assert_eq!(app.agent_grants.len(), 2);
        assert!(app.notice.as_ref().unwrap().danger);
        app.notice = None;
        app.refresh_agent_grants();
        assert!(
            app.notice.is_none(),
            "repeat refresh errors must be suppressed"
        );
        app.revoke_agent_grant(first, secret);
        assert_eq!(app.agent_grants.len(), 2);
        assert!(app.notice.as_ref().unwrap().danger);
        app.revoke_all_agent_grants();
        assert_eq!(app.agent_grants.len(), 2);
        assert!(app.notice.as_ref().unwrap().danger);
        app.broker = broker;
        app.refresh_agent_grants();
        assert!(!app.agent_grants_error_shown);
        app.revoke_agent_grant(first, secret);
        assert_eq!(app.agent_grants.len(), 1);
        assert_eq!(app.agent_grants[0].client_session_id(), second);
        app.revoke_all_agent_grants();
        assert!(app.agent_grants.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn agent_access_view_preserves_broker_label_uuid_and_secret_name_order() {
        let (mut app, endpoint, _directory) = app_with_sensitive_detail(false);
        let mut draft = AddSecretDraft::new();
        draft.set_name("A");
        draft.fields_mut()[0].value_mut().push_str("unused");
        app.controller
            .lock()
            .unwrap()
            .add_secret(&mut draft)
            .unwrap();
        // Equal short IDs must still be ordered by the full UUID.
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        let third = Uuid::from_u128(3);
        grant_desktop_access(&app, &endpoint, second, "repeated");
        grant_desktop_access(&app, &endpoint, first, "repeated");
        grant_desktop_access(&app, &endpoint, third, "Alpha");
        app.refresh_agent_grants();
        let observed: Vec<_> = app
            .agent_grants
            .iter()
            .map(|grant| {
                (
                    grant.client_label(),
                    grant.client_session_id(),
                    grant.secret_name(),
                )
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                ("Alpha", third, "A"),
                ("Alpha", third, "external-lock-target"),
                ("repeated", first, "A"),
                ("repeated", first, "external-lock-target"),
                ("repeated", second, "A"),
                ("repeated", second, "external-lock-target"),
            ]
        );
    }

    #[test]
    #[cfg(unix)]
    fn agent_access_cache_clears_on_lock_and_vault_session_changes() {
        let (mut app, endpoint, _directory) = app_with_sensitive_detail(false);
        grant_desktop_access(&app, &endpoint, Uuid::from_u128(1), "client");
        app.refresh_agent_grants();
        let saved = app.agent_grants.clone();
        assert_eq!(saved.len(), 1);
        app.clear_for_app_lock();
        assert!(app.agent_grants.is_empty());
        app.agent_grants = saved.clone();
        app.clear_sensitive_state();
        assert!(app.agent_grants.is_empty());
        app.refresh_agent_grants();
        app.agent_grants = saved;
        app.controller.lock().unwrap().lock();
        app.controller
            .lock()
            .unwrap()
            .unlock(&SensitiveText::from("correct horse"))
            .unwrap();
        let broker = app.broker.take();
        app.refresh_agent_grants();
        assert!(app.agent_grants.is_empty());
        app.broker = broker;
    }

    #[test]
    #[cfg(unix)]
    fn agent_access_controller_failure_keeps_the_previous_snapshot_and_surfaces_once() {
        let (mut app, endpoint, _directory) = app_with_sensitive_detail(false);
        grant_desktop_access(&app, &endpoint, Uuid::from_u128(1), "client");
        app.refresh_agent_grants();
        let controller = Arc::clone(&app.controller);
        let _ = std::thread::spawn(move || {
            let _guard = controller.lock().unwrap();
            panic!("poison controller for snapshot failure regression");
        })
        .join();
        app.refresh_agent_grants();
        assert_eq!(app.agent_grants.len(), 1);
        assert!(app.notice.as_ref().unwrap().danger);
        app.notice = None;
        app.refresh_agent_grants();
        assert!(app.notice.is_none());
        eframe::App::on_exit(&mut app, None);
        assert!(app.agent_grants.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn agent_access_panel_sanitizes_reported_labels_and_contains_no_fields_or_values() {
        let (mut app, endpoint, _directory) = app_with_sensitive_detail(false);
        let id = Uuid::parse_str("a31f92c4-1111-2222-3333-444444444444").unwrap();
        grant_desktop_access(&app, &endpoint, id, "client\n\u{202e}evil");
        app.refresh_agent_grants();
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| app.show_agent_access(ui));
        });
        for expected in [
            "Agent access · 1",
            "client\\u{a}\\u{202e}evil",
            "(reported)",
            "a31f92c4",
            "external-lock-target",
            "Revoke",
            "Revoke all",
        ] {
            assert!(
                output
                    .shapes
                    .iter()
                    .any(|shape| shape_contains_text(&shape.shape, expected)),
                "missing {expected}"
            );
        }
        for forbidden in [
            "client\n\u{202e}evil",
            "value",
            "fake-external-lock-secret",
            "Running",
        ] {
            assert!(
                !output
                    .shapes
                    .iter()
                    .any(|shape| shape_contains_text(&shape.shape, forbidden)),
                "rendered {forbidden}"
            );
        }
    }

    #[test]
    fn selected_action_rows_keep_delete_with_the_primary_actions() {
        assert_eq!(
            selected_action_labels(SelectedActionSet::Unlock),
            (["Unlock this secret"].as_slice(), "Delete")
        );
        assert_eq!(
            selected_action_labels(SelectedActionSet::Hidden),
            (["Show", "Edit"].as_slice(), "Delete")
        );
        assert_eq!(
            selected_action_labels(SelectedActionSet::Revealed),
            (["Hide", "Edit"].as_slice(), "Delete")
        );
        assert_eq!(
            selected_action_labels(SelectedActionSet::Editing).0,
            &[] as &[&str]
        );
    }

    #[test]
    fn remove_control_matches_the_sensitive_text_row_height() {
        assert_eq!(REMOVE_BUTTON_HEIGHT, SENSITIVE_FIELD_HEIGHT);
    }

    #[test]
    fn only_text_values_are_copyable() {
        let text = EditableValue::Text(SensitiveText::from("fake-copy-value"));
        assert_eq!(copyable_text(&text), Some("fake-copy-value"));
        let binary = EditableValue::Binary {
            bytes: ladon_core::SensitiveBytes::new(vec![0xff]),
            original_hint: ladon_core::TextHint::Binary,
        };
        assert_eq!(copyable_text(&binary), None);
    }

    #[test]
    fn clipboard_notice_preserves_authentication_and_destructive_errors() {
        for text in ["Authentication failed", "Delete failed"] {
            let mut notice = Some(Notice {
                text: text.to_owned(),
                danger: true,
            });
            set_clipboard_notice(&mut notice, "Clipboard is unavailable");
            assert_eq!(notice.unwrap().text, text);
        }
        let mut notice = None;
        set_clipboard_notice(&mut notice, "Clipboard is unavailable");
        assert_eq!(notice.unwrap().text, "Clipboard is unavailable");
    }

    fn shape_contains_text(shape: &egui::epaint::Shape, expected: &str) -> bool {
        match shape {
            egui::epaint::Shape::Text(text) => text.galley.job.text == expected,
            egui::epaint::Shape::Vec(shapes) => shapes
                .iter()
                .any(|shape| shape_contains_text(shape, expected)),
            _ => false,
        }
    }

    fn text_position(shapes: &[egui::epaint::ClippedShape], expected: &str) -> egui::Pos2 {
        shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) if text.galley.job.text == expected => {
                    Some(text.pos)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing rendered text: {expected}"))
    }

    #[test]
    #[cfg(unix)]
    fn selected_actions_share_one_row_before_fields_including_delete_confirmation() {
        let (mut app, _, _directory) = app_with_sensitive_detail(false);
        let secret = app.controller.lock().unwrap().secrets().remove(0);
        let context = egui::Context::default();
        configure_style(&context);
        for confirm in [false, true] {
            app.pending_delete = confirm.then_some(secret.id);
            let output = context.run(egui::RawInput::default(), |context| {
                egui::CentralPanel::default()
                    .show(context, |ui| app.show_selected_workspace(ui, &secret));
            });
            let hide = text_position(&output.shapes, "Hide");
            let edit = text_position(&output.shapes, "Edit");
            let delete = text_position(&output.shapes, "Delete");
            assert_eq!(hide.y, edit.y);
            assert_eq!(edit.y, delete.y);
            assert!(delete.y < text_position(&output.shapes, &secret.field_names[0]).y);
            if confirm {
                let cancel = text_position(&output.shapes, "Cancel");
                assert_eq!(delete.y, cancel.y);
                assert!(
                    delete.x < cancel.x,
                    "confirmation keeps Delete then Cancel in the right-hand area"
                );
            }
        }
    }

    #[test]
    fn sensitive_row_widgets_have_equal_rendered_heights() {
        let context = egui::Context::default();
        configure_style(&context);
        let mut value = SensitiveText::from("fake-value");
        let mut name = "value".to_owned();
        let _ = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| {
                ui.horizontal(|ui| {
                    let name = ui.add_sized(
                        [94.0, SENSITIVE_FIELD_HEIGHT],
                        TextEdit::singleline(&mut name),
                    );
                    let value = visible_sensitive_text_field(ui, &mut value, "Value", 170.0);
                    let copy = ui.scope(|ui| {
                        copy_value_button(
                            ui,
                            &EditableValue::Text(SensitiveText::from("fake-copy")),
                            &mut None,
                        )
                    });
                    let remove = remove_field_button(ui);
                    assert_eq!(name.rect.height(), value.rect.height());
                    assert_eq!(value.rect.height(), copy.response.rect.height());
                    assert_eq!(value.rect.height(), remove.rect.height());
                    assert_eq!(remove.rect.height(), 34.0);
                });
            });
        });
    }

    #[test]
    #[cfg(unix)]
    fn add_field_rows_stay_compact_and_keep_remove_aligned_with_values() {
        let (mut app, _, _directory) = app_with_sensitive_detail(false);
        app.draft.fields_mut()[0]
            .value_mut()
            .push_str("fake-primary");
        app.draft.add_field();
        app.draft.fields_mut()[1]
            .value_mut()
            .push_str("fake-additional");
        let context = egui::Context::default();
        configure_style(&context);
        let output = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| app.show_add_workspace(ui));
        });
        let primary = text_position(&output.shapes, "fake-primary");
        let additional = text_position(&output.shapes, "fake-additional");
        let remove = text_position(&output.shapes, "×");
        assert!(primary.y < 200.0);
        assert!(additional.y < 300.0);
        assert!(
            (additional.y - remove.y).abs() < 10.0,
            "remove must align with its value input"
        );
    }

    #[test]
    #[cfg(unix)]
    fn editing_sensitive_input_is_visible_and_clears_undo() {
        let (mut app, _, _directory) = app_with_sensitive_detail(true);
        let secret = app.controller.lock().unwrap().secrets().remove(0);
        let context = egui::Context::default();
        let output = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| {
                app.show_selected_workspace(ui, &secret);
            });
        });
        assert!(
            output
                .shapes
                .iter()
                .any(|shape| shape_contains_text(&shape.shape, "fake-external-lock-secret")),
            "edit values must render visibly"
        );
        // Exercise the same visible-sensitive widget's persisted undo state.
        visible_sensitive_widget_does_not_retain_undo_history();
    }

    #[cfg(unix)]
    fn app_with_sensitive_detail(editing: bool) -> (LadonDesktop, PathBuf, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let path = root.join("vault.ladon");
        let endpoint = root.join("broker.sock");
        let controller = Arc::new(Mutex::new(VaultController::new(path.clone())));
        let passphrase = SensitiveText::from("correct horse");
        let (secret_id, session_id, loaded) = {
            let mut controller = controller.lock().unwrap();
            controller.create(&passphrase, &passphrase).unwrap();
            let mut draft = AddSecretDraft::new();
            draft.set_name("external-lock-target");
            draft.fields_mut()[0]
                .value_mut()
                .push_str("fake-external-lock-secret");
            let secret_id = controller.add_secret(&mut draft).unwrap();
            let session_id = controller.session_id().unwrap();
            let loaded = controller.load_secret(secret_id).unwrap();
            (secret_id, session_id, loaded)
        };
        let mut detail = SecretDetailState::default();
        detail.navigate_now(NavigationTarget::Secret(secret_id));
        let attempt = detail.authentication_attempt(session_id).unwrap();
        assert!(detail.accept_authentication(attempt, session_id));
        if editing {
            detail.begin_edit(session_id, loaded).unwrap();
            detail.mark_dirty();
        } else {
            detail.begin_reveal(session_id, loaded).unwrap();
        }
        let broker = LocalBrokerHandle::start_at_for_desktop(
            Arc::clone(&controller),
            &endpoint,
            Arc::new(|| {}),
        )
        .unwrap();
        let session_pin =
            SessionPin::new(&SensitiveText::from("1234"), &SensitiveText::from("1234")).unwrap();
        (
            LadonDesktop {
                _instance_lock: InstanceLock::acquire(&path).unwrap(),
                controller,
                broker: Some(broker),
                agent_grants: Vec::new(),
                agent_grants_session: None,
                agent_grants_error_shown: false,
                passphrase: SensitiveText::default(),
                confirmation: SensitiveText::default(),
                session_pin: SensitiveText::default(),
                session_pin_confirmation: SensitiveText::default(),
                local_pin: SensitiveText::from("1234"),
                session_confirmation: Some(SessionConfirmation::with_pin(session_pin)),
                desktop_lock: DesktopLockState::Active,
                desktop_lock_epoch: 0,
                pending_app_lock: None,
                app_unlock_pin_visible: false,
                pending_touch_id: None,
                focused_approval: None,
                draft: AddSecretDraft::new(),
                add_form_error: None,
                notice: None,
                clipboard: SecretClipboard::default(),
                ui_clock_started: Instant::now(),
                clipboard_clear_notice_shown: false,
                detail,
                unlock_confirmation: false,
                discard_confirmation: editing,
                pending_delete: None,
                last_phase: VaultUiPhase::Unlocked,
                manager_window_active: true,
            },
            endpoint,
            directory,
        )
    }

    #[cfg(unix)]
    fn assert_external_lock_waits_for_sensitive_detail_wipe(editing: bool) {
        let (mut app, endpoint, directory) = app_with_sensitive_detail(editing);
        let client = crate::LocalClient::new(endpoint);
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        let locking = std::thread::spawn(move || {
            let response = client.call(&ladon_core::RpcRequest {
                version: 2,
                request_id: Uuid::new_v4(),
                client_session_id: Uuid::new_v4(),
                client_label: "desktop lock regression".to_owned(),
                method: ladon_core::RpcMethod::Lock,
            });
            response_tx.send(response).unwrap();
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if app
                .broker
                .as_ref()
                .unwrap()
                .pending_external_lock()
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "external lock notification never arrived"
            );
            std::thread::yield_now();
        }
        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert!(response_rx.recv_timeout(Duration::from_millis(30)).is_err());
        assert!(app.detail.has_sensitive_buffer());

        app.process_external_lock();

        assert!(!app.detail.has_sensitive_buffer());
        assert!(app.detail.selected().is_none());
        assert!(app.session_confirmation.is_none());
        assert!(app.local_pin.as_str().is_empty());
        assert!(!app.discard_confirmation);
        let response = response_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert!(matches!(
            response.result(),
            Some(ladon_core::RpcResult::Locked)
        ));
        assert!(!format!("{response:?}").contains("fake-external-lock-secret"));
        locking.join().unwrap();
        drop(app);
        drop(directory);
    }

    #[cfg(unix)]
    #[test]
    fn external_lock_waits_until_revealed_secret_is_wiped() {
        assert_external_lock_waits_for_sensitive_detail_wipe(false);
    }

    #[cfg(unix)]
    #[test]
    fn external_lock_waits_until_unsaved_edit_is_wiped_without_prompt() {
        assert_external_lock_waits_for_sensitive_detail_wipe(true);
    }

    #[cfg(unix)]
    #[test]
    fn external_lock_cancels_pending_touch_id_before_acknowledgement() {
        let (mut app, endpoint, directory) = app_with_sensitive_detail(false);
        let session_id = app.vault_session_id().unwrap();
        let auth_attempt = app.detail.authentication_attempt(session_id).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (cancelled_tx, cancelled_rx) = std::sync::mpsc::channel();
        let authentication = TouchIdAttempt::spawn_with(move |cancelled| {
            started_tx.send(()).unwrap();
            while !cancelled.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::yield_now();
            }
            cancelled_tx.send(()).unwrap();
            Err(LadonError::ApprovalCancelled)
        })
        .unwrap();
        app.pending_touch_id = Some(PendingTouchId {
            authentication,
            target: TouchIdTarget::Secret {
                attempt: auth_attempt,
                vault_session_id: session_id,
            },
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let client = crate::LocalClient::new(endpoint);
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        let locking = std::thread::spawn(move || {
            let response = client.call(&ladon_core::RpcRequest {
                version: 2,
                request_id: Uuid::new_v4(),
                client_session_id: Uuid::new_v4(),
                client_label: "pending Touch ID lock regression".to_owned(),
                method: ladon_core::RpcMethod::Lock,
            });
            response_tx.send(response).unwrap();
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if app
                .broker
                .as_ref()
                .unwrap()
                .pending_external_lock()
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "external lock notification never arrived"
            );
            std::thread::yield_now();
        }
        assert!(response_rx.recv_timeout(Duration::from_millis(30)).is_err());

        app.process_external_lock();

        assert!(app.pending_touch_id.is_none());
        cancelled_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let response = response_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert!(matches!(
            response.result(),
            Some(ladon_core::RpcResult::Locked)
        ));
        locking.join().unwrap();
        drop(app);
        drop(directory);
    }

    #[cfg(unix)]
    #[test]
    fn app_lock_clears_gui_owned_secret_values_without_ending_the_vault_session() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(true);
        app.passphrase = SensitiveText::from("fake-passphrase");
        app.confirmation = SensitiveText::from("fake-passphrase");
        app.session_pin = SensitiveText::from("1234");
        app.session_pin_confirmation = SensitiveText::from("1234");
        app.focused_approval = Some(Uuid::new_v4());
        app.draft.set_name("unsaved");
        app.draft.fields_mut()[0]
            .value_mut()
            .push_str("fake-draft-secret");
        app.unlock_confirmation = true;
        app.pending_delete = Some(SecretId::new());
        app.notice = Some(Notice {
            text: "fake-secret-notice".to_owned(),
            danger: false,
        });
        app.desktop_lock_epoch = 12;
        app.desktop_lock = DesktopLockState::Locked { epoch: 12 };
        app.app_unlock_pin_visible = true;
        let vault_session_id = app.vault_session_id().unwrap();

        app.clear_for_app_lock();

        assert_eq!(app.vault_session_id().unwrap(), vault_session_id);
        assert!(app.session_confirmation.is_some());
        assert_eq!(app.desktop_lock, DesktopLockState::Locked { epoch: 12 });
        assert_eq!(app.desktop_lock_epoch, 12);
        assert!(!app.app_unlock_pin_visible);
        assert!(app.passphrase.as_str().is_empty());
        assert!(app.confirmation.as_str().is_empty());
        assert!(app.session_pin.as_str().is_empty());
        assert!(app.session_pin_confirmation.as_str().is_empty());
        assert!(app.draft.name().is_empty());
        assert!(app.draft.fields()[0].value().as_str().is_empty());
        assert!(app.local_pin.as_str().is_empty());
        assert!(app.detail.selected().is_none());
        assert!(!app.detail.has_sensitive_buffer());
        assert!(app.pending_touch_id.is_none());
        assert!(app.focused_approval.is_none());
        assert!(!app.unlock_confirmation);
        assert!(!app.discard_confirmation);
        assert!(app.pending_delete.is_none());
        assert!(app.notice.is_none());
    }

    #[cfg(unix)]
    fn finish_pending_app_lock(app: &mut LadonDesktop) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while matches!(app.desktop_lock, DesktopLockState::Locking { .. }) {
            app.process_app_lock_result();
            assert!(
                std::time::Instant::now() < deadline,
                "app lock cleanup did not complete"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn app_unlock_start_prefers_touch_id_and_falls_back_safely() {
        assert_eq!(app_unlock_start(true, true), AppUnlockStart::TouchId);
        assert_eq!(app_unlock_start(true, false), AppUnlockStart::TouchId);
        assert_eq!(app_unlock_start(false, true), AppUnlockStart::Pin);
        assert_eq!(app_unlock_start(false, false), AppUnlockStart::HardLock);
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_single_start_chooses_touch_id_when_pin_is_also_configured() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        let DesktopLockState::Locked { epoch } = app.desktop_lock else {
            panic!("app lock did not reach the locked state");
        };
        let vault_session_id = app.vault_session_id().unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let start = app.begin_app_unlock_with(true, || {
            TouchIdAttempt::spawn_with(move |_| {
                release_rx.recv().unwrap();
                Ok(())
            })
        });

        assert_eq!(start, AppUnlockStart::TouchId);
        assert!(matches!(
            app.pending_touch_id.as_ref().map(|pending| &pending.target),
            Some(TouchIdTarget::AppUnlock {
                vault_session_id: pending_session_id,
                lock_epoch: pending_epoch,
            }) if *pending_session_id == vault_session_id && *pending_epoch == epoch
        ));
        assert!(!app.app_unlock_pin_visible);
        release_tx.send(()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_stale_touch_id_success_does_not_reopen_the_broker_or_manager() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        let DesktopLockState::Locked { epoch } = app.desktop_lock else {
            panic!("app lock did not reach the locked state");
        };
        let vault_session_id = app.vault_session_id().unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let authentication = TouchIdAttempt::spawn_with(move |_| {
            release_rx.recv().unwrap();
            Ok(())
        })
        .unwrap();
        app.pending_touch_id = Some(PendingTouchId {
            authentication,
            target: TouchIdTarget::AppUnlock {
                vault_session_id,
                lock_epoch: epoch,
            },
        });
        let next_epoch = epoch.checked_add(1).unwrap();
        app.desktop_lock_epoch = next_epoch;
        app.desktop_lock = DesktopLockState::Locked { epoch: next_epoch };

        release_tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while app.pending_touch_id.is_some() {
            app.process_touch_id_result();
            assert!(
                std::time::Instant::now() < deadline,
                "fake Touch ID result never arrived"
            );
            std::thread::yield_now();
        }

        assert_eq!(
            app.desktop_lock,
            DesktopLockState::Locked { epoch: next_epoch }
        );
        assert!(!manager_rendering_allowed(
            app.controller.lock().unwrap().phase(),
            app.desktop_lock
        ));
        assert!(matches!(
            app.broker.as_ref().unwrap().begin_app_lock(),
            Err(LadonError::Busy)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_touch_id_success_for_another_vault_session_stays_locked() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        let DesktopLockState::Locked { epoch } = app.desktop_lock else {
            panic!("app lock did not reach the locked state");
        };
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let authentication = TouchIdAttempt::spawn_with(move |_| {
            release_rx.recv().unwrap();
            Ok(())
        })
        .unwrap();
        app.pending_touch_id = Some(PendingTouchId {
            authentication,
            target: TouchIdTarget::AppUnlock {
                vault_session_id: Uuid::new_v4(),
                lock_epoch: epoch,
            },
        });

        release_tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while app.pending_touch_id.is_some() {
            app.process_touch_id_result();
            assert!(
                std::time::Instant::now() < deadline,
                "fake Touch ID result never arrived"
            );
            std::thread::yield_now();
        }

        assert_eq!(app.desktop_lock, DesktopLockState::Locked { epoch });
        assert!(matches!(
            app.broker.as_ref().unwrap().begin_app_lock(),
            Err(LadonError::Busy)
        ));
    }

    #[cfg(unix)]
    fn finish_fake_app_unlock_touch_id(app: &mut LadonDesktop, result: Result<(), LadonError>) {
        let (vault_session_id, lock_epoch) = app.current_app_unlock_context().unwrap();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let authentication = TouchIdAttempt::spawn_with(move |_| {
            release_rx.recv().unwrap();
            result
        })
        .unwrap();
        app.pending_touch_id = Some(PendingTouchId {
            authentication,
            target: TouchIdTarget::AppUnlock {
                vault_session_id,
                lock_epoch,
            },
        });
        release_tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while app.pending_touch_id.is_some() {
            app.process_touch_id_result();
            assert!(
                std::time::Instant::now() < deadline,
                "fake Touch ID result never arrived"
            );
            std::thread::yield_now();
        }
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_cancelled_and_failed_touch_id_leave_pin_failures_untouched() {
        for result in [
            Err(LadonError::ApprovalCancelled),
            Err(LadonError::ApprovalAuthenticationFailed),
        ] {
            let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
            app.lock_app();
            finish_pending_app_lock(&mut app);
            app.local_pin = SensitiveText::from("transient-value");

            finish_fake_app_unlock_touch_id(&mut app, result);

            assert!(matches!(app.desktop_lock, DesktopLockState::Locked { .. }));
            assert!(app.local_pin.as_str().is_empty());
            app.use_app_unlock_pin();
            app.local_pin = SensitiveText::from("9999");
            app.authenticate_app_pin();
            assert_eq!(
                app.notice.as_ref().unwrap().text,
                "PIN rejected; 4 attempts remain"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_touch_id_success_resets_the_shared_pin_failure_counter() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        app.use_app_unlock_pin();
        for remaining in [4, 3, 2, 1] {
            app.local_pin = SensitiveText::from("9999");
            app.authenticate_app_pin();
            assert_eq!(
                app.notice.as_ref().unwrap().text,
                format!("PIN rejected; {remaining} attempts remain")
            );
        }

        finish_fake_app_unlock_touch_id(&mut app, Ok(()));
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        app.use_app_unlock_pin();
        app.local_pin = SensitiveText::from("9999");
        app.authenticate_app_pin();

        assert_eq!(
            app.notice.as_ref().unwrap().text,
            "PIN rejected; 4 attempts remain"
        );
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_five_wrong_pins_hard_lock_the_vault() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        app.use_app_unlock_pin();

        for _ in 0..5 {
            app.local_pin = SensitiveText::from("9999");
            app.authenticate_app_pin();
        }

        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(app.session_confirmation.is_none());
        assert!(app.pending_touch_id.is_none());
        assert!(app.local_pin.as_str().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_valid_pin_reopens_the_broker_and_manager() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        app.use_app_unlock_pin();
        app.local_pin = SensitiveText::from("1234");

        app.authenticate_app_pin();

        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(manager_rendering_allowed(
            app.controller.lock().unwrap().phase(),
            app.desktop_lock
        ));
        assert!(app.local_pin.as_str().is_empty());
        assert!(app.pending_touch_id.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_valid_pin_for_stale_context_does_not_reopen_the_gate() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        let DesktopLockState::Locked { epoch } = app.desktop_lock else {
            panic!("app lock did not reach the locked state");
        };
        app.use_app_unlock_pin();
        app.local_pin = SensitiveText::from("9999");
        app.authenticate_app_pin();
        app.local_pin = SensitiveText::from("1234");

        app.authenticate_app_pin_for_context(Uuid::new_v4(), epoch);

        assert_eq!(app.desktop_lock, DesktopLockState::Locked { epoch });
        assert!(app.local_pin.as_str().is_empty());
        app.local_pin = SensitiveText::from("9999");
        app.authenticate_app_pin();
        assert_eq!(
            app.notice.as_ref().unwrap().text,
            "PIN rejected; 3 attempts remain"
        );
        assert!(matches!(
            app.broker.as_ref().unwrap().begin_app_lock(),
            Err(LadonError::Busy)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn app_unlock_without_an_available_method_hard_locks_the_vault() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.session_confirmation = Some(SessionConfirmation::touch_id_only());
        app.lock_app_with_touch_id_availability(true);
        finish_pending_app_lock(&mut app);

        let start =
            app.begin_app_unlock_with(false, || panic!("Touch ID must not start when unavailable"));

        assert_eq!(start, AppUnlockStart::HardLock);
        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(app.session_confirmation.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn app_lock_and_unlock_do_not_extend_the_controller_idle_deadline() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        let before = app.controller.lock().unwrap().remaining_unlocked().unwrap();

        app.lock_app();
        assert!(matches!(app.desktop_lock, DesktopLockState::Locking { .. }));
        assert!(app.pending_app_lock.is_some());
        assert!(app.session_confirmation.is_some());
        assert!(app.detail.selected().is_none());
        assert!(!app.detail.has_sensitive_buffer());
        finish_pending_app_lock(&mut app);
        let DesktopLockState::Locked { .. } = app.desktop_lock else {
            panic!("app lock did not reach the locked state");
        };
        let after_lock = app.controller.lock().unwrap().remaining_unlocked().unwrap();
        finish_fake_app_unlock_touch_id(&mut app, Ok(()));
        let after_unlock = app.controller.lock().unwrap().remaining_unlocked().unwrap();

        assert!(after_lock <= before);
        assert!(after_unlock <= after_lock);
        assert!(before.saturating_sub(after_unlock) < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn app_lock_completion_for_the_wrong_epoch_hard_locks_the_vault() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.desktop_lock_epoch = 9;
        app.desktop_lock = DesktopLockState::Locking { epoch: 9 };

        app.finish_app_lock_result(8, Ok(()));

        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(app.session_confirmation.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn idle_expiry_while_app_locked_clears_the_retained_confirmation() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.desktop_lock_epoch = 4;
        app.desktop_lock = DesktopLockState::Locked { epoch: 4 };
        app.clear_for_app_lock();
        app.controller.lock().unwrap().lock();

        app.finish_auto_lock(true);

        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(app.session_confirmation.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn external_mcp_lock_upgrades_an_app_lock_to_a_hard_vault_lock() {
        let (mut app, endpoint, _directory) = app_with_sensitive_detail(false);
        app.lock_app();
        finish_pending_app_lock(&mut app);
        assert!(matches!(app.desktop_lock, DesktopLockState::Locked { .. }));

        let client = crate::LocalClient::new(endpoint);
        let locking = std::thread::spawn(move || {
            client.call(&ladon_core::RpcRequest {
                version: 2,
                request_id: Uuid::new_v4(),
                client_session_id: Uuid::new_v4(),
                client_label: "app-locked hard-lock regression".to_owned(),
                method: ladon_core::RpcMethod::Lock,
            })
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if app
                .broker
                .as_ref()
                .unwrap()
                .pending_external_lock()
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "external lock notification never arrived"
            );
            std::thread::yield_now();
        }

        app.process_external_lock();

        assert!(locking.join().unwrap().is_ok());
        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(app.session_confirmation.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn app_lock_completion_failure_wipes_gui_buffers_and_hard_locks_the_vault() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(true);
        app.desktop_lock_epoch = 7;
        app.desktop_lock = DesktopLockState::Locking { epoch: 7 };
        app.passphrase = SensitiveText::from("fake-passphrase");
        app.local_pin = SensitiveText::from("1234");
        app.draft.set_name("fake-draft");

        app.finish_app_lock_result(7, Err(LadonError::ProcessFailure));

        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(app.session_confirmation.is_none());
        assert!(app.passphrase.as_str().is_empty());
        assert!(app.local_pin.as_str().is_empty());
        assert!(app.draft.name().is_empty());
        assert!(app.detail.selected().is_none());
        assert!(!app.detail.has_sensitive_buffer());
    }

    #[cfg(unix)]
    #[test]
    fn app_lock_without_a_local_unlock_method_falls_back_to_a_hard_vault_lock() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.session_confirmation = Some(SessionConfirmation::touch_id_only());

        app.lock_app_with_touch_id_availability(false);

        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(app.session_confirmation.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn app_lock_begin_failure_wipes_gui_buffers_and_hard_locks_the_vault() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(true);
        app.broker = None;
        app.draft.set_name("fake-draft");
        app.local_pin = SensitiveText::from("1234");

        app.lock_app_with_touch_id_availability(false);

        assert_eq!(app.controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(app.session_confirmation.is_none());
        assert!(app.draft.name().is_empty());
        assert!(app.local_pin.as_str().is_empty());
        assert!(app.detail.selected().is_none());
        assert!(!app.detail.has_sensitive_buffer());
    }

    #[test]
    fn session_setup_requires_pin_only_when_touch_id_is_unavailable() {
        assert!(can_finish_session_setup(true, false));
        assert!(can_finish_session_setup(true, true));
        assert!(can_finish_session_setup(false, true));
        assert!(!can_finish_session_setup(false, false));
    }

    #[test]
    fn protected_actions_offer_every_current_confirmation_capability() {
        assert_eq!(
            confirmation_actions(true, true),
            vec![ConfirmationAction::TouchId, ConfirmationAction::Pin]
        );
        assert_eq!(
            confirmation_actions(true, false),
            vec![ConfirmationAction::TouchId]
        );
        assert_eq!(
            confirmation_actions(false, true),
            vec![ConfirmationAction::Pin]
        );
        assert!(confirmation_actions(false, false).is_empty());
    }

    #[test]
    fn manager_rendering_stops_as_soon_as_app_lock_begins() {
        assert!(manager_rendering_allowed(
            VaultUiPhase::Unlocked,
            DesktopLockState::Active
        ));
        assert!(!manager_rendering_allowed(
            VaultUiPhase::Unlocked,
            DesktopLockState::Locking { epoch: 1 }
        ));
        assert!(!manager_rendering_allowed(
            VaultUiPhase::Unlocked,
            DesktopLockState::Locked { epoch: 1 }
        ));
        assert!(!manager_rendering_allowed(
            VaultUiPhase::Locked,
            DesktopLockState::Active
        ));
    }

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
    fn visible_sensitive_widget_does_not_retain_undo_history() {
        let context = egui::Context::default();
        let mut value = SensitiveText::from("fake-visible-secret");
        let mut widget_id = None;
        let _ = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| {
                widget_id =
                    Some(visible_sensitive_text_field(ui, &mut value, "Secret value", 230.0).id);
            });
        });
        let id = widget_id.unwrap();
        let mut state = TextEdit::load_state(&context, id).unwrap();
        let current = (
            state.cursor.char_range().unwrap_or_default(),
            value.as_str().to_owned(),
        );
        let mut undoer = state.undoer();
        undoer.add_undo(&(current.0, "fake-previous-secret".to_owned()));
        assert!(undoer.has_undo(&current));
        state.set_undoer(undoer);
        state.store(&context, id);

        let _ = context.run(egui::RawInput::default(), |context| {
            egui::CentralPanel::default().show(context, |ui| {
                assert_eq!(
                    visible_sensitive_text_field(ui, &mut value, "Secret value", 230.0).id,
                    id
                );
            });
        });
        let state = TextEdit::load_state(&context, id).unwrap();

        assert!(!state.undoer().has_undo(&current));
        assert!(!state.undoer().is_in_flux());
    }

    fn keyboard_clipboard_output(
        event: egui::Event,
        sensitive_focused: bool,
    ) -> (egui::FullOutput, SensitiveText, String) {
        let context = egui::Context::default();
        let mut secret = SensitiveText::from("fake-selected-secret");
        let mut name = "ordinary-name".to_owned();
        let mut selected_id = None;
        let mut render = |context: &egui::Context| {
            egui::CentralPanel::default().show(context, |ui| {
                let sensitive = visible_sensitive_text_field(ui, &mut secret, "Secret", 230.0);
                let ordinary = ui.add(TextEdit::singleline(&mut name));
                selected_id = Some(if sensitive_focused {
                    sensitive.id
                } else {
                    ordinary.id
                });
            });
        };
        let _ = context.run(egui::RawInput::default(), &mut render);
        let id = selected_id.unwrap();
        let mut state = TextEdit::load_state(&context, id).unwrap();
        state
            .cursor
            .set_char_range(Some(egui::text::CCursorRange::two(
                egui::text::CCursor::new(0),
                egui::text::CCursor::new(if sensitive_focused { 20 } else { 13 }),
            )));
        state.store(&context, id);
        context.memory_mut(|memory| memory.request_focus(id));
        let output = context.run(
            egui::RawInput {
                events: vec![event],
                ..Default::default()
            },
            |context| {
                egui::CentralPanel::default().show(context, |ui| {
                    visible_sensitive_text_field(ui, &mut secret, "Secret", 230.0);
                    ui.add(TextEdit::singleline(&mut name));
                });
            },
        );
        (output, secret, name)
    }

    #[test]
    fn visible_sensitive_keyboard_copy_does_not_emit_unmanaged_clipboard_output() {
        let (output, secret, _) = keyboard_clipboard_output(egui::Event::Copy, true);
        assert!(
            output.platform_output.commands.is_empty(),
            "sensitive Copy must not reach the OS clipboard"
        );
        assert_eq!(secret.as_str(), "fake-selected-secret");
    }

    #[test]
    fn visible_sensitive_keyboard_cut_does_not_emit_clipboard_output_or_remove_text() {
        let (output, secret, _) = keyboard_clipboard_output(egui::Event::Cut, true);
        assert!(
            output.platform_output.commands.is_empty(),
            "sensitive Cut must not reach the OS clipboard"
        );
        assert_eq!(
            secret.as_str(),
            "fake-selected-secret",
            "suppressed Cut must not remove the selected secret"
        );
    }

    #[test]
    fn ordinary_keyboard_copy_and_cut_work_next_to_sensitive_input() {
        for event in [egui::Event::Copy, egui::Event::Cut] {
            let cut = matches!(event, egui::Event::Cut);
            let (output, secret, name) = keyboard_clipboard_output(event, false);
            assert!(
                matches!(output.platform_output.commands.as_slice(), [egui::OutputCommand::CopyText(text)] if text == "ordinary-name")
            );
            assert_eq!(name, if cut { "" } else { "ordinary-name" });
            assert_eq!(secret.as_str(), "fake-selected-secret");
        }
    }

    fn ime_clipboard_output(
        shortcut: egui::Event,
        move_focus_to_name: bool,
        ime_before_shortcut: bool,
    ) -> (egui::FullOutput, SensitiveText, String) {
        let context = egui::Context::default();
        let mut secret = SensitiveText::from("fake-selected-secret");
        let mut name = "ordinary-name".to_owned();
        let mut ids = None;
        let mut output = None;
        for frame in 0..4 {
            let events = match frame {
                2 => vec![egui::Event::Ime(egui::ImeEvent::Enabled)],
                3 => {
                    let mut events = vec![shortcut.clone(), egui::Event::Text("x".to_owned())];
                    events.insert(
                        usize::from(!ime_before_shortcut),
                        egui::Event::Ime(egui::ImeEvent::Disabled),
                    );
                    events
                }
                _ => vec![],
            };
            output = Some(context.run(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |context| {
                    if let Some((sensitive_id, ordinary_id)) = ids {
                        let ordinary_focused = frame == 3 && move_focus_to_name;
                        let focused = if ordinary_focused {
                            ordinary_id
                        } else {
                            sensitive_id
                        };
                        context.memory_mut(|memory| memory.request_focus(focused));
                        if frame == 3 {
                            let mut state = TextEdit::load_state(context, focused).unwrap();
                            state
                                .cursor
                                .set_char_range(Some(egui::text::CCursorRange::two(
                                    egui::text::CCursor::new(0),
                                    egui::text::CCursor::new(if ordinary_focused {
                                        13
                                    } else {
                                        20
                                    }),
                                )));
                            state.store(context, focused);
                        }
                    }
                    egui::CentralPanel::default().show(context, |ui| {
                        let sensitive =
                            visible_sensitive_text_field(ui, &mut secret, "Secret", 230.0);
                        if frame == 3 && move_focus_to_name {
                            assert!(
                                ui.input(|input| !input
                                    .events
                                    .iter()
                                    .any(|event| matches!(event, egui::Event::Ime(_)))),
                                "test must exercise egui's focus-loss IME removal"
                            );
                        }
                        let ordinary = ui.add(TextEdit::singleline(&mut name));
                        ids = Some((sensitive.id, ordinary.id));
                    });
                },
            ));
        }
        (output.unwrap(), secret, name)
    }

    #[test]
    fn ime_focus_transition_preserves_ordinary_copy_cut_before_text() {
        for shortcut in [egui::Event::Copy, egui::Event::Cut] {
            for ime_before_shortcut in [true, false] {
                let (output, secret, name) =
                    ime_clipboard_output(shortcut.clone(), true, ime_before_shortcut);
                assert!(
                    matches!(output.platform_output.commands.as_slice(), [egui::OutputCommand::CopyText(text)] if text == "ordinary-name"),
                    "ordinary shortcut must run before the subsequent Text event"
                );
                assert_eq!(name, "x");
                assert_eq!(secret.as_str(), "fake-selected-secret");
            }
        }
    }

    #[test]
    fn ime_sensitive_copy_cut_stays_suppressed_while_text_input_works() {
        for shortcut in [egui::Event::Copy, egui::Event::Cut] {
            for ime_before_shortcut in [true, false] {
                let (output, secret, name) =
                    ime_clipboard_output(shortcut.clone(), false, ime_before_shortcut);
                assert!(output.platform_output.commands.is_empty());
                assert_eq!(secret.as_str(), "x");
                assert_eq!(name, "ordinary-name");
            }
        }
    }

    #[test]
    fn add_form_error_copy_identifies_the_visible_row() {
        assert_eq!(
            add_form_error_text(AddDraftValidationError::MissingName { field_index: 1 }),
            "Field 2: enter a name or remove this field"
        );
        assert_eq!(
            add_form_error_text(AddDraftValidationError::DuplicateName { field_index: 2 }),
            "Field 3: this name is already used"
        );
        assert_eq!(
            add_form_error_text(AddDraftValidationError::InvalidName { field_index: 0 }),
            "Field 1: start with a letter; then use letters, numbers, _ or -"
        );
        assert_eq!(
            add_form_error_text(AddDraftValidationError::ValueTooLarge { field_index: 3 }),
            "Field 4: value exceeds 1 MiB"
        );
    }

    #[cfg(unix)]
    #[test]
    fn applied_navigation_clears_form_feedback() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
        app.add_form_error = Some(AddDraftValidationError::InvalidName { field_index: 1 });
        app.notice = Some(Notice {
            text: "stale feedback".to_owned(),
            danger: true,
        });

        app.request_navigation(NavigationTarget::Add);

        assert!(app.add_form_error.is_none());
        assert!(app.notice.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn confirmed_discard_navigation_clears_form_feedback() {
        let (mut app, _endpoint, _directory) = app_with_sensitive_detail(true);
        app.discard_confirmation = false;
        app.add_form_error = Some(AddDraftValidationError::InvalidName { field_index: 1 });
        app.notice = Some(Notice {
            text: "stale feedback".to_owned(),
            danger: true,
        });

        app.request_navigation(NavigationTarget::Add);
        assert!(app.discard_confirmation);

        let closing = app.finish_discard_navigation();

        assert!(!closing);
        assert!(app.detail.selected().is_none());
        assert!(!app.discard_confirmation);
        assert!(app.add_form_error.is_none());
        assert!(app.notice.is_none());
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
        let selected = SecretId::new();
        let session_id = controller.lock().unwrap().session_id().unwrap();
        let mut detail = SecretDetailState::default();
        detail.navigate_now(NavigationTarget::Secret(selected));
        let attempt = detail.authentication_attempt(session_id).unwrap();
        assert!(detail.accept_authentication(attempt, session_id));
        detail
            .begin_edit(
                session_id,
                crate::EditSecretDraft::from_parts(
                    selected,
                    "selected",
                    vec![crate::EditableField::text(
                        "value",
                        SensitiveText::from("fake-selected-secret"),
                    )],
                ),
            )
            .unwrap();
        let mut app = LadonDesktop {
            _instance_lock: InstanceLock::acquire(&path).unwrap(),
            controller: Arc::clone(&controller),
            #[cfg(unix)]
            broker: None,
            #[cfg(unix)]
            agent_grants: Vec::new(),
            #[cfg(unix)]
            agent_grants_session: None,
            #[cfg(unix)]
            agent_grants_error_shown: false,
            passphrase: SensitiveText::default(),
            confirmation: SensitiveText::default(),
            session_pin: SensitiveText::from("123456"),
            session_pin_confirmation: SensitiveText::from("123456"),
            local_pin: SensitiveText::from("123456"),
            session_confirmation: Some(SessionConfirmation::with_pin(
                SessionPin::new(
                    &SensitiveText::from("123456"),
                    &SensitiveText::from("123456"),
                )
                .unwrap(),
            )),
            desktop_lock: DesktopLockState::Active,
            desktop_lock_epoch: 0,
            #[cfg(unix)]
            pending_app_lock: None,
            app_unlock_pin_visible: false,
            pending_touch_id: None,
            focused_approval: Some(Uuid::new_v4()),
            draft,
            add_form_error: Some(AddDraftValidationError::InvalidName { field_index: 0 }),
            notice: None,
            detail,
            clipboard: SecretClipboard::default(),
            ui_clock_started: Instant::now(),
            clipboard_clear_notice_shown: false,
            unlock_confirmation: true,
            discard_confirmation: true,
            pending_delete: None,
            last_phase: VaultUiPhase::Unlocked,
            manager_window_active: true,
        };
        app.desktop_lock_epoch = 5;
        app.desktop_lock = DesktopLockState::Locked { epoch: 5 };
        app.app_unlock_pin_visible = true;

        controller.lock().unwrap().lock();
        app.synchronize_phase(VaultUiPhase::Locked);

        assert!(app.draft.name().is_empty());
        assert!(app.draft.fields()[0].value().as_str().is_empty());
        assert!(app.session_pin.as_str().is_empty());
        assert!(app.session_pin_confirmation.as_str().is_empty());
        assert!(app.local_pin.as_str().is_empty());
        assert!(app.session_confirmation.is_none());
        assert!(app.detail.selected().is_none());
        assert!(!app.detail.has_sensitive_buffer());
        assert!(!app.unlock_confirmation);
        assert!(!app.discard_confirmation);
        assert!(app.add_form_error.is_none());
        assert!(app.focused_approval.is_none());
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(!app.app_unlock_pin_visible);
        #[cfg(unix)]
        assert!(app.pending_app_lock.is_none());
    }

    #[test]
    fn failed_immediate_lock_still_wipes_gui_authentication_and_detail_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.ladon");
        let controller = Arc::new(Mutex::new(VaultController::new(path.clone())));
        let mut draft = AddSecretDraft::new();
        draft.set_name("unsaved");
        draft.fields_mut()[0].value_mut().push_str("fake-secret");
        let mut app = LadonDesktop {
            _instance_lock: InstanceLock::acquire(&path).unwrap(),
            controller,
            #[cfg(unix)]
            broker: None,
            #[cfg(unix)]
            agent_grants: Vec::new(),
            #[cfg(unix)]
            agent_grants_session: None,
            #[cfg(unix)]
            agent_grants_error_shown: false,
            passphrase: SensitiveText::from("fake-passphrase"),
            confirmation: SensitiveText::from("fake-passphrase"),
            session_pin: SensitiveText::from("123456"),
            session_pin_confirmation: SensitiveText::from("123456"),
            local_pin: SensitiveText::from("123456"),
            session_confirmation: Some(SessionConfirmation::with_pin(
                SessionPin::new(
                    &SensitiveText::from("123456"),
                    &SensitiveText::from("123456"),
                )
                .unwrap(),
            )),
            desktop_lock: DesktopLockState::Active,
            desktop_lock_epoch: 0,
            #[cfg(unix)]
            pending_app_lock: None,
            app_unlock_pin_visible: false,
            pending_touch_id: None,
            focused_approval: Some(Uuid::new_v4()),
            draft,
            add_form_error: None,
            notice: None,
            clipboard: SecretClipboard::default(),
            ui_clock_started: Instant::now(),
            clipboard_clear_notice_shown: false,
            detail: SecretDetailState::default(),
            unlock_confirmation: true,
            discard_confirmation: true,
            pending_delete: Some(SecretId::new()),
            last_phase: VaultUiPhase::Unlocked,
            manager_window_active: true,
        };
        app.desktop_lock_epoch = 6;
        app.desktop_lock = DesktopLockState::Locking { epoch: 6 };
        app.app_unlock_pin_visible = true;

        app.finish_immediate_lock(Err(LadonError::ProcessFailure));

        assert!(app.passphrase.as_str().is_empty());
        assert!(app.draft.name().is_empty());
        assert!(app.local_pin.as_str().is_empty());
        assert!(app.session_confirmation.is_none());
        assert!(!app.unlock_confirmation);
        assert!(!app.discard_confirmation);
        assert!(app.pending_delete.is_none());
        assert!(app.focused_approval.is_none());
        assert_eq!(app.desktop_lock, DesktopLockState::Active);
        assert!(!app.app_unlock_pin_visible);
        #[cfg(unix)]
        assert!(app.pending_app_lock.is_none());
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

    #[test]
    fn approval_pin_is_cleared_when_request_changes_or_disappears() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut focused = Some(first);
        let mut pin = SensitiveText::from("123456");

        assert!(update_focused_approval(
            &mut focused,
            &mut pin,
            Some(second)
        ));
        assert!(pin.as_str().is_empty());
        pin.push_str("654321");
        assert!(update_focused_approval(&mut focused, &mut pin, None));
        assert!(pin.as_str().is_empty());
    }

    #[test]
    fn selected_action_set_is_independent_of_field_count() {
        let hidden = DetailMode::Hidden;
        assert_eq!(
            selected_action_set(false, &hidden),
            SelectedActionSet::Unlock
        );
        assert_eq!(
            selected_action_set(true, &hidden),
            SelectedActionSet::Hidden
        );

        let revealed = DetailMode::Revealed(crate::EditSecretDraft::from_parts(
            SecretId::new(),
            "example",
            vec![],
        ));
        assert_eq!(
            selected_action_set(true, &revealed),
            SelectedActionSet::Revealed
        );

        let editing = DetailMode::Editing {
            draft: crate::EditSecretDraft::from_parts(SecretId::new(), "example", vec![]),
            dirty: false,
        };
        assert_eq!(
            selected_action_set(true, &editing),
            SelectedActionSet::Editing
        );
    }

    #[test]
    fn compact_desktop_layout_has_stable_dimensions() {
        assert_eq!(AUTH_WINDOW_SIZE, [500.0, 380.0]);
        assert_eq!(MANAGER_WINDOW_SIZE, [640.0, 420.0]);
        assert_eq!(WINDOW_MIN_SIZE, [480.0, 340.0]);
        assert_eq!(SECRET_RAIL_WIDTH, 180.0);
        assert_eq!(WORKSPACE_CARD_WIDTH, 380.0);
        assert_eq!(AUTH_FORM_WIDTH, 340.0);
        assert_eq!(window_size(false), AUTH_WINDOW_SIZE);
        assert_eq!(window_size(true), MANAGER_WINDOW_SIZE);
    }

    #[test]
    fn secret_rail_keeps_one_field_inline_and_hides_the_rest_in_hover_text() {
        let fields = vec![
            "value".to_owned(),
            "username".to_owned(),
            "endpoint".to_owned(),
        ];

        let summary = summarize_field_names(&fields);

        assert_eq!(summary.primary, Some("value"));
        assert_eq!(summary.additional_count, 2);
        assert_eq!(summary.additional_hover, "username\nendpoint");

        let single_field = ["token".to_owned()];
        let single = summarize_field_names(&single_field);
        assert_eq!(single.primary, Some("token"));
        assert_eq!(single.additional_count, 0);
        assert!(single.additional_hover.is_empty());
    }

    #[test]
    fn selected_secret_row_uses_cobalt_fill() {
        assert_eq!(secret_row_fill(true), COBALT);
        assert_eq!(secret_row_fill(false), Color32::TRANSPARENT);
    }
}
