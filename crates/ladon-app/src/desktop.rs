use std::{
    env,
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
use crate::{AddSecretDraft, SensitiveText, VaultController, VaultUiPhase};

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
        Box::new(move |context| Ok(Box::new(LadonDesktop::new(context, path)))),
    )
    .map_err(|_| "Ladon could not open its native window")
}

struct LadonDesktop {
    controller: Arc<Mutex<VaultController>>,
    #[cfg(unix)]
    broker: Option<LocalBrokerHandle>,
    passphrase: SensitiveText,
    confirmation: SensitiveText,
    draft: AddSecretDraft,
    notice: Option<Notice>,
    selected: Option<SecretId>,
    pending_delete: Option<SecretId>,
}

struct Notice {
    text: &'static str,
    danger: bool,
}

impl LadonDesktop {
    fn new(context: &eframe::CreationContext<'_>, path: PathBuf) -> Self {
        configure_style(&context.egui_ctx);
        let controller = Arc::new(Mutex::new(VaultController::new(path)));
        #[cfg(unix)]
        let (broker, notice) = match LocalBrokerHandle::start(Arc::clone(&controller)) {
            Ok(broker) => (Some(broker), None),
            Err(error) => (
                None,
                Some(Notice {
                    text: error.safe_message(),
                    danger: true,
                }),
            ),
        };
        #[cfg(not(unix))]
        let notice = None;
        Self {
            controller,
            #[cfg(unix)]
            broker,
            passphrase: SensitiveText::default(),
            confirmation: SensitiveText::default(),
            draft: AddSecretDraft::new(),
            notice,
            selected: None,
            pending_delete: None,
        }
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
                    "The primary file could not be opened. Ladon found an authenticated backup.",
                )
                .color(MUTED),
            );
            ui.add_space(18.0);
            if primary_button(ui, "Restore authenticated backup").clicked() {
                let result = with_controller(&self.controller, VaultController::restore_backup);
                self.notice_from(result, "Backup restored");
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
                            if let Some(broker) = &self.broker {
                                broker.cancel_active_run();
                            }
                            let _ = with_controller(&self.controller, |controller| {
                                controller.lock();
                                Ok(())
                            });
                            self.selected = None;
                            self.pending_delete = None;
                            self.notice = None;
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
                                    ui.add(
                                        TextEdit::singleline(field.value_mut())
                                            .password(true)
                                            .hint_text("kept out of chat and command arguments")
                                            .desired_width(350.0),
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

impl eframe::App for LadonDesktop {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        let auto_locked = with_controller(&self.controller, |controller| {
            Ok(controller.auto_lock_if_idle())
        })
        .unwrap_or(false);
        if auto_locked {
            #[cfg(unix)]
            if let Some(broker) = &self.broker {
                broker.cancel_active_run();
            }
            self.selected = None;
            self.pending_delete = None;
            self.notice = Some(Notice {
                text: "Vault locked after 30 minutes without secret activity",
                danger: false,
            });
        }
        context.request_repaint_after(Duration::from_secs(1));

        let phase = with_controller(&self.controller, |controller| Ok(controller.phase()))
            .unwrap_or(VaultUiPhase::Locked);
        match phase {
            VaultUiPhase::FirstRun => shell(context, |ui| self.show_first_run(ui)),
            VaultUiPhase::Locked => shell(context, |ui| self.show_locked(ui)),
            VaultUiPhase::RecoveryRequired => shell(context, |ui| self.show_recovery(ui)),
            VaultUiPhase::Unlocked => self.show_unlocked(context),
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        #[cfg(unix)]
        if let Some(broker) = &self.broker {
            broker.cancel_active_run();
        }
        let _ = with_controller(&self.controller, |controller| {
            controller.lock();
            Ok(())
        });
        self.clear_unlock_fields();
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
    ui.add(
        TextEdit::singleline(value)
            .password(true)
            .hint_text(hint)
            .desired_width(430.0),
    )
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
