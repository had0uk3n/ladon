#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrayAction {
    Open,
    LockApp,
    LockVault,
    Quit,
}

#[cfg(target_os = "macos")]
mod platform {
    use std::sync::mpsc::{self, Receiver, Sender};

    use eframe::egui;
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2::{DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
    use objc2_app_kit::{NSApplication, NSMenu, NSMenuItem, NSStatusBar, NSStatusItem};
    use objc2_foundation::{NSObject, NSObjectProtocol, NSString, ns_string};

    use super::TrayAction;

    struct TrayTargetIvars {
        events: Sender<TrayAction>,
        egui: egui::Context,
    }

    define_class!(
        // SAFETY: NSObject has no subclassing requirements. The generated
        // deallocator drops TrayTargetIvars after NSObject has deallocated.
        #[unsafe(super = NSObject)]
        #[thread_kind = MainThreadOnly]
        #[ivars = TrayTargetIvars]
        struct TrayTarget;

        // SAFETY: NSObjectProtocol has no additional safety requirements.
        unsafe impl NSObjectProtocol for TrayTarget {}

        impl TrayTarget {
            #[unsafe(method(openLadon:))]
            fn open_ladon(&self, _sender: &AnyObject) {
                self.emit(TrayAction::Open);
            }

            #[unsafe(method(lockApp:))]
            fn lock_app(&self, _sender: &AnyObject) {
                self.emit(TrayAction::LockApp);
            }

            #[unsafe(method(lockVault:))]
            fn lock_vault(&self, _sender: &AnyObject) {
                self.emit(TrayAction::LockVault);
            }

            #[unsafe(method(quitLadon:))]
            fn quit_ladon(&self, _sender: &AnyObject) {
                self.emit(TrayAction::Quit);
            }
        }
    );

    impl TrayTarget {
        fn new(
            mtm: MainThreadMarker,
            events: Sender<TrayAction>,
            egui: egui::Context,
        ) -> Retained<Self> {
            let this = Self::alloc(mtm).set_ivars(TrayTargetIvars { events, egui });
            // SAFETY: NSObject's -init signature has no arguments and returns
            // an initialized instance of the receiver's class.
            unsafe { msg_send![super(this), init] }
        }

        fn emit(&self, action: TrayAction) {
            if self.ivars().events.send(action).is_ok() {
                self.ivars().egui.request_repaint();
            }
        }
    }

    pub(crate) struct Tray {
        status_bar: Retained<NSStatusBar>,
        status_item: Retained<NSStatusItem>,
        // NSMenuItem targets are not retained by AppKit. Keep this alive until
        // after the status item (and its menu) has been removed in Drop.
        _target: Retained<TrayTarget>,
        events: Receiver<TrayAction>,
    }

    impl Tray {
        pub(crate) fn new(egui: egui::Context) -> Option<Self> {
            let mtm = MainThreadMarker::new()?;
            let (event_tx, events) = mpsc::channel();
            let target = TrayTarget::new(mtm, event_tx, egui);
            let status_bar = NSStatusBar::systemStatusBar();
            let status_item = status_bar.statusItemWithLength(-1.0);
            let menu = NSMenu::initWithTitle(NSMenu::alloc(mtm), ns_string!("Ladon"));

            add_menu_item(
                &menu,
                ns_string!("Open Ladon"),
                sel!(openLadon:),
                &target,
                mtm,
            );
            add_menu_item(&menu, ns_string!("Lock app"), sel!(lockApp:), &target, mtm);
            add_menu_item(
                &menu,
                ns_string!("Lock vault completely"),
                sel!(lockVault:),
                &target,
                mtm,
            );
            menu.addItem(&NSMenuItem::separatorItem(mtm));
            add_menu_item(&menu, ns_string!("Quit"), sel!(quitLadon:), &target, mtm);

            // NSStatusItem's title remains the smallest supported API surface
            // for the pinned objc2 feature set (the replacement requires the
            // full NSButton/NSView hierarchy solely to set this label).
            #[allow(deprecated)]
            status_item.setTitle(Some(ns_string!("Ladon")));
            status_item.setMenu(Some(&menu));

            Some(Self {
                status_bar,
                status_item,
                _target: target,
                events,
            })
        }

        pub(crate) fn try_event(&self) -> Option<TrayAction> {
            self.events.try_recv().ok()
        }
    }

    impl Drop for Tray {
        fn drop(&mut self) {
            self.status_item.setMenu(None);
            self.status_bar.removeStatusItem(&self.status_item);
        }
    }

    fn add_menu_item(
        menu: &NSMenu,
        title: &NSString,
        action: objc2::runtime::Sel,
        target: &TrayTarget,
        mtm: MainThreadMarker,
    ) {
        // SAFETY: `action` names a one-argument method implemented by
        // TrayTarget. The target is retained by Tray for the menu's lifetime.
        let item = unsafe {
            NSMenuItem::initWithTitle_action_keyEquivalent(
                NSMenuItem::alloc(mtm),
                title,
                Some(action),
                ns_string!(""),
            )
        };
        // SAFETY: Every selector passed above is implemented by TrayTarget with
        // the NSMenuItem action ABI, and Tray outlives the attached menu.
        unsafe { item.setTarget(Some(target)) };
        menu.addItem(&item);
    }

    pub(crate) fn focus_application() {
        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        #[allow(deprecated)]
        NSApplication::sharedApplication(mtm).activateIgnoringOtherApps(true);
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use eframe::egui;

    use super::TrayAction;

    pub(crate) struct Tray;

    impl Tray {
        pub(crate) fn new(_egui: egui::Context) -> Option<Self> {
            None
        }

        pub(crate) fn try_event(&self) -> Option<TrayAction> {
            None
        }
    }

    pub(crate) fn focus_application() {}
}

pub(crate) use platform::{Tray, focus_application};
