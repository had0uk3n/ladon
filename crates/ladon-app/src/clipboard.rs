use std::{
    fmt,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, TryRecvError},
    },
};

use ladon_core::SensitiveBytes;
use zeroize::Zeroizing;

use crate::ClipboardLease;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClipboardError;

impl fmt::Display for ClipboardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Clipboard is unavailable")
    }
}

impl std::error::Error for ClipboardError {}

pub(crate) trait ClipboardBackend {
    fn set_text(&mut self, text: &str) -> Result<(), ClipboardError>;
    fn get_text(&mut self) -> Result<String, ClipboardError>;
}

#[derive(Default)]
pub(crate) struct SystemClipboard {
    clipboard: Option<arboard::Clipboard>,
}

impl SystemClipboard {
    fn clipboard(&mut self) -> Result<&mut arboard::Clipboard, ClipboardError> {
        if self.clipboard.is_none() {
            self.clipboard = Some(arboard::Clipboard::new().map_err(|_| ClipboardError)?);
        }

        self.clipboard.as_mut().ok_or(ClipboardError)
    }
}

impl ClipboardBackend for SystemClipboard {
    fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
        self.clipboard()?.set_text(text).map_err(|_| ClipboardError)
    }

    fn get_text(&mut self) -> Result<String, ClipboardError> {
        self.clipboard()?.get_text().map_err(|_| ClipboardError)
    }
}

pub(crate) struct SecretClipboard<B = SystemClipboard> {
    backend: B,
    lease: Option<ClipboardLease>,
    pending_clear: Option<Receiver<ConditionalClearResult>>,
}

impl<B: Default> Default for SecretClipboard<B> {
    fn default() -> Self {
        Self {
            backend: B::default(),
            lease: None,
            pending_clear: None,
        }
    }
}

impl<B: ClipboardBackend> SecretClipboard<B> {
    pub(crate) fn copy(
        &mut self,
        value: SensitiveBytes,
        now_millis: u64,
    ) -> Result<(), ClipboardError> {
        value.expose(|bytes| {
            std::str::from_utf8(bytes)
                .map_err(|_| ClipboardError)
                .and_then(|text| self.backend.set_text(text))
        })?;
        self.lease = Some(ClipboardLease::new(value, now_millis));
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn poll_clear(&mut self, now_millis: u64) -> Result<(), ClipboardError> {
        let Some(lease) = self.lease.as_ref() else {
            return Ok(());
        };
        if !lease.is_expired(now_millis) {
            return Ok(());
        }

        self.clear_if_owned()
    }

    #[cfg(test)]
    pub(crate) fn clear_if_owned(&mut self) -> Result<(), ClipboardError> {
        let Some(lease) = self.lease.as_ref() else {
            return Ok(());
        };
        let clipboard_text = Zeroizing::new(self.backend.get_text()?);
        let still_owned = lease.matches(clipboard_text.as_bytes());
        drop(clipboard_text);

        if still_owned {
            self.backend.set_text("")?;
        }
        self.lease = None;
        Ok(())
    }

    #[cfg(test)]
    fn with_backend(backend: B) -> Self {
        Self {
            backend,
            lease: None,
            pending_clear: None,
        }
    }
}

type ConditionalClearResult = Result<(), (ClipboardError, ClipboardLease)>;

fn clear_lease_if_owned<B: ClipboardBackend>(
    lease: ClipboardLease,
    backend: &mut B,
) -> ConditionalClearResult {
    let clipboard_text = match backend.get_text() {
        Ok(text) => Zeroizing::new(text),
        Err(error) => return Err((error, lease)),
    };
    let still_owned = lease.matches(clipboard_text.as_bytes());
    drop(clipboard_text);
    if still_owned && let Err(error) = backend.set_text("") {
        return Err((error, lease));
    }
    Ok(())
}

fn spawn_conditional_clear<B, F>(
    lease: ClipboardLease,
    make_backend: F,
) -> Result<Receiver<ConditionalClearResult>, (ClipboardError, ClipboardLease)>
where
    B: ClipboardBackend + 'static,
    F: FnOnce() -> B + Send + 'static,
{
    let (sender, result) = mpsc::sync_channel(1);
    let lease = Arc::new(Mutex::new(Some(lease)));
    let worker_lease = Arc::clone(&lease);
    let spawned = std::thread::Builder::new()
        .name("ladon-clipboard-clear".to_owned())
        .spawn(move || {
            let lease = worker_lease
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let Some(lease) = lease else {
                return;
            };
            let mut backend = make_backend();
            let _ = sender.send(clear_lease_if_owned(lease, &mut backend));
        });
    if spawned.is_err() {
        let lease = lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("clipboard worker did not start");
        return Err((ClipboardError, lease));
    }
    Ok(result)
}

impl SecretClipboard<SystemClipboard> {
    pub(crate) fn poll_clear_in_background(
        &mut self,
        now_millis: u64,
    ) -> Result<(), ClipboardError> {
        if let Some(pending) = self.pending_clear.as_ref() {
            match pending.try_recv() {
                Ok(Ok(())) => self.pending_clear = None,
                Ok(Err((error, lease))) => {
                    self.pending_clear = None;
                    if self.lease.is_none() {
                        self.lease = Some(lease);
                    }
                    return Err(error);
                }
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => {
                    self.pending_clear = None;
                    return Err(ClipboardError);
                }
            }
        }

        let expired = self
            .lease
            .as_ref()
            .is_some_and(|lease| lease.is_expired(now_millis));
        if expired {
            let lease = self.lease.take().ok_or(ClipboardError)?;
            match spawn_conditional_clear(lease, SystemClipboard::default) {
                Ok(pending) => self.pending_clear = Some(pending),
                Err((error, lease)) => {
                    self.lease = Some(lease);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn clear_in_background(&mut self) {
        if let Some(lease) = self.lease.take() {
            let _ = spawn_conditional_clear(lease, SystemClipboard::default);
        }
        self.pending_clear = None;
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use zeroize::Zeroizing;

    use super::{ClipboardBackend, ClipboardError, SecretClipboard};
    use crate::SensitiveText;

    #[derive(Default)]
    struct FakeClipboard {
        text: Zeroizing<String>,
        fail_writes: bool,
        fail_reads: bool,
        read_count: usize,
    }

    impl ClipboardBackend for FakeClipboard {
        fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
            if self.fail_writes {
                return Err(ClipboardError);
            }
            self.text = Zeroizing::new(text.to_owned());
            Ok(())
        }

        fn get_text(&mut self) -> Result<String, ClipboardError> {
            self.read_count += 1;
            if self.fail_reads {
                return Err(ClipboardError);
            }
            Ok(self.text.to_string())
        }
    }

    impl SecretClipboard<FakeClipboard> {
        fn test_text(&self) -> &str {
            self.backend.text.as_str()
        }

        fn replace_for_test(&mut self, text: &str) {
            self.backend.text = Zeroizing::new(text.to_owned());
        }

        fn fail_writes_for_test(&mut self) {
            self.backend.fail_writes = true;
        }

        fn allow_writes_for_test(&mut self) {
            self.backend.fail_writes = false;
        }

        fn fail_reads_for_test(&mut self) {
            self.backend.fail_reads = true;
        }

        fn allow_reads_for_test(&mut self) {
            self.backend.fail_reads = false;
        }

        fn read_count_for_test(&self) -> usize {
            self.backend.read_count
        }
    }

    #[test]
    fn expired_ladon_value_is_cleared_but_newer_user_content_is_preserved() {
        let backend = FakeClipboard::default();
        let mut clipboard = SecretClipboard::with_backend(backend);
        clipboard
            .copy(
                SensitiveText::from("fake-copy-value").to_sensitive_bytes(),
                1_000,
            )
            .unwrap();

        clipboard.poll_clear(30_999).unwrap();
        assert_eq!(clipboard.test_text(), "fake-copy-value");
        clipboard.poll_clear(31_000).unwrap();
        assert_eq!(clipboard.test_text(), "");

        clipboard
            .copy(
                SensitiveText::from("fake-second-value").to_sensitive_bytes(),
                40_000,
            )
            .unwrap();
        clipboard.replace_for_test("user-newer-value");
        clipboard.poll_clear(70_000).unwrap();
        assert_eq!(clipboard.test_text(), "user-newer-value");
    }

    #[test]
    fn lock_clear_is_immediate_only_when_ladon_still_owns_the_clipboard() {
        let backend = FakeClipboard::default();
        let mut clipboard = SecretClipboard::with_backend(backend);
        clipboard
            .copy(
                SensitiveText::from("fake-copy-value").to_sensitive_bytes(),
                1_000,
            )
            .unwrap();
        clipboard.clear_if_owned().unwrap();
        assert_eq!(clipboard.test_text(), "");

        clipboard
            .copy(
                SensitiveText::from("fake-second-value").to_sensitive_bytes(),
                2_000,
            )
            .unwrap();
        clipboard.replace_for_test("user-newer-value");
        clipboard.clear_if_owned().unwrap();
        assert_eq!(clipboard.test_text(), "user-newer-value");
    }

    #[test]
    fn failed_clear_keeps_the_lease_for_a_later_retry() {
        let backend = FakeClipboard::default();
        let mut clipboard = SecretClipboard::with_backend(backend);
        clipboard
            .copy(
                SensitiveText::from("fake-copy-value").to_sensitive_bytes(),
                1_000,
            )
            .unwrap();
        clipboard.fail_writes_for_test();

        assert!(clipboard.clear_if_owned().is_err());

        clipboard.allow_writes_for_test();
        clipboard.clear_if_owned().unwrap();
        assert_eq!(clipboard.test_text(), "");
    }

    #[test]
    fn failed_read_keeps_the_lease_for_a_later_retry() {
        let backend = FakeClipboard::default();
        let mut clipboard = SecretClipboard::with_backend(backend);
        clipboard
            .copy(
                SensitiveText::from("fake-copy-value").to_sensitive_bytes(),
                1_000,
            )
            .unwrap();
        clipboard.fail_reads_for_test();

        assert!(clipboard.clear_if_owned().is_err());

        clipboard.allow_reads_for_test();
        clipboard.clear_if_owned().unwrap();
        assert_eq!(clipboard.test_text(), "");
    }

    #[test]
    fn failed_copy_does_not_install_or_replace_a_lease() {
        let backend = FakeClipboard::default();
        let mut clipboard = SecretClipboard::with_backend(backend);
        clipboard.replace_for_test("user-newer-value");
        clipboard.fail_writes_for_test();

        assert!(
            clipboard
                .copy(
                    SensitiveText::from("failed-fresh-copy").to_sensitive_bytes(),
                    1_000,
                )
                .is_err()
        );

        clipboard.allow_writes_for_test();
        clipboard.clear_if_owned().unwrap();
        assert_eq!(clipboard.test_text(), "user-newer-value");
        assert_eq!(clipboard.read_count_for_test(), 0);

        clipboard
            .copy(
                SensitiveText::from("first-copy-value").to_sensitive_bytes(),
                2_000,
            )
            .unwrap();
        clipboard.fail_writes_for_test();

        assert!(
            clipboard
                .copy(
                    SensitiveText::from("failed-replacement-copy").to_sensitive_bytes(),
                    3_000,
                )
                .is_err()
        );

        clipboard.allow_writes_for_test();
        clipboard.clear_if_owned().unwrap();
        assert_eq!(clipboard.test_text(), "");
    }

    #[test]
    fn conditional_clear_worker_never_blocks_the_locking_thread() {
        struct StalledClipboard {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        }

        impl ClipboardBackend for StalledClipboard {
            fn set_text(&mut self, _text: &str) -> Result<(), ClipboardError> {
                Ok(())
            }

            fn get_text(&mut self) -> Result<String, ClipboardError> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                Ok("fake-copy-value".to_owned())
            }
        }

        let lease = crate::ClipboardLease::new(
            SensitiveText::from("fake-copy-value").to_sensitive_bytes(),
            1_000,
        );
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let completion = super::spawn_conditional_clear(lease, move || StalledClipboard {
            entered: entered_tx,
            release: release_rx,
        })
        .unwrap();

        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            completion.try_recv().is_err(),
            "stalled OS I/O must continue outside the locking thread"
        );
        release_tx.send(()).unwrap();
        assert!(
            completion
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_ok()
        );
    }
}
