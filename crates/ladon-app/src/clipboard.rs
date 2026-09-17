use std::fmt;

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

#[derive(Default)]
pub(crate) struct SecretClipboard<B = SystemClipboard> {
    backend: B,
    lease: Option<ClipboardLease>,
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

    pub(crate) fn poll_clear(&mut self, now_millis: u64) -> Result<(), ClipboardError> {
        let Some(lease) = self.lease.as_ref() else {
            return Ok(());
        };
        if !lease.is_expired(now_millis) {
            return Ok(());
        }

        self.clear_if_owned()
    }

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
        }
    }
}

#[cfg(test)]
mod tests {
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
}
