use std::fmt;

use ladon_core::SensitiveBytes;

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
}

pub(crate) struct SecretClipboard<B = SystemClipboard> {
    backend: B,
}

impl<B: Default> Default for SecretClipboard<B> {
    fn default() -> Self {
        Self {
            backend: B::default(),
        }
    }
}

impl<B: ClipboardBackend> SecretClipboard<B> {
    pub(crate) fn copy(&mut self, value: SensitiveBytes) -> Result<(), ClipboardError> {
        value.expose(|bytes| {
            std::str::from_utf8(bytes)
                .map_err(|_| ClipboardError)
                .and_then(|text| self.backend.set_text(text))
        })
    }

    #[cfg(test)]
    fn with_backend(backend: B) -> Self {
        Self { backend }
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
        write_count: usize,
    }

    impl ClipboardBackend for FakeClipboard {
        fn set_text(&mut self, text: &str) -> Result<(), ClipboardError> {
            if self.fail_writes {
                return Err(ClipboardError);
            }
            self.write_count += 1;
            self.text = Zeroizing::new(text.to_owned());
            Ok(())
        }
    }

    impl SecretClipboard<FakeClipboard> {
        fn test_text(&self) -> &str {
            self.backend.text.as_str()
        }

        fn write_count(&self) -> usize {
            self.backend.write_count
        }
    }

    #[test]
    fn copy_only_sets_the_current_secret_value() {
        let backend = FakeClipboard::default();
        let mut clipboard = SecretClipboard::with_backend(backend);

        clipboard
            .copy(SensitiveText::from("fake-copy-value").to_sensitive_bytes())
            .unwrap();

        assert_eq!(clipboard.test_text(), "fake-copy-value");
        assert_eq!(clipboard.write_count(), 1);
    }

    #[test]
    fn copy_reports_backend_failure_without_retaining_the_value() {
        let backend = FakeClipboard {
            fail_writes: true,
            ..FakeClipboard::default()
        };
        let mut clipboard = SecretClipboard::with_backend(backend);

        assert!(
            clipboard
                .copy(SensitiveText::from("fake-copy-value").to_sensitive_bytes())
                .is_err()
        );
        assert_eq!(clipboard.test_text(), "");
    }
}
