use std::fmt;

use zeroize::Zeroizing;

pub struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl SensitiveBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(self.0.as_slice())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SensitiveBytes([REDACTED; {} bytes])",
            self.len()
        )
    }
}

impl PartialEq for SensitiveBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SensitiveBytes {}
