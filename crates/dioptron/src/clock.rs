//! Wall clocks for authorization decisions.

use std::time::{SystemTime, UNIX_EPOCH};

use epitrope::Clock;
use syntheke::Timestamp;

/// The system wall clock, in milliseconds since the Unix epoch.
///
/// A clock set before the epoch reads as the epoch.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
            });
        Timestamp::from_unix_millis(millis)
    }
}

/// A clock read from a file on every call, so a test can move the time a
/// running daemon sees. Built only with the `test-clock` feature.
///
/// The file holds signed milliseconds since the Unix epoch as decimal
/// text. A file that cannot be read or parsed reads as `i64::MAX`, which
/// expires every grant: an unreadable clock fails closed.
#[cfg(feature = "test-clock")]
#[derive(Clone, Debug)]
pub struct FileClock {
    path: std::path::PathBuf,
}

#[cfg(feature = "test-clock")]
impl FileClock {
    /// The environment variable naming the clock file.
    pub const ENV: &'static str = "DIOPTRON_TEST_CLOCK";

    /// A clock reading `path`.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[cfg(feature = "test-clock")]
impl Clock for FileClock {
    fn now(&self) -> Timestamp {
        let millis = std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|text| text.trim().parse::<i64>().ok())
            .unwrap_or(i64::MAX);
        Timestamp::from_unix_millis(millis)
    }
}

/// The daemon's clock: the file clock when the `test-clock` feature is
/// built and [`FileClock::ENV`] is set, the system clock otherwise.
#[must_use]
pub fn daemon_clock() -> std::sync::Arc<dyn Clock + Send + Sync> {
    #[cfg(feature = "test-clock")]
    if let Some(path) = std::env::var_os(FileClock::ENV) {
        return std::sync::Arc::new(FileClock::new(path));
    }
    std::sync::Arc::new(SystemClock)
}

#[cfg(test)]
mod tests;
