//! The injected clock.

use syntheke::Timestamp;

/// A source of the current wall time.
///
/// Every validity decision reads time through this trait, so the crate
/// never touches the system clock and tests pin time exactly. The daemon
/// supplies the real clock.
pub trait Clock {
    /// The current wall time.
    fn now(&self) -> Timestamp;
}

/// A clock that always reads the same instant.
///
/// # Examples
///
/// ```
/// use epitrope::{Clock, FixedClock};
/// use syntheke::Timestamp;
///
/// let clock = FixedClock(Timestamp::from_unix_millis(1_000));
/// assert_eq!(clock.now(), Timestamp::from_unix_millis(1_000));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock(pub Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}
