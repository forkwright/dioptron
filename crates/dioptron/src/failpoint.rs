//! Process-level failure injection (`docs/design/custody-store.md`,
//! "Failure-injection specification"). Built only with the `failpoints`
//! feature.
//!
//! With `DIOPTRON_FAILPOINT=<phase>:<boundary>` set, the daemon calls
//! [`std::process::abort`] at that point of the first matching store
//! commit, so a test can restart it and observe recovery. `<phase>` is
//! `before_commit` or `after_commit`; `<boundary>` is `B1` through `B5`.

use phylake::store::{Boundary, Crash, Failpoint, Phase};
use snafu::OptionExt as _;

use crate::error::{Error, UsageSnafu};

/// The environment variable naming the failpoint.
pub const ENV: &str = "DIOPTRON_FAILPOINT";

/// Aborts the process at one boundary and phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbortAt {
    boundary: Boundary,
    phase: Phase,
}

impl AbortAt {
    /// Parses `<phase>:<boundary>`, for example `after_commit:B2`.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] for any other text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let usage = || UsageSnafu {
            message: format!("{ENV} must be before_commit:Bn or after_commit:Bn, found {text}"),
        };
        let (phase, boundary) = text.split_once(':').with_context(usage)?;
        let phase = match phase {
            "before_commit" => Phase::BeforeCommit,
            "after_commit" => Phase::AfterCommit,
            _ => return usage().fail(),
        };
        let boundary = Boundary::ALL
            .into_iter()
            .find(|candidate| candidate.name() == boundary)
            .with_context(usage)?;
        Ok(Self { boundary, phase })
    }

    /// The failpoint [`ENV`] names, if it is set.
    ///
    /// # Errors
    ///
    /// As [`AbortAt::parse`].
    pub fn from_env() -> Result<Option<Self>, Error> {
        std::env::var(ENV)
            .ok()
            .map(|text| Self::parse(&text))
            .transpose()
    }

    /// Whether this failpoint fires at `boundary` in `phase`.
    #[must_use]
    pub fn fires(self, boundary: Boundary, phase: Phase) -> bool {
        self.boundary == boundary && self.phase == phase
    }
}

impl Failpoint for AbortAt {
    fn before_commit(&self, boundary: Boundary) -> Result<(), Crash> {
        if self.fires(boundary, Phase::BeforeCommit) {
            std::process::abort();
        }
        Ok(())
    }

    fn after_commit(&self, boundary: Boundary) -> Result<(), Crash> {
        if self.fires(boundary, Phase::AfterCommit) {
            std::process::abort();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
