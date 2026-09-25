//! Budget dimensions, ceilings, and declared costs (contract § Budgets).

use crate::names::named_enum;

named_enum! {
    /// One budget dimension. Each dimension is a separate ceiling; a ceiling
    /// on one never substitutes for another.
    ///
    /// Names are the snake-case field names used in the contract and the
    /// fixtures (`ceiling_<name>`).
    pub enum Dimension {
        /// Wall-clock time in milliseconds.
        WallTimeMs => "wall_time_ms",
        /// Number of producer fetches.
        Fetches => "fetches",
        /// Bytes the producer transferred.
        BytesTransferred => "bytes_transferred",
        /// Bytes of output returned to the caller.
        OutputBytes => "output_bytes",
        /// Reserved: token count. Units are not fixed in contract version 1.
        Tokens => "tokens",
        /// Reserved: operations-band cost. Units are not fixed in contract
        /// version 1.
        OpsBand => "ops_band",
    }
}

/// Per-dimension ceilings carried by one grant.
///
/// `None` means this grant sets no ceiling on that dimension; the effective
/// ceiling is the tightest one set anywhere along the grant chain, plus the
/// session and tenant ledgers.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Ceilings {
    /// Ceiling on [`Dimension::WallTimeMs`].
    pub wall_time_ms: Option<u64>,
    /// Ceiling on [`Dimension::Fetches`].
    pub fetches: Option<u64>,
    /// Ceiling on [`Dimension::BytesTransferred`].
    pub bytes_transferred: Option<u64>,
    /// Ceiling on [`Dimension::OutputBytes`].
    pub output_bytes: Option<u64>,
    /// Ceiling on [`Dimension::Tokens`] (reserved).
    pub tokens: Option<u64>,
    /// Ceiling on [`Dimension::OpsBand`] (reserved).
    pub ops_band: Option<u64>,
}

impl Ceilings {
    /// The ceiling this grant sets on `dimension`, if any.
    #[must_use]
    pub const fn get(&self, dimension: Dimension) -> Option<u64> {
        match dimension {
            Dimension::WallTimeMs => self.wall_time_ms,
            Dimension::Fetches => self.fetches,
            Dimension::BytesTransferred => self.bytes_transferred,
            Dimension::OutputBytes => self.output_bytes,
            Dimension::Tokens => self.tokens,
            Dimension::OpsBand => self.ops_band,
        }
    }
}

/// An amount on every dimension: a declared maximum at reservation, a plan's
/// cost estimate, or an actual consumption at settlement.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Cost {
    /// Amount on [`Dimension::WallTimeMs`].
    pub wall_time_ms: u64,
    /// Amount on [`Dimension::Fetches`].
    pub fetches: u64,
    /// Amount on [`Dimension::BytesTransferred`].
    pub bytes_transferred: u64,
    /// Amount on [`Dimension::OutputBytes`].
    pub output_bytes: u64,
    /// Amount on [`Dimension::Tokens`] (reserved).
    pub tokens: u64,
    /// Amount on [`Dimension::OpsBand`] (reserved).
    pub ops_band: u64,
}

impl Cost {
    /// The amount on `dimension`.
    #[must_use]
    pub const fn get(&self, dimension: Dimension) -> u64 {
        match dimension {
            Dimension::WallTimeMs => self.wall_time_ms,
            Dimension::Fetches => self.fetches,
            Dimension::BytesTransferred => self.bytes_transferred,
            Dimension::OutputBytes => self.output_bytes,
            Dimension::Tokens => self.tokens,
            Dimension::OpsBand => self.ops_band,
        }
    }
}

#[cfg(test)]
mod tests;
