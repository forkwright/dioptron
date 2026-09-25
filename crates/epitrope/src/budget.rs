//! Budget reservation and settlement arithmetic (contract § Budgets).
//!
//! Each dimension is a separate ceiling. A reservation debits the declared
//! maximum on every dimension against every ledger the call touches; a
//! settlement debits the actual consumption, at most the reservation, and
//! releases the rest. All arithmetic is checked.

use snafu::OptionExt as _;
use syntheke::{Ceilings, Cost, DenyCode, Dimension, Failure};

use crate::error::{Error, LedgerOverflowSnafu, LedgerUnderflowSnafu, SettleOverrunSnafu};
use crate::view::LedgerId;

/// One ledger as the planner sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerState {
    /// The ledger.
    pub id: LedgerId,
    /// Its ceilings; `None` on a dimension sets no ceiling there.
    pub ceilings: Ceilings,
    /// Settled consumption plus unsettled reservations.
    pub used: Cost,
    /// Whether the ledger is the caller's own: its tenant ledger, a grant
    /// it holds, or a session it owns. Only an own ledger's dimension is
    /// ever reported to the caller.
    pub own: bool,
}

/// A reservation that fits: debit `cost` from every ledger in `ledgers`,
/// in one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationPlan {
    cost: Cost,
    ledgers: Vec<LedgerId>,
}

impl ReservationPlan {
    /// The declared maximum debited from each ledger.
    #[must_use]
    pub const fn cost(&self) -> Cost {
        self.cost
    }

    /// The ledgers to debit, in the order given to [`plan_reservation`].
    #[must_use]
    pub fn ledgers(&self) -> &[LedgerId] {
        &self.ledgers
    }

    /// Each ledger with the amount to debit from it.
    pub fn debits(&self) -> impl Iterator<Item = (LedgerId, Cost)> + '_ {
        self.ledgers.iter().map(|&ledger| (ledger, self.cost))
    }
}

/// Why a reservation does not fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BudgetRefusal {
    /// One of the caller's own ledgers cannot cover `dimension`.
    Own {
        /// The exhausted ledger.
        ledger: LedgerId,
        /// The exhausted dimension.
        dimension: Dimension,
    },
    /// A ledger the caller does not own (an ancestor grant's, or a session
    /// another tenant owns) cannot cover the reservation. Which dimension is
    /// withheld.
    Upstream,
}

impl BudgetRefusal {
    /// The failure the caller observes.
    ///
    /// WHY `Denied{BudgetUnavailable}` for an upstream ledger: the contract
    /// lets `BudgetExceeded` name a dimension only on the caller's own
    /// ledgers, so exhaustion anywhere else is a denial with no dimension.
    #[must_use]
    pub const fn failure(self) -> Failure {
        match self {
            Self::Own { dimension, .. } => Failure::BudgetExceeded { dimension },
            Self::Upstream => Failure::denied(DenyCode::BudgetUnavailable),
        }
    }
}

/// The result of [`plan_reservation`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BudgetCheck {
    /// Every ledger covers the declared maximum.
    Fits(ReservationPlan),
    /// Some ledger does not.
    Exceeded(BudgetRefusal),
}

/// Checks that every ledger covers `declared` on every dimension.
///
/// A ledger covers a dimension when it sets no ceiling there, or when
/// `used + declared <= ceiling`. When several ledgers fall short, an own
/// ledger is reported before an upstream one, and within each group the
/// first ledger in `ledgers` order and the first dimension in
/// [`Dimension::ALL`] order win.
///
/// # Errors
///
/// [`Error::LedgerOverflow`] when a ledger with no ceiling on a dimension
/// would pass `u64::MAX` there. A capped ledger that would overflow simply
/// does not cover the reservation.
pub fn plan_reservation(ledgers: &[LedgerState], declared: &Cost) -> Result<BudgetCheck, Error> {
    let mut own_refusal = None;
    let mut upstream = false;
    for ledger in ledgers {
        for &dimension in Dimension::ALL {
            let total = ledger
                .used
                .get(dimension)
                .checked_add(declared.get(dimension));
            let covers = match (ledger.ceilings.get(dimension), total) {
                (None, Some(_)) => true,
                (None, None) => return LedgerOverflowSnafu { dimension }.fail(),
                (Some(ceiling), Some(total)) => total <= ceiling,
                (Some(_), None) => false,
            };
            if covers {
                continue;
            }
            if ledger.own {
                own_refusal.get_or_insert(BudgetRefusal::Own {
                    ledger: ledger.id,
                    dimension,
                });
            } else {
                upstream = true;
            }
        }
    }
    Ok(match (own_refusal, upstream) {
        (Some(refusal), _) => BudgetCheck::Exceeded(refusal),
        (None, true) => BudgetCheck::Exceeded(BudgetRefusal::Upstream),
        (None, false) => BudgetCheck::Fits(ReservationPlan {
            cost: *declared,
            ledgers: ledgers.iter().map(|ledger| ledger.id).collect(),
        }),
    })
}

/// How a settled reservation moves every ledger it debited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settlement {
    /// The consumption kept as spent: the actual amount, at most the
    /// reservation.
    pub debit: Cost,
    /// The amount returned to each ledger: reservation minus `debit`.
    pub release: Cost,
}

/// Settles `reserved` against the `actual` consumption.
///
/// # Errors
///
/// [`Error::SettleOverrun`] when `actual` exceeds `reserved` on some
/// dimension. The error carries the clamped settlement (debit the whole
/// reservation on the overrun dimensions, release nothing there), which
/// the caller applies while recording the overrun.
pub fn settle(reserved: &Cost, actual: &Cost) -> Result<Settlement, Error> {
    let debit = cost_from(|d| reserved.get(d).min(actual.get(d)));
    let release = cost_from(|d| reserved.get(d).saturating_sub(debit.get(d)));
    let settlement = Settlement { debit, release };
    match Dimension::ALL
        .iter()
        .copied()
        .find(|&d| actual.get(d) > reserved.get(d))
    {
        Some(dimension) => SettleOverrunSnafu {
            dimension,
            reserved: reserved.get(dimension),
            actual: actual.get(dimension),
            settlement,
        }
        .fail(),
        None => Ok(settlement),
    }
}

/// The settlement of an `UnknownEffect` terminal: the effect cannot be
/// proven either way, so the whole reservation is charged and nothing is
/// released.
#[must_use]
pub const fn unknown_effect_settlement(reserved: &Cost) -> Settlement {
    Settlement {
        debit: *reserved,
        release: Cost {
            wall_time_ms: 0,
            fetches: 0,
            bytes_transferred: 0,
            output_bytes: 0,
            tokens: 0,
            ops_band: 0,
        },
    }
}

/// A ledger's `used` after reserving `amount`.
///
/// # Errors
///
/// [`Error::LedgerOverflow`] when a dimension would pass `u64::MAX`.
pub fn reserve(used: &Cost, amount: &Cost) -> Result<Cost, Error> {
    try_cost_from(|dimension| {
        used.get(dimension)
            .checked_add(amount.get(dimension))
            .context(LedgerOverflowSnafu { dimension })
    })
}

/// A ledger's `used` after releasing `amount`.
///
/// # Errors
///
/// [`Error::LedgerUnderflow`] when a dimension would go below zero.
pub fn release(used: &Cost, amount: &Cost) -> Result<Cost, Error> {
    try_cost_from(|dimension| {
        used.get(dimension)
            .checked_sub(amount.get(dimension))
            .context(LedgerUnderflowSnafu { dimension })
    })
}

/// Builds a cost from one amount per dimension.
fn cost_from(mut amount: impl FnMut(Dimension) -> u64) -> Cost {
    Cost {
        wall_time_ms: amount(Dimension::WallTimeMs),
        fetches: amount(Dimension::Fetches),
        bytes_transferred: amount(Dimension::BytesTransferred),
        output_bytes: amount(Dimension::OutputBytes),
        tokens: amount(Dimension::Tokens),
        ops_band: amount(Dimension::OpsBand),
    }
}

/// Builds a cost from one fallible amount per dimension.
fn try_cost_from(mut amount: impl FnMut(Dimension) -> Result<u64, Error>) -> Result<Cost, Error> {
    Ok(Cost {
        wall_time_ms: amount(Dimension::WallTimeMs)?,
        fetches: amount(Dimension::Fetches)?,
        bytes_transferred: amount(Dimension::BytesTransferred)?,
        output_bytes: amount(Dimension::OutputBytes)?,
        tokens: amount(Dimension::Tokens)?,
        ops_band: amount(Dimension::OpsBand)?,
    })
}

#[cfg(test)]
mod tests;
