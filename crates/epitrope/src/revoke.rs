//! Revocation authorization (contract § Revocation authority).

use snafu::ResultExt as _;
use syntheke::{Capability, DenyCode, Failure, GrantId, TenantId};

use crate::clock::Clock;
use crate::decision::{Decision, designated_chain};
use crate::error::{Error, ViewSnafu};
use crate::grant::Revocation;
use crate::view::{GrantView, Snapshot};

/// The most grants the subtree walk visits. A chain holds at most 256
/// grants (depths 0 through 255), so a longer walk only follows a cycle.
const SUBTREE_WALK_LIMIT: usize = 256;

/// The result of [`check_revoke`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevokeDecision {
    /// Write a revocation record for the target.
    Revoke {
        /// The grant to revoke.
        target: GrantId,
    },
    /// The target is already revoked. The call succeeds and writes no new
    /// record; the reply carries this one.
    AlreadyRevoked {
        /// The existing revocation record.
        record: Revocation,
    },
    /// The designated grant cannot authorize the revocation.
    Denied {
        /// Why.
        code: DenyCode,
    },
    /// The designated grant is missing or not held by the caller, or the
    /// target is missing or outside the designated grant's subtree.
    /// Identical for every case.
    NotFoundOrDenied,
}

impl RevokeDecision {
    /// The failure the caller observes, or `None` when the call succeeds.
    #[must_use]
    pub const fn refusal(&self) -> Option<Failure> {
        match self {
            Self::Revoke { .. } | Self::AlreadyRevoked { .. } => None,
            Self::Denied { code } => Some(Failure::denied(*code)),
            Self::NotFoundOrDenied => Some(Failure::NotFoundOrDenied),
        }
    }
}

/// Decides whether `tenant`, acting under `designated`, may revoke
/// `target` at `clock.now()`.
///
/// Checks run in this order, and the first refusal wins:
///
/// 1. `designated` exists, `tenant` holds it, its whole chain is usable,
///    and every link confers `GrantRevoke`, exactly as [`crate::authorize`]
///    checks them.
/// 2. `target` is `designated` or descends from it through parent links.
///    A missing target and one outside the subtree (an ancestor, a sibling,
///    another tenant's grant) are [`RevokeDecision::NotFoundOrDenied`]
///    through one path.
/// 3. A target that already has a revocation record is
///    [`RevokeDecision::AlreadyRevoked`], so a repeated revocation writes
///    nothing new.
///
/// # Errors
///
/// [`Error::View`], [`Error::ChainBroken`], or [`Error::ChainMalformed`]
/// from the designated grant's chain; the caller fails closed. A broken or
/// cyclic parent link above the target ends the subtree walk as outside
/// the subtree, so a foreign grant's records cannot change the reply.
pub fn check_revoke(
    view: &dyn Snapshot,
    tenant: TenantId,
    designated: GrantId,
    target: GrantId,
    clock: &dyn Clock,
) -> Result<RevokeDecision, Error> {
    match designated_chain(view, tenant, designated, Capability::GrantRevoke, clock)? {
        Ok(_) => {}
        Err(Decision::Denied { code }) => return Ok(RevokeDecision::Denied { code }),
        Err(_) => return Ok(RevokeDecision::NotFoundOrDenied),
    }
    if !in_subtree(view, designated, target)? {
        return Ok(RevokeDecision::NotFoundOrDenied);
    }
    Ok(match view.revocation(target).context(ViewSnafu)? {
        Some(record) => RevokeDecision::AlreadyRevoked { record },
        None => RevokeDecision::Revoke { target },
    })
}

/// Whether `target` is `root` or reaches it through parent links within
/// [`SUBTREE_WALK_LIMIT`] grants. A missing grant, a view answer for a
/// different id, a root reached first, or the limit ends the walk outside.
fn in_subtree(view: &dyn GrantView, root: GrantId, target: GrantId) -> Result<bool, Error> {
    let mut current = target;
    for _ in 0..SUBTREE_WALK_LIMIT {
        if current == root {
            return Ok(true);
        }
        match view.grant(current).context(ViewSnafu)? {
            Some(grant) if grant.id == current => match grant.parent {
                Some(parent) => current = parent,
                None => return Ok(false),
            },
            _ => return Ok(false),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests;
