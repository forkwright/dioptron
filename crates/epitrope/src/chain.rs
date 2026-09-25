//! Chain validity (contract § Expiry and validity, § Revocation epochs).

use snafu::{OptionExt as _, ResultExt as _, ensure};
use syntheke::{DenyCode, GrantId, Timestamp};

use crate::error::{ChainBrokenSnafu, ChainMalformedSnafu, Error, ViewSnafu};
use crate::grant::Grant;
use crate::view::GrantView;

/// The result of walking a grant chain at one instant.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainStatus {
    /// Every link is usable. The chain is leaf first and ends at the root.
    Valid(Vec<Grant>),
    /// A link is not usable.
    Invalid {
        /// Why the link is not usable.
        code: DenyCode,
        /// The first unusable link, walking from the leaf toward the root.
        failing_link: GrantId,
    },
}

/// Walks the chain from `leaf` to its root and checks every link at `now`.
///
/// A link is usable when it has no revocation record, `not_before <= now`,
/// and `now < expires_at`. Within one link, revocation is reported first,
/// then expiry, then not-yet-valid. A revoked ancestor fails every
/// descendant's walk, so revocation needs no write to the descendants.
///
/// WHY any revocation record counts regardless of its time: a record is
/// written when the revocation takes effect, and a record dated after `now`
/// can only come from clock skew; refusing is the closed side.
///
/// # Errors
///
/// [`Error::View`] when a read fails; [`Error::ChainBroken`] when a parent
/// is missing; [`Error::ChainMalformed`] when the view answers a parent
/// lookup with another grant, a link's depth is not its parent's plus one
/// or reaches its parent's maximum depth, a link raises its parent's
/// maximum depth, a root's depth is not zero, or a link's issuer is not its
/// parent's holder. The walk re-checks at every read what issue-time
/// narrowing already enforced, so a corrupt record fails closed. Depth
/// strictly decreases, so the walk ends within 256 links.
pub fn check_chain(
    view: &dyn GrantView,
    leaf: Grant,
    now: Timestamp,
) -> Result<ChainStatus, Error> {
    let chain = load_chain(view, leaf)?;
    for link in &chain {
        let revoked = view.revocation(link.id).context(ViewSnafu)?.is_some();
        let code = if revoked {
            Some(DenyCode::GrantRevoked)
        } else if now >= link.expires_at {
            Some(DenyCode::GrantExpired)
        } else if now < link.not_before {
            Some(DenyCode::GrantNotYetValid)
        } else {
            None
        };
        if let Some(code) = code {
            return Ok(ChainStatus::Invalid {
                code,
                failing_link: link.id,
            });
        }
    }
    Ok(ChainStatus::Valid(chain))
}

/// Loads every link from `leaf` to the root, checking structure only.
fn load_chain(view: &dyn GrantView, leaf: Grant) -> Result<Vec<Grant>, Error> {
    let mut chain = Vec::with_capacity(usize::from(leaf.depth).saturating_add(1));
    let mut current = leaf;
    while let Some(parent_id) = current.parent {
        let parent = view
            .grant(parent_id)
            .context(ViewSnafu)?
            .context(ChainBrokenSnafu { grant: parent_id })?;
        ensure!(
            parent.id == parent_id
                && parent.depth.checked_add(1) == Some(current.depth)
                && current.depth < parent.max_depth
                && current.max_depth <= parent.max_depth
                && current.issuer == parent.holder,
            ChainMalformedSnafu { grant: current.id }
        );
        chain.push(current);
        current = parent;
    }
    ensure!(
        current.depth == 0,
        ChainMalformedSnafu { grant: current.id }
    );
    chain.push(current);
    Ok(chain)
}

#[cfg(test)]
mod tests;
