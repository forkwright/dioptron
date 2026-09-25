//! Authorization decisions for Dioptron tenants.
//!
//! `epitrope` decides, over the types of the capability contract
//! (`syntheke`), whether a call may run and what it costs:
//!
//! - grant narrowing on every axis ([`check_issue`], [`narrowing_violation`]):
//!   capabilities, session and target scopes, ceilings against the parent's
//!   remaining budget, validity window, and delegation depth;
//! - chain validity at an injected [`Clock`]'s instant against revocation
//!   records, with no fan-out on revocation ([`check_chain`]);
//! - designated-grant authorization ([`authorize`]), where a grant the
//!   caller does not hold reads exactly as a missing one;
//! - budget reservation and settlement arithmetic ([`plan_reservation`],
//!   [`settle`]);
//! - the invocation transition table and restart recovery ([`next_state`],
//!   [`recovery_action`]);
//! - a dry-run planner over a read-only [`Snapshot`] ([`plan`]);
//! - the audit scope defaults of D17.7 and the rule evaluator's
//!   [`RuleView`], which has no audit access.
//!
//! It performs no IO, starts no runtime, and reads time only through the
//! injected clock. Every read goes through the [`GrantView`] and
//! [`LedgerView`] traits, which have no write methods.
#![deny(missing_docs)]

mod audit;
mod budget;
mod chain;
mod clock;
mod decision;
mod error;
mod grant;
mod lifecycle;
mod origin;
mod view;

#[cfg(test)]
mod test_support;

pub use audit::{RuleView, applied_audit_scope, audit_scope_within, default_audit_scope};
pub use budget::{
    BudgetCheck, BudgetRefusal, LedgerState, ReservationPlan, Settlement, plan_reservation,
    release, reserve, settle, unknown_effect_settlement,
};
pub use chain::{ChainStatus, check_chain};
pub use clock::{Clock, FixedClock};
pub use decision::{AuthzRequest, Decision, authorize, plan};
pub use error::Error;
pub use grant::{
    Grant, IssueContext, IssueDecision, MAX_TENANT_LINEAGE, Revocation, check_issue, in_lineage,
    narrowing_violation,
};
pub use lifecycle::{RecoveryAction, Step, next_state, recovery_action};
pub use origin::{Origin, OriginPattern, Scheme, TargetScope};
pub use view::{GrantView, LedgerId, LedgerView, Snapshot, ViewError};
