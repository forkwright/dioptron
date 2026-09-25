//! Outcome and error taxonomy, and the invocation state vocabulary
//! (contract § Outcome and error taxonomy, § Invocation lifecycle).

use crate::budget::Dimension;
use crate::names::named_enum;

named_enum! {
    /// The policy reason carried by [`Failure::Denied`].
    ///
    /// Used only where the caller is already entitled to know the resource
    /// exists; anything else is [`Failure::NotFoundOrDenied`].
    pub enum DenyCode {
        /// The request's designated grant does not confer the requested
        /// capability.
        CapabilityNotGranted => "CapabilityNotGranted",
        /// The target is outside the grant's target scope.
        ScopeViolation => "ScopeViolation",
        /// A link in the grant chain is not yet valid (`now < not_before`).
        GrantNotYetValid => "GrantNotYetValid",
        /// A link in the grant chain has expired (`now >= expires_at`).
        GrantExpired => "GrantExpired",
        /// The grant or a link in its chain is revoked.
        GrantRevoked => "GrantRevoked",
        /// A requested child grant does not attenuate its parent on some
        /// axis ([`NarrowingAxis`]); the failure names the axis.
        NarrowingViolation => "NarrowingViolation",
        /// A budget ledger the caller does not own (an ancestor grant's, or
        /// a session another tenant owns) cannot cover the declared cost.
        /// The dimension is withheld; the caller's own ledgers report
        /// [`Failure::BudgetExceeded`] instead.
        BudgetUnavailable => "BudgetUnavailable",
        /// The capability requires a session and the call names none.
        SessionRequired => "SessionRequired",
        /// The capability is defined by the contract but this daemon does
        /// not serve it yet (version 1: `Ingest`, until the knowledge
        /// pipeline lands). Decided after the grant, chain, and capability
        /// checks, so it discloses nothing about the named resource.
        NotSupported => "NotSupported",
    }
}

named_enum! {
    /// The attenuation axis a narrowing check failed on (contract
    /// § Delegation attenuation). Names match the fixtures' `axis` field.
    pub enum NarrowingAxis {
        /// The child's capability set is not a subset of the parent's.
        Capabilities => "capabilities",
        /// The child's audit scope reads records the parent's does not.
        AuditScope => "audit_scope",
        /// The child's session scope is not a subset of the parent's.
        SessionScope => "session_scope",
        /// The child's target scope is not a subset of the parent's.
        TargetScope => "target_scope",
        /// A child ceiling exceeds the parent's remaining ceiling.
        Ceilings => "ceilings",
        /// The child expires after the parent.
        Expiry => "expiry",
        /// The child's depth reaches the chain's maximum depth.
        Depth => "depth",
        /// The designated parent grant does not confer `GrantIssue`.
        IssuerAuthority => "issuer_authority",
    }
}

named_enum! {
    /// Coarse class of a failed transfer.
    pub enum TransferClass {
        /// The connection was reset or closed early.
        Reset => "Reset",
        /// The transfer timed out at the producer.
        Timeout => "Timeout",
        /// The transfer exceeded its byte limit.
        TooLarge => "TooLarge",
        /// The origin answered with a non-success status.
        Status => "Status",
        /// A redirect was refused or the redirect limit was reached.
        Redirect => "Redirect",
        /// The TLS session failed.
        Tls => "Tls",
        /// The caller's egress policy refused the transfer.
        PolicyRefused => "PolicyRefused",
    }
}

named_enum! {
    /// Coarse class of a failed extraction.
    pub enum ExtractionClass {
        /// The transferred content could not be parsed.
        Malformed => "Malformed",
        /// The content type has no extractor.
        Unsupported => "Unsupported",
        /// The extracted output exceeded its limit.
        TooLarge => "TooLarge",
    }
}

/// A failure a caller observes, one variant per outcome kind the contract
/// names. Non-exhaustive: a later contract version may add kinds.
///
/// No variant carries a target, artifact reference, or URL, so a failure
/// never echoes anything the caller did not supply.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[non_exhaustive]
pub enum Failure {
    /// The frame or sequence violated the wire contract.
    ProtocolError,
    /// The handshake did not establish an admitted identity. One kind for
    /// every cause.
    AuthFailed,
    /// Authorization failed for a stated policy reason on a resource the
    /// caller may know exists.
    ///
    /// `axis` is set exactly when `code` is
    /// [`DenyCode::NarrowingViolation`], naming the first axis on which the
    /// requested child fails to attenuate the issuer's own designated
    /// grant. Any other combination is malformed
    /// ([`Failure::is_well_formed`]).
    Denied {
        /// The policy reason.
        code: DenyCode,
        /// The failing attenuation axis of a narrowing violation.
        axis: Option<NarrowingAxis>,
    },
    /// The resource is missing, or it exists and the caller may not see it.
    /// Byte-identical for both.
    NotFoundOrDenied,
    /// A ceiling on one of the caller's own ledgers was reached.
    BudgetExceeded {
        /// The exhausted dimension.
        dimension: Dimension,
    },
    /// The producer could not be contacted.
    ProducerUnavailable,
    /// The producer began and the transfer failed.
    TransferFailed {
        /// Coarse failure class.
        class: TransferClass,
    },
    /// The transfer completed and extraction failed.
    ExtractionFailed {
        /// Coarse failure class.
        class: ExtractionClass,
    },
    /// The deadline elapsed before completion.
    DeadlineExceeded,
    /// The call was cancelled.
    Cancelled,
    /// An effect may have occurred exactly once and cannot be proven.
    UnknownEffect,
    /// The idempotency key is bound to a different request.
    IdempotencyConflict,
}

impl Failure {
    /// A denial for `code` with no axis. A narrowing violation is built
    /// with [`Failure::narrowing`], which names the axis.
    #[must_use]
    pub const fn denied(code: DenyCode) -> Self {
        Self::Denied { code, axis: None }
    }

    /// A narrowing-violation denial naming the failing `axis`.
    #[must_use]
    pub const fn narrowing(axis: NarrowingAxis) -> Self {
        Self::Denied {
            code: DenyCode::NarrowingViolation,
            axis: Some(axis),
        }
    }

    /// Whether a `Denied` failure carries an axis exactly when its code is
    /// [`DenyCode::NarrowingViolation`]. Every other failure is well formed.
    #[must_use]
    pub const fn is_well_formed(self) -> bool {
        match self {
            Self::Denied { code, axis } => {
                matches!(code, DenyCode::NarrowingViolation) == axis.is_some()
            }
            _ => true,
        }
    }

    /// The outcome kind of this failure.
    #[must_use]
    pub const fn kind(self) -> OutcomeKind {
        match self {
            Self::ProtocolError => OutcomeKind::ProtocolError,
            Self::AuthFailed => OutcomeKind::AuthFailed,
            Self::Denied { .. } => OutcomeKind::Denied,
            Self::NotFoundOrDenied => OutcomeKind::NotFoundOrDenied,
            Self::BudgetExceeded { .. } => OutcomeKind::BudgetExceeded,
            Self::ProducerUnavailable => OutcomeKind::ProducerUnavailable,
            Self::TransferFailed { .. } => OutcomeKind::TransferFailed,
            Self::ExtractionFailed { .. } => OutcomeKind::ExtractionFailed,
            Self::DeadlineExceeded => OutcomeKind::DeadlineExceeded,
            Self::Cancelled => OutcomeKind::Cancelled,
            Self::UnknownEffect => OutcomeKind::UnknownEffect,
            Self::IdempotencyConflict => OutcomeKind::IdempotencyConflict,
        }
    }
}

named_enum! {
    /// The kind of a reply, without its payload: the three non-failure
    /// replies plus one kind per [`Failure`] variant. Audit records carry
    /// this kind.
    pub enum OutcomeKind {
        /// The call completed.
        Success => "Success",
        /// A dry-run returned its plan.
        Plan => "Plan",
        /// An idempotent replay found the original call still running.
        InProgress => "InProgress",
        /// See [`Failure::ProtocolError`].
        ProtocolError => "ProtocolError",
        /// See [`Failure::AuthFailed`].
        AuthFailed => "AuthFailed",
        /// See [`Failure::Denied`].
        Denied => "Denied",
        /// See [`Failure::NotFoundOrDenied`].
        NotFoundOrDenied => "NotFoundOrDenied",
        /// See [`Failure::BudgetExceeded`].
        BudgetExceeded => "BudgetExceeded",
        /// See [`Failure::ProducerUnavailable`].
        ProducerUnavailable => "ProducerUnavailable",
        /// See [`Failure::TransferFailed`].
        TransferFailed => "TransferFailed",
        /// See [`Failure::ExtractionFailed`].
        ExtractionFailed => "ExtractionFailed",
        /// See [`Failure::DeadlineExceeded`].
        DeadlineExceeded => "DeadlineExceeded",
        /// See [`Failure::Cancelled`].
        Cancelled => "Cancelled",
        /// See [`Failure::UnknownEffect`].
        UnknownEffect => "UnknownEffect",
        /// See [`Failure::IdempotencyConflict`].
        IdempotencyConflict => "IdempotencyConflict",
    }
}

named_enum! {
    /// The state of an invocation (contract § Invocation lifecycle).
    ///
    /// The transition rules live in the authorization crate; this is the
    /// shared vocabulary.
    pub enum InvocationState {
        /// In memory: authorized and costed. A dry-run ends here.
        Planned => "Planned",
        /// Durable, terminal: authorization failed; audit is the only write.
        Denied => "Denied",
        /// B1: reservation, intent, and idempotency index committed.
        IntentPersisted => "IntentPersisted",
        /// B2: dispatch recorded before the producer call.
        Dispatched => "Dispatched",
        /// B3: the producer returned; the blob is written, not yet visible.
        TransferComplete => "TransferComplete",
        /// B4: the atomic publish point; the capture is visible.
        Published => "Published",
        /// B5, terminal: actual cost settled, remainder released.
        Settled => "Settled",
        /// B5, terminal: the whole reservation released with a reason.
        Released => "Released",
        /// B5, terminal: an effect may have happened once; charged at the
        /// reserved cost and never re-dispatched.
        UnknownEffect => "UnknownEffect",
    }
}

impl InvocationState {
    /// Whether no further transition leaves this state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Settled | Self::Released | Self::UnknownEffect
        )
    }

    /// Whether this state is persisted in the store.
    #[must_use]
    pub const fn is_durable(self) -> bool {
        !matches!(self, Self::Planned)
    }
}

named_enum! {
    /// Why an invocation released its whole reservation.
    pub enum ReleaseReason {
        /// A crash left the call at B1; the producer was never called.
        Abandoned => "Abandoned",
        /// The authorizing grant was revoked before any effect.
        Revoked => "Revoked",
        /// The producer could not be contacted.
        ProducerUnavailable => "ProducerUnavailable",
        /// The call was cancelled before any effect.
        Cancelled => "Cancelled",
        /// The deadline elapsed before any effect.
        DeadlineExceeded => "DeadlineExceeded",
        /// A link of the authorizing chain expired before any effect.
        Expired => "Expired",
    }
}

#[cfg(test)]
mod tests;
