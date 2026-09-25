//! Mapping fixture tables onto `syntheke` request and reply types.

use syntheke::{
    ArtifactRef, AuditPage, AuditQueryRequest, AuditScope, AuditSeq, Capability, CaptureLimits,
    CaptureOutcome, CaptureRequest, Ceilings, Cost, DenyCode, Dimension, ExtractionClass, Failure,
    GrantId, GrantIssueRequest, GrantIssued, GrantRevokeRequest, GrantRevoked, OutcomeKind, Plan,
    QueryPage, QueryRequest, ReadChunk, ReadRequest, RequestBody, ResponseBody, SessionForkRequest,
    SessionOpened, SessionScope, SourceRef, Timestamp, TransferClass,
};
use toml::Table;

use crate::load::{
    TestResult, flag, id, int, named, need_id, need_text, parse_id, rfc3339, strings, text,
};

/// Session used when a capture fixture omits `session`: the cast's
/// session `ses0a`, owned by agent `tnt0b`.
pub(crate) const CAST_SESSION: &str = "01j8k7r3v9zq4n5m6p7s8ses0a";

fn capture_body(req: &Table, name: &str) -> TestResult<RequestBody> {
    let session = match id(req, "session", name)? {
        Some(session) => session,
        None => CAST_SESSION.parse()?,
    };
    Ok(RequestBody::Capture(CaptureRequest {
        session,
        target: need_text(req, "target", name)?.to_owned(),
        limits: CaptureLimits {
            max_output_bytes: int(req, "max_output_bytes", name)?,
            max_transfer_bytes: int(req, "max_transfer_bytes", name)?,
        },
        egress_policy: None,
    }))
}

fn grant_issue_body(req: &Table, name: &str) -> TestResult<RequestBody> {
    let capabilities = strings(req, "capabilities", name)?
        .into_iter()
        .map(|c| named(c, Capability::from_name, "capability", name))
        .collect::<TestResult<Vec<_>>>()?;
    let mut ceilings = Ceilings::default();
    for (key, value) in req {
        let Some(dimension) = key.strip_prefix("ceiling_") else {
            continue;
        };
        let dimension = named(dimension, Dimension::from_name, "dimension", name)?;
        let amount = value
            .as_integer()
            .and_then(|v| u64::try_from(v).ok())
            .ok_or_else(|| format!("{name}: `{key}` is not a count"))?;
        match dimension {
            Dimension::WallTimeMs => ceilings.wall_time_ms = Some(amount),
            Dimension::Fetches => ceilings.fetches = Some(amount),
            Dimension::BytesTransferred => ceilings.bytes_transferred = Some(amount),
            Dimension::OutputBytes => ceilings.output_bytes = Some(amount),
            Dimension::Tokens => ceilings.tokens = Some(amount),
            Dimension::OpsBand => ceilings.ops_band = Some(amount),
            _ => return Err(format!("{name}: unmapped dimension {dimension}").into()),
        }
        assert_eq!(ceilings.get(dimension), Some(amount), "{name}: {key} maps");
    }
    let expires_at = match text(req, "expires_at") {
        Some(value) => rfc3339(value, name)?,
        None => Timestamp::from_unix_millis(i64::MAX),
    };
    Ok(RequestBody::GrantIssue(GrantIssueRequest {
        holder: need_id(req, "holder", name)?,
        capabilities,
        session_scope: SessionScope::Own,
        target_scope: strings(req, "target_scope", name)?
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ceilings,
        not_before: Timestamp::from_unix_millis(0),
        expires_at,
        max_depth: None,
    }))
}

/// Maps a capability fixture's wire fields into a request body.
pub(crate) fn request_body(
    capability: Capability,
    req: &Table,
    name: &str,
) -> TestResult<RequestBody> {
    Ok(match capability {
        Capability::SessionCreate => RequestBody::SessionCreate,
        Capability::SessionFork => RequestBody::SessionFork(SessionForkRequest {
            parent_session: need_id(req, "parent_session", name)?,
        }),
        Capability::Capture => capture_body(req, name)?,
        Capability::Read => RequestBody::Read(ReadRequest {
            artifact_ref: need_id(req, "artifact_ref", name)?,
            offset: int(req, "offset", name)?.unwrap_or(0),
            len: int(req, "len", name)?.unwrap_or(4096),
        }),
        Capability::Query => RequestBody::Query(QueryRequest {
            session_scope: id(req, "session_scope", name)?,
            predicate: need_text(req, "predicate", name)?.to_owned(),
            limit: 100,
        }),
        Capability::GrantIssue => grant_issue_body(req, name)?,
        Capability::GrantRevoke => RequestBody::GrantRevoke(GrantRevokeRequest {
            target_grant: need_id(req, "target_grant", name)?,
        }),
        Capability::AuditQuery => RequestBody::AuditQuery(AuditQueryRequest {
            audit_scope: named(
                need_text(req, "audit_scope", name)?,
                AuditScope::from_name,
                "audit scope",
                name,
            )?,
            session: None,
            after: None,
            limit: 100,
        }),
        _ => return Err(format!("{name}: no fixture mapping for {capability}").into()),
    })
}

/// Maps a negative fixture's outcome and its `code` or `class` to a failure.
pub(crate) fn failure(outcome: OutcomeKind, exp: &Table, name: &str) -> TestResult<Failure> {
    let code = || need_text(exp, "code", name);
    let class = || need_text(exp, "class", name);
    Ok(match outcome {
        OutcomeKind::ProtocolError => Failure::ProtocolError,
        OutcomeKind::AuthFailed => Failure::AuthFailed,
        OutcomeKind::Denied => Failure::Denied {
            code: named(code()?, DenyCode::from_name, "deny code", name)?,
        },
        OutcomeKind::NotFoundOrDenied => Failure::NotFoundOrDenied,
        OutcomeKind::ProducerUnavailable => Failure::ProducerUnavailable,
        OutcomeKind::TransferFailed => Failure::TransferFailed {
            class: named(class()?, TransferClass::from_name, "transfer class", name)?,
        },
        OutcomeKind::ExtractionFailed => Failure::ExtractionFailed {
            class: named(
                class()?,
                ExtractionClass::from_name,
                "extraction class",
                name,
            )?,
        },
        OutcomeKind::DeadlineExceeded => Failure::DeadlineExceeded,
        OutcomeKind::Cancelled => Failure::Cancelled,
        OutcomeKind::UnknownEffect => Failure::UnknownEffect,
        OutcomeKind::IdempotencyConflict => Failure::IdempotencyConflict,
        _ => return Err(format!("{name}: {outcome} is not a failure").into()),
    })
}

fn captured(exp: &Table, name: &str) -> TestResult<ResponseBody> {
    let text_view = text(exp, "text_view").map(str::to_owned);
    let output_bytes = match int(exp, "output_bytes", name)? {
        Some(bytes) => bytes,
        None => u64::try_from(text_view.as_ref().map_or(0, String::len))?,
    };
    Ok(ResponseBody::Captured(CaptureOutcome {
        artifact_ref: need_id(exp, "artifact_ref", name)?,
        source: SourceRef {
            fingerprint: text(exp, "source_fingerprint")
                .unwrap_or_default()
                .to_owned(),
            schema_id: need_text(exp, "source_schema_id", name)?.to_owned(),
            producer_revision: text(exp, "producer_revision")
                .unwrap_or_default()
                .to_owned(),
        },
        text_view,
        truncated: flag(exp, "truncated").ok_or("capture reply needs `truncated`")?,
        output_bytes,
        revoked_after_effect: false,
    }))
}

/// Maps a positive fixture's reply fields into the capability's reply.
pub(crate) fn success(capability: Capability, exp: &Table, name: &str) -> TestResult<ResponseBody> {
    Ok(match capability {
        Capability::SessionCreate | Capability::SessionFork => {
            ResponseBody::SessionOpened(SessionOpened {
                session: need_id(exp, "session", name)?,
                owner: need_id(exp, "owner", name)?,
                parent_session: id(exp, "parent_session", name)?,
            })
        }
        Capability::Capture => captured(exp, name)?,
        Capability::Read => {
            let len: usize = int(exp, "len", name)?.ok_or("read reply needs `len`")?;
            ResponseBody::Chunk(ReadChunk {
                offset: int(exp, "offset", name)?.ok_or("read reply needs `offset`")?,
                bytes: vec![0; len],
                total_len: u64::try_from(len)?,
            })
        }
        Capability::Query => ResponseBody::QueryPage(QueryPage {
            result_refs: strings(exp, "result_refs", name)?
                .into_iter()
                .map(|v| parse_id::<ArtifactRef>(v, "result_refs", name))
                .collect::<TestResult<_>>()?,
            more: false,
        }),
        Capability::GrantIssue => ResponseBody::GrantIssued(GrantIssued {
            grant: need_id(exp, "grant", name)?,
            parent_grant: need_id(exp, "parent_grant", name)?,
        }),
        Capability::GrantRevoke => ResponseBody::GrantRevoked(GrantRevoked {
            revoked_grant: need_id(exp, "revoked_grant", name)?,
            effect_sequence: AuditSeq::new(
                int(exp, "effect_sequence", name)?.ok_or("revoke needs `effect_sequence`")?,
            ),
            effect_time: Timestamp::from_unix_millis(0),
        }),
        Capability::AuditQuery => ResponseBody::AuditPage(AuditPage {
            scope_applied: named(
                need_text(exp, "scope_applied", name)?,
                AuditScope::from_name,
                "audit scope",
                name,
            )?,
            records: Vec::new(),
            next_after: None,
        }),
        _ => return Err(format!("{name}: no reply mapping for {capability}").into()),
    })
}

/// Maps a dry-run fixture's reply fields into a plan.
pub(crate) fn plan(capability: Capability, exp: &Table, name: &str) -> TestResult<ResponseBody> {
    Ok(ResponseBody::Plan(Plan {
        capability,
        cost: Cost {
            fetches: int(exp, "plan_cost_fetches", name)?.ok_or("plan needs a cost")?,
            ..Cost::default()
        },
        grant_chain: strings(exp, "plan_grant_chain", name)?
            .into_iter()
            .map(|v| parse_id::<GrantId>(v, "plan_grant_chain", name))
            .collect::<TestResult<_>>()?,
        rule_chain: Vec::new(),
        refusal: None,
    }))
}
