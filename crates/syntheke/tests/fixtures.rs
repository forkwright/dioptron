//! Conformance of the contract fixtures under `docs/contract/fixtures/`.
//!
//! Every fixture's wire fields are mapped into `syntheke` request and reply
//! types and carried through a full encode and validating decode; every name
//! a fixture uses (capability, mode, outcome kind, deny code, class, state,
//! reason, axis, scope, frame kind) must parse as the contract type it names.
//! A missing fixture directory or a missing declared fixture fails the test.

// NOTE: clippy's tests_outside_test_module (denied workspace-wide) also
// applies to integration test crates, hence the module wrapper.
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::str::FromStr;

    use syntheke::{
        ArtifactRef, AuditPage, AuditQueryRequest, AuditScope, AuditSeq, Capability, CaptureLimits,
        CaptureOutcome, CaptureRequest, Ceilings, ClientHello, Cost, DEFAULT_MAX_BODY, DenyCode,
        Dimension, Error, ExtractionClass, Failure, Fault, FrameHeader, FrameKind, GrantId,
        GrantIssueRequest, GrantIssued, GrantRevokeRequest, GrantRevoked, HEADER_LEN,
        IdempotencyKey, InvocationState, Mode, NONCE_LEN, NarrowingAxis, Nonce, OutcomeKind,
        PRE_AUTH_MAX_BODY, Plan, QueryPage, QueryRequest, ReadChunk, ReadRequest, ReleaseReason,
        Request, RequestBody, Response, ResponseBody, SessionForkRequest, SessionId, SessionOpened,
        SessionScope, SourceRef, TenantId, Timestamp, TransferClass, VersionChoice, WIRE_VERSION,
        decode, decode_frame, encode, encode_frame, negotiate_version,
    };
    use toml::{Table, Value};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/contract/fixtures");

    /// Every scenario the contract declares. A missing file fails the test;
    /// an undeclared file fails it too, so a new fixture gets a mapping.
    const DECLARED: [&str; 21] = [
        "audit_query_own",
        "capture_success",
        "capture_truncated",
        "dry_run",
        "grant_issue_valid",
        "grant_revoke",
        "neg_cross_tenant_read",
        "neg_expired_grant",
        "neg_extraction_failed",
        "neg_forged_identity",
        "neg_idempotency_conflict",
        "neg_incompatible_version",
        "neg_narrowing_violation",
        "neg_oversized_frame",
        "neg_producer_unavailable",
        "neg_revoked_parent",
        "neg_transfer_failed",
        "query_success",
        "read_success",
        "session_create",
        "session_fork",
    ];

    /// Contract § Fixture keys: `[request]` wire fields (through `tenant`),
    /// then scenario setup keys.
    const REQUEST_KEYS: &str = "\
        capability mode idempotency_key session target max_output_bytes \
        max_transfer_bytes artifact_ref offset len predicate session_scope \
        parent_session parent_grant holder capabilities target_scope expires_at \
        target_grant audit_scope frame version_min version_max client_nonce \
        signature tenant \
        grant clock_now grant_expires_at parent_capabilities \
        parent_revoked_at_sequence prior_request_digest producer_fault peer_uid \
        bound_uids cause declared_len pre_auth negotiated_max";

    /// Contract § Fixture keys: `[expected]` reply fields (through
    /// `plan_grant_chain`), then observation keys.
    const EXPECTED_KEYS: &str = "\
        outcome code class axis artifact_ref source_fingerprint source_schema_id \
        producer_revision text_view truncated output_bytes session owner \
        parent_session grant parent_grant revoked_grant effect_sequence offset \
        len result_refs scope_applied plan_cost_fetches plan_grant_chain \
        final_state released_reason producer_calls durable_writes dispatched \
        narrowed descendants_invalidated failing_link indistinguishable \
        echoes_ref authenticated allocated connection envelope_verbatim \
        scoped_to_caller records_outside_scope read_audited";

    /// Keys whose values are identifiers (a ULID or an array of ULIDs).
    const ID_KEYS: &str = "\
        tenant session grant parent_grant holder artifact_ref parent_session \
        session_scope target_grant owner revoked_grant failing_link result_refs \
        plan_grant_chain";

    /// The five authentication failure causes the contract names.
    const AUTH_CAUSES: &[&str] = &[
        "wrong_key",
        "replayed_signature",
        "uid_not_bound",
        "pre_auth_request",
        "unknown_tenant",
    ];

    /// Session used when a capture fixture omits `session`: the cast's
    /// session `ses0a`, owned by agent `tnt0b`.
    const CAST_SESSION: &str = "01j8k7r3v9zq4n5m6p7s8ses0a";

    /// Whether the whitespace-separated `list` holds `word` exactly.
    fn has_word(list: &str, word: &str) -> bool {
        list.split_whitespace().any(|item| item == word)
    }

    struct Fixture {
        name: String,
        meta: Table,
        request: Table,
        expected: Table,
    }

    fn table(root: &Table, key: &str, name: &str) -> TestResult<Table> {
        match root.get(key) {
            Some(Value::Table(inner)) => Ok(inner.clone()),
            _ => Err(format!("{name}: missing [{key}] table").into()),
        }
    }

    fn load() -> TestResult<Vec<Fixture>> {
        let dir = Path::new(FIXTURE_DIR);
        let entries = std::fs::read_dir(dir).map_err(|err| {
            format!(
                "contract fixtures missing at {}: {err}; they land with the \
                 capability contract (docs/contract/fixtures)",
                dir.display()
            )
        })?;
        let mut fixtures = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or("fixture file name is not UTF-8")?
                .to_owned();
            let root: Table = std::fs::read_to_string(&path)?.parse()?;
            let extra: Vec<&String> = root
                .keys()
                .filter(|key| !["meta", "request", "expected"].contains(&key.as_str()))
                .collect();
            assert!(extra.is_empty(), "{name}: unexpected tables {extra:?}");
            fixtures.push(Fixture {
                meta: table(&root, "meta", &name)?,
                request: table(&root, "request", &name)?,
                expected: table(&root, "expected", &name)?,
                name,
            });
        }
        fixtures.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(fixtures)
    }

    fn text<'a>(t: &'a Table, key: &str) -> Option<&'a str> {
        t.get(key).and_then(Value::as_str)
    }

    fn need_text<'a>(t: &'a Table, key: &str, name: &str) -> TestResult<&'a str> {
        text(t, key).ok_or_else(|| format!("{name}: missing string `{key}`").into())
    }

    fn int<T: TryFrom<i64>>(t: &Table, key: &str, name: &str) -> TestResult<Option<T>> {
        match t.get(key) {
            None => Ok(None),
            Some(value) => {
                let raw = value
                    .as_integer()
                    .ok_or_else(|| format!("{name}: `{key}` is not an integer"))?;
                let converted = T::try_from(raw)
                    .map_err(|_err| format!("{name}: `{key}` = {raw} is out of range"))?;
                Ok(Some(converted))
            }
        }
    }

    fn flag(t: &Table, key: &str) -> Option<bool> {
        t.get(key).and_then(Value::as_bool)
    }

    fn strings<'a>(t: &'a Table, key: &str, name: &str) -> TestResult<Vec<&'a str>> {
        let Some(value) = t.get(key) else {
            return Ok(Vec::new());
        };
        let array = value
            .as_array()
            .ok_or_else(|| format!("{name}: `{key}` is not an array"))?;
        array
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or_else(|| format!("{name}: `{key}` holds a non-string").into())
            })
            .collect()
    }

    fn id<T>(t: &Table, key: &str, name: &str) -> TestResult<Option<T>>
    where
        T: FromStr<Err = Error> + ToString,
    {
        text(t, key)
            .map(|value| parse_id(value, key, name))
            .transpose()
    }

    fn need_id<T>(t: &Table, key: &str, name: &str) -> TestResult<T>
    where
        T: FromStr<Err = Error> + ToString,
    {
        id(t, key, name)?.ok_or_else(|| format!("{name}: missing id `{key}`").into())
    }

    /// Parses a fixture ULID and checks it displays back to the same text.
    fn parse_id<T>(value: &str, key: &str, name: &str) -> TestResult<T>
    where
        T: FromStr<Err = Error> + ToString,
    {
        let parsed: T = value
            .parse()
            .map_err(|err| format!("{name}: `{key}` = {value:?} is not a ULID: {err}"))?;
        assert_eq!(
            parsed.to_string().to_ascii_lowercase(),
            value,
            "{name}: `{key}` must display back to its fixture text"
        );
        Ok(parsed)
    }

    fn named<T>(
        value: &str,
        parse: fn(&str) -> Option<T>,
        what: &str,
        name: &str,
    ) -> TestResult<T> {
        parse(value).ok_or_else(|| format!("{name}: {value:?} is not a contract {what}").into())
    }

    fn hex(value: &str, name: &str) -> TestResult<Vec<u8>> {
        let digits = value.as_bytes();
        if !digits.len().is_multiple_of(2) {
            return Err(format!("{name}: odd-length hex {value:?}").into());
        }
        digits
            .chunks(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair)?;
                Ok(u8::from_str_radix(pair, 16)
                    .map_err(|err| format!("{name}: bad hex {value:?}: {err}"))?)
            })
            .collect()
    }

    /// Parses `YYYY-MM-DDTHH:MM:SSZ` into a timestamp.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "civil-to-epoch arithmetic on four-digit-year fixture dates stays far inside i64"
    )]
    fn rfc3339(value: &str, name: &str) -> TestResult<Timestamp> {
        let bad = || format!("{name}: {value:?} is not YYYY-MM-DDTHH:MM:SSZ");
        let (date, time) = value
            .strip_suffix('Z')
            .and_then(|v| v.split_once('T'))
            .ok_or_else(bad)?;
        let field =
            |part: Option<&str>| -> TestResult<i64> { Ok(part.ok_or_else(bad)?.parse::<i64>()?) };
        let mut ymd = date.split('-');
        let (year, month, day) = (field(ymd.next())?, field(ymd.next())?, field(ymd.next())?);
        let mut hms = time.split(':');
        let (hour, minute, second) = (field(hms.next())?, field(hms.next())?, field(hms.next())?);
        // Days from civil (proleptic Gregorian), era-based.
        let y = if month <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (month + 9) % 12;
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
        Ok(Timestamp::from_unix_millis(seconds * 1_000))
    }

    fn idempotency_key(t: &Table, name: &str) -> TestResult<Option<IdempotencyKey>> {
        text(t, "idempotency_key")
            .map(|value| Ok(IdempotencyKey::new(hex(value, name)?)?))
            .transpose()
    }

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
            parent_grant: need_id(req, "parent_grant", name)?,
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
    fn request_body(capability: Capability, req: &Table, name: &str) -> TestResult<RequestBody> {
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

    fn failure(outcome: OutcomeKind, exp: &Table, name: &str) -> TestResult<Failure> {
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
    fn success(capability: Capability, exp: &Table, name: &str) -> TestResult<ResponseBody> {
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

    fn plan(capability: Capability, exp: &Table, name: &str) -> TestResult<ResponseBody> {
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

    /// Carries a message through a full frame and a validating decode.
    fn through_wire(request: &Request, response: &Response) -> TestResult<(Request, Response)> {
        let frame = encode_frame(request, DEFAULT_MAX_BODY)?;
        let (head, body) = frame.split_at(HEADER_LEN);
        let header = FrameHeader::decode(head.try_into()?, DEFAULT_MAX_BODY)?;
        let request = decode_frame(&header, body, DEFAULT_MAX_BODY)?;
        let response = decode(&encode(response)?, DEFAULT_MAX_BODY)?;
        Ok((request, response))
    }

    fn check_capability_fixture(fixture: &Fixture, capability: Capability) -> TestResult {
        let (name, req, exp) = (&fixture.name, &fixture.request, &fixture.expected);
        let mode = named(need_text(req, "mode", name)?, Mode::from_name, "mode", name)?;
        let request = Request {
            request_id: 1,
            idempotency_key: idempotency_key(req, name)?,
            mode,
            deadline_ms: 30_000,
            body: request_body(capability, req, name)?,
        };
        let outcome_name = need_text(exp, "outcome", name)?;
        let outcome = named(outcome_name, OutcomeKind::from_name, "outcome kind", name)?;
        let body = match outcome {
            OutcomeKind::Success => success(capability, exp, name)?,
            OutcomeKind::Plan => plan(capability, exp, name)?,
            OutcomeKind::InProgress => ResponseBody::InProgress,
            _ => ResponseBody::Failed(failure(outcome, exp, name)?),
        };
        let response = Response {
            request_id: 1,
            invocation: None,
            body,
        };
        let (request_back, response_back) = through_wire(&request, &response)?;
        assert_eq!(request_back, request, "{name}: request survives the wire");
        assert_eq!(response_back, response, "{name}: reply survives the wire");
        assert_eq!(
            request_back.body.capability().name(),
            capability.name(),
            "{name}: capability"
        );
        assert_eq!(request_back.mode, mode, "{name}: mode");
        assert_eq!(
            response_back.body.outcome().name(),
            outcome_name,
            "{name}: outcome kind"
        );
        Ok(())
    }

    fn check_frame_fixture(fixture: &Fixture, frame: FrameKind) -> TestResult {
        let (name, req, exp) = (&fixture.name, &fixture.request, &fixture.expected);
        let outcome = need_text(exp, "outcome", name)?;
        match frame {
            FrameKind::ClientHello => {
                let nonce: [u8; NONCE_LEN] = hex(need_text(req, "client_nonce", name)?, name)?
                    .as_slice()
                    .try_into()?;
                let hello = ClientHello {
                    version_min: int(req, "version_min", name)?.ok_or("needs version_min")?,
                    version_max: int(req, "version_max", name)?.ok_or("needs version_max")?,
                    tenant: need_id(req, "tenant", name)?,
                    client_nonce: Nonce::from_bytes(nonce),
                };
                let back: ClientHello = decode(&encode(&hello)?, PRE_AUTH_MAX_BODY)?;
                assert_eq!(back, hello, "{name}: hello survives the wire");
                let choice = negotiate_version(
                    hello.version_min,
                    hello.version_max,
                    WIRE_VERSION,
                    WIRE_VERSION,
                );
                let choice_name = match choice {
                    VersionChoice::Chosen(_) => "Chosen",
                    VersionChoice::Incompatible => "Incompatible",
                };
                assert_eq!(choice_name, outcome, "{name}: negotiation outcome");
            }
            FrameKind::Request => {
                let declared: u32 = int(req, "declared_len", name)?.ok_or("needs declared_len")?;
                let pre_auth = flag(req, "pre_auth").ok_or("needs pre_auth")?;
                let cap = if pre_auth {
                    PRE_AUTH_MAX_BODY
                } else {
                    int(req, "negotiated_max", name)?.ok_or("needs negotiated_max")?
                };
                let result = FrameHeader::decode(&FrameHeader::new(frame, declared).encode(), cap);
                assert!(
                    matches!(result, Err(Error::FrameTooLarge { .. })),
                    "{name}: oversized header is refused, got {result:?}"
                );
                check_fault(outcome, Failure::ProtocolError, name)?;
            }
            FrameKind::Auth => {
                let cause = need_text(req, "cause", name)?;
                assert!(AUTH_CAUSES.contains(&cause), "{name}: cause {cause:?}");
                check_fault(outcome, Failure::AuthFailed, name)?;
            }
            _ => return Err(format!("{name}: no mapping for frame {}", frame.name()).into()),
        }
        Ok(())
    }

    fn check_fault(outcome: &str, expected: Failure, name: &str) -> TestResult {
        assert_eq!(outcome, expected.kind().name(), "{name}: outcome kind");
        let fault = Fault { failure: expected };
        let back: Fault = decode(&encode(&fault)?, PRE_AUTH_MAX_BODY)?;
        assert_eq!(back, fault, "{name}: fault survives the wire");
        Ok(())
    }

    #[test]
    fn declared_fixtures_are_present_and_no_others() -> TestResult {
        let found: BTreeSet<String> = load()?.into_iter().map(|f| f.name).collect();
        let declared: BTreeSet<String> = DECLARED.iter().map(|&n| n.to_owned()).collect();
        let missing: Vec<&String> = declared.difference(&found).collect();
        let undeclared: Vec<&String> = found.difference(&declared).collect();
        assert!(missing.is_empty(), "declared fixtures missing: {missing:?}");
        assert!(
            undeclared.is_empty(),
            "fixtures without a mapping: {undeclared:?}"
        );
        Ok(())
    }

    #[test]
    fn meta_tables_follow_the_fixture_schema() -> TestResult {
        for fixture in load()? {
            let name = &fixture.name;
            assert_eq!(
                need_text(&fixture.meta, "name", name)?,
                name,
                "meta.name equals the file stem"
            );
            let kind = need_text(&fixture.meta, "kind", name)?;
            let expected_kind = if name.starts_with("neg_") {
                "negative"
            } else {
                "positive"
            };
            assert_eq!(kind, expected_kind, "{name}: kind matches the neg_ prefix");
            assert!(
                !need_text(&fixture.meta, "clause", name)?.trim().is_empty(),
                "{name}: clause is quoted"
            );
        }
        Ok(())
    }

    #[test]
    fn every_key_has_a_contract_role() -> TestResult {
        for fixture in load()? {
            for key in fixture.request.keys() {
                let known = has_word(REQUEST_KEYS, key) || key.starts_with("ceiling_");
                assert!(known, "{}: [request] key `{key}` has no role", fixture.name);
            }
            for key in fixture.expected.keys() {
                assert!(
                    has_word(EXPECTED_KEYS, key),
                    "{}: [expected] key `{key}` has no role",
                    fixture.name
                );
            }
        }
        Ok(())
    }

    #[test]
    fn every_identifier_parses_and_displays_back() -> TestResult {
        for fixture in load()? {
            for t in [&fixture.request, &fixture.expected] {
                for key in ID_KEYS.split_whitespace() {
                    match t.get(key) {
                        None => {}
                        Some(Value::String(value)) => {
                            parse_id::<TenantId>(value, key, &fixture.name)?;
                        }
                        Some(Value::Array(_)) => {
                            for value in strings(t, key, &fixture.name)? {
                                parse_id::<TenantId>(value, key, &fixture.name)?;
                            }
                        }
                        Some(other) => {
                            return Err(format!("{}: `{key}` = {other}", fixture.name).into());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn observation_names_parse_as_contract_types() -> TestResult {
        for fixture in load()? {
            let (name, req, exp) = (&fixture.name, &fixture.request, &fixture.expected);
            if let Some(state) = text(exp, "final_state") {
                named(state, InvocationState::from_name, "invocation state", name)?;
            }
            if let Some(reason) = text(exp, "released_reason") {
                named(reason, ReleaseReason::from_name, "release reason", name)?;
                assert_eq!(
                    text(exp, "final_state"),
                    Some("Released"),
                    "{name}: released"
                );
            }
            if let Some(axis) = text(exp, "axis") {
                named(axis, NarrowingAxis::from_name, "narrowing axis", name)?;
            }
            for key in ["capabilities", "parent_capabilities"] {
                for capability in strings(req, key, name)? {
                    named(capability, Capability::from_name, "capability", name)?;
                }
            }
            for key in ["clock_now", "grant_expires_at", "expires_at"] {
                if let Some(value) = text(req, key) {
                    rfc3339(value, name)?;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn rfc3339_matches_independent_epoch_values() -> TestResult {
        for (text, millis) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2026-09-24T00:00:00Z", 1_790_208_000_000),
            ("2026-09-25T00:00:00Z", 1_790_294_400_000),
            ("2026-10-25T00:00:00Z", 1_792_886_400_000),
        ] {
            assert_eq!(rfc3339(text, "helper")?.unix_millis(), millis, "{text}");
        }
        Ok(())
    }

    #[test]
    fn every_fixture_maps_onto_contract_types() -> TestResult {
        for fixture in load()? {
            let name = &fixture.name;
            match (
                text(&fixture.request, "capability"),
                text(&fixture.request, "frame"),
            ) {
                (Some(capability), None) => {
                    let capability = named(capability, Capability::from_name, "capability", name)?;
                    check_capability_fixture(&fixture, capability)?;
                }
                (None, Some(frame)) => {
                    let frame = named(frame, FrameKind::from_name, "frame kind", name)?;
                    check_frame_fixture(&fixture, frame)?;
                }
                _ => return Err(format!("{name}: needs exactly one of capability, frame").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn grant_issue_fixture_carries_its_ceilings_and_expiry() -> TestResult {
        let fixture = load()?
            .into_iter()
            .find(|f| f.name == "grant_issue_valid")
            .ok_or("grant_issue_valid missing")?;
        let RequestBody::GrantIssue(issue) =
            request_body(Capability::GrantIssue, &fixture.request, &fixture.name)?
        else {
            return Err("grant_issue_valid did not map to GrantIssue".into());
        };
        assert_eq!(issue.ceilings.fetches, Some(10), "ceiling_fetches");
        assert_eq!(
            issue.ceilings.bytes_transferred,
            Some(524_288),
            "ceiling_bytes_transferred"
        );
        assert_eq!(
            issue.ceilings.wall_time_ms, None,
            "unset ceilings stay unset"
        );
        assert_eq!(
            issue.expires_at,
            Timestamp::from_unix_millis(1_792_886_400_000),
            "expires_at 2026-10-25"
        );
        assert_eq!(
            issue.capabilities,
            [Capability::Capture, Capability::Read],
            "capabilities"
        );
        Ok(())
    }

    #[test]
    fn idempotency_keys_are_hex_encoded_16_to_64_bytes() -> TestResult {
        let mut seen = 0_usize;
        for fixture in load()? {
            if let Some(key) = idempotency_key(&fixture.request, &fixture.name)? {
                assert_eq!(key.as_bytes().len(), 16, "{}: 32 hex digits", fixture.name);
                seen = seen.saturating_add(1);
            }
        }
        assert!(seen > 0, "fixtures exercise idempotency keys");
        Ok(())
    }

    #[test]
    fn capture_session_fallback_is_a_valid_id() -> TestResult {
        let session: SessionId = CAST_SESSION.parse()?;
        assert_eq!(
            session.to_string().to_ascii_lowercase(),
            CAST_SESSION,
            "cast session"
        );
        Ok(())
    }
}
