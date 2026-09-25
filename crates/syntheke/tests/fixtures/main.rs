//! Conformance of the contract fixtures under `docs/contract/fixtures/`.
//!
//! Every fixture's wire fields are mapped into `syntheke` request and reply
//! types and carried through a full encode and validating decode; every name
//! a fixture uses (capability, mode, outcome kind, deny code, class, state,
//! reason, axis, scope, frame kind) must parse as the contract type it names.
//! A missing fixture directory or a missing declared fixture fails the test.

mod load;
mod mapping;

// NOTE: clippy's tests_outside_test_module (denied workspace-wide) also
// applies to integration test crates, hence the module wrapper.
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use syntheke::{
        Capability, ClientHello, DEFAULT_MAX_BODY, Error, Failure, Fault, FrameHeader, FrameKind,
        GrantId, HEADER_LEN, InvocationState, Mode, NONCE_LEN, NarrowingAxis, Nonce, OutcomeKind,
        PRE_AUTH_MAX_BODY, ReleaseReason, Request, RequestBody, Response, ResponseBody, SessionId,
        TenantId, Timestamp, VersionChoice, WIRE_VERSION, decode, decode_frame, encode,
        encode_frame, negotiate_version,
    };
    use toml::Value;

    use crate::load::{
        Fixture, TestResult, fixture, flag, has_word, hex, idempotency_key, int, load, named,
        need_id, need_text, parse_id, rfc3339, strings, text,
    };
    use crate::mapping::{CAST_SESSION, failure, plan, request_body, success};

    /// Every scenario the contract declares. A missing file fails the test;
    /// an undeclared file fails it too, so a new fixture gets a mapping.
    const DECLARED: [&str; 22] = [
        "audit_query_own",
        "capture_success",
        "capture_truncated",
        "dry_run",
        "grant_issue_valid",
        "grant_revoke",
        "neg_cross_tenant_read",
        "neg_expired_grant",
        "neg_extraction_failed",
        "neg_foreign_grant",
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
        capability mode grant idempotency_key session target max_output_bytes \
        max_transfer_bytes artifact_ref offset len predicate session_scope \
        parent_session holder capabilities target_scope expires_at \
        target_grant audit_scope frame version_min version_max client_nonce \
        signature tenant \
        clock_now grant_expires_at parent_grant parent_capabilities \
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

    /// Carries a message through a full frame and a validating decode.
    fn through_wire(request: &Request, response: &Response) -> TestResult<(Request, Response)> {
        let frame = encode_frame(request, DEFAULT_MAX_BODY)?;
        let (head, body) = frame.split_at(HEADER_LEN);
        let header = FrameHeader::decode(head.try_into()?, DEFAULT_MAX_BODY)?;
        let request = decode_frame(&header, body, DEFAULT_MAX_BODY)?;
        let response = decode(&encode(response)?, DEFAULT_MAX_BODY)?;
        Ok((request, response))
    }

    /// Builds the request a capability fixture describes.
    fn fixture_request(fixture: &Fixture, capability: Capability) -> TestResult<Request> {
        let (name, req) = (&fixture.name, &fixture.request);
        Ok(Request {
            request_id: 1,
            grant: need_id(req, "grant", name)?,
            idempotency_key: idempotency_key(req, name)?,
            mode: named(need_text(req, "mode", name)?, Mode::from_name, "mode", name)?,
            deadline_ms: 30_000,
            body: request_body(capability, req, name)?,
        })
    }

    /// Whether `haystack` holds `needle` as a contiguous run.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// For a fixture that expects `echoes_ref = false`, the encoded reply
    /// holds none of the request's grant, artifact reference, or target.
    fn check_no_echo(fixture: &Fixture, request: &Request, response: &Response) -> TestResult {
        if flag(&fixture.expected, "echoes_ref") != Some(false) {
            return Ok(());
        }
        let reply = encode(response)?;
        let mut supplied: Vec<Vec<u8>> = vec![request.grant.to_bytes().to_vec()];
        if let Some(artifact) = text(&fixture.request, "artifact_ref") {
            let artifact: syntheke::ArtifactRef = artifact.parse()?;
            supplied.push(artifact.to_bytes().to_vec());
        }
        if let Some(target) = text(&fixture.request, "target") {
            supplied.push(target.as_bytes().to_vec());
        }
        for needle in supplied {
            assert!(
                !contains(&reply, &needle),
                "{}: the reply echoes a caller-supplied reference",
                fixture.name
            );
        }
        Ok(())
    }

    fn check_capability_fixture(fixture: &Fixture, capability: Capability) -> TestResult {
        let (name, exp) = (&fixture.name, &fixture.expected);
        let request = fixture_request(fixture, capability)?;
        let outcome_name = need_text(exp, "outcome", name)?;
        let outcome = named(outcome_name, OutcomeKind::from_name, "outcome kind", name)?;
        let body = match outcome {
            OutcomeKind::Success => success(capability, exp, name)?,
            OutcomeKind::Plan => plan(capability, exp, name)?,
            OutcomeKind::InProgress => ResponseBody::InProgress,
            _ => ResponseBody::Failed(failure(outcome, exp, name)?),
        };
        if let ResponseBody::Plan(plan) = &body {
            assert_eq!(
                plan.grant_chain.first(),
                Some(&request.grant),
                "{name}: a plan's chain starts at the designated grant"
            );
        }
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
        assert_eq!(
            request_back.grant,
            need_id::<GrantId>(&fixture.request, "grant", name)?,
            "{name}: designated grant"
        );
        assert_eq!(
            response_back.body.outcome().name(),
            outcome_name,
            "{name}: outcome kind"
        );
        check_no_echo(fixture, &request, &response)
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
                    _ => return Err(format!("{name}: unmapped version choice").into()),
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
    fn every_capability_request_designates_a_grant() -> TestResult {
        let mut seen = 0_usize;
        for fixture in load()? {
            if text(&fixture.request, "capability").is_some() {
                need_id::<GrantId>(&fixture.request, "grant", &fixture.name)?;
                seen = seen.saturating_add(1);
            }
        }
        assert!(seen > 0, "fixtures exercise capability requests");
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
        let fixture = fixture("grant_issue_valid")?;
        let request = fixture_request(&fixture, Capability::GrantIssue)?;
        let RequestBody::GrantIssue(issue) = request.body else {
            return Err("grant_issue_valid did not map to GrantIssue".into());
        };
        assert_eq!(
            request.grant,
            need_id::<GrantId>(&fixture.expected, "parent_grant", &fixture.name)?,
            "the designated grant is the parent the reply names"
        );
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
    fn foreign_grant_fixture_designates_another_tenants_grant() -> TestResult {
        let foreign = fixture("neg_foreign_grant")?;
        let own = fixture("capture_success")?;
        let name = &foreign.name;
        let caller: TenantId = need_id(&foreign.request, "tenant", name)?;
        let holder: TenantId = need_id(&own.request, "tenant", &own.name)?;
        assert_ne!(caller, holder, "{name}: the caller is not the holder");
        assert_eq!(
            need_id::<GrantId>(&foreign.request, "grant", name)?,
            need_id::<GrantId>(&own.request, "grant", &own.name)?,
            "{name}: the designated grant is the holder's"
        );
        assert_eq!(
            need_text(&foreign.expected, "outcome", name)?,
            OutcomeKind::NotFoundOrDenied.name(),
            "{name}: a foreign grant reads as missing"
        );
        assert_eq!(
            flag(&foreign.expected, "indistinguishable"),
            Some(true),
            "{name}: the reply matches the reply for a grant that does not exist"
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
