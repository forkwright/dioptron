use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn origin(text: &str) -> Result<Origin, Error> {
    Origin::parse(text)
}

fn pattern(text: &str) -> Result<OriginPattern, Error> {
    OriginPattern::parse(text)
}

#[test]
fn parse_extracts_scheme_host_and_effective_port() -> TestResult {
    let cases = [
        ("https://example.com/article", "https://example.com:443"),
        ("http://example.com", "http://example.com:80"),
        ("HTTPS://EXAMPLE.com:8443?q", "https://example.com:8443"),
        ("https://example.com#frag", "https://example.com:443"),
        (
            "https://example.com\\@evil.example/",
            "https://example.com:443",
        ),
        ("http://192.0.2.7:080/x", "http://192.0.2.7:80"),
        ("https://a-b.example.com/", "https://a-b.example.com:443"),
    ];
    for (text, expected) in cases {
        assert_eq!(origin(text)?.to_string(), expected, "origin of {text}");
    }
    Ok(())
}

#[test]
fn parse_rejects_ambiguous_targets() {
    let refused = [
        "https://user@example.com/",
        "https://example.com@evil.example/",
        "https://[2001:db8::1]/",
        "https://exa%6Dple.com/",
        "https://exa\tmple.com/",
        " https://example.com/",
        "https://example.com /",
        "https:///example.com/",
        "https:example.com",
        "ftp://example.com/",
        "https://example.com./",
        "https://example..com/",
        "https://-example.com/",
        "https://example-.com/",
        "https://ex_ample.com/",
        "https://exämple.com/",
        "https://example.com:/",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:1:2/",
        "https://example.com:8a/",
        "https://0x7f.1/",
        "https://2130706433/",
        "https://127.1/",
        "https://192.0.2.01/",
        "https://192.0.2.256/",
        "https://1.192.0.2.7/",
        "https://example.123/",
        "https:///",
        "https://",
    ];
    for text in refused {
        assert!(
            matches!(origin(text), Err(Error::OriginSyntax { .. })),
            "{text:?} must be refused"
        );
    }
}

#[test]
fn parse_rejects_overlong_hosts_and_labels() {
    let long_label = format!("https://{}.example.com/", "a".repeat(64));
    assert!(origin(&long_label).is_err(), "64-byte label refused");
    let ok_label = format!("https://{}.example.com/", "a".repeat(63));
    assert!(origin(&ok_label).is_ok(), "63-byte label accepted");
    let long_host = format!("https://{}com/", "abcdefghi.".repeat(26));
    assert!(origin(&long_host).is_err(), "host over 253 bytes refused");
}

#[test]
fn pattern_matches_by_scheme_host_and_port() -> TestResult {
    let cases: [(&str, &str, bool); 14] = [
        ("example.com", "https://example.com/a", true),
        ("example.com", "http://example.com/a", true),
        ("example.com", "https://example.com:8443/a", false),
        ("example.com", "https://news.example.com/a", false),
        ("https://example.com", "http://example.com/a", false),
        (
            "https://example.com:8443",
            "https://example.com:8443/",
            true,
        ),
        ("example.com:8443", "http://example.com:8443/", true),
        ("*.example.com", "https://a.b.example.com/", true),
        ("*.example.com", "https://example.com/", false),
        ("*.example.com", "https://badexample.com/", false),
        ("*", "https://anything.example.org/", true),
        ("*", "https://192.0.2.1/", true),
        ("192.0.2.1", "http://192.0.2.1/", true),
        ("*.com", "https://192.0.2.1/", false),
    ];
    for (pat, target, expected) in cases {
        assert_eq!(
            pattern(pat)?.matches(&origin(target)?),
            expected,
            "{pat} against {target}"
        );
    }
    Ok(())
}

#[test]
fn pattern_parse_rejects_malformed_patterns() {
    let refused = [
        "",
        "*.",
        "*.*.example.com",
        "a.*.example.com",
        "*.192.0.2.1",
        "ftp://example.com",
        "example.com/path",
        "example.com:",
        "example .com",
    ];
    for text in refused {
        assert!(
            matches!(pattern(text), Err(Error::OriginSyntax { .. })),
            "{text:?} must be refused"
        );
    }
}

#[test]
fn covers_follows_the_admitted_origin_sets() -> TestResult {
    let cases: [(&str, &str, bool); 14] = [
        ("*", "example.com", true),
        ("example.com", "*", false),
        ("example.com", "example.com", true),
        ("example.com", "https://example.com", true),
        ("https://example.com", "example.com", false),
        ("example.com", "example.com:8443", false),
        ("https://example.com", "https://example.com:443", true),
        ("http://example.com:443", "https://example.com", false),
        ("*.example.com", "news.example.com", true),
        ("*.example.com", "example.com", false),
        ("*.example.com", "*.news.example.com", true),
        ("*.example.com", "*.example.com", true),
        ("*.news.example.com", "*.example.com", false),
        ("example.com", "*.example.com", false),
    ];
    for (outer, inner, expected) in cases {
        assert_eq!(
            pattern(outer)?.covers(&pattern(inner)?),
            expected,
            "{outer} covers {inner}"
        );
    }
    Ok(())
}

#[test]
fn target_scope_is_a_union_and_empty_admits_nothing() -> TestResult {
    let scope = TargetScope::parse(&["example.com", "*.example.org"])?;
    assert!(scope.matches(&origin("https://example.com/")?), "first");
    assert!(scope.matches(&origin("https://a.example.org/")?), "second");
    assert!(!scope.matches(&origin("https://example.org/")?), "neither");
    assert!(
        !TargetScope::default().matches(&origin("https://example.com/")?),
        "empty scope admits nothing"
    );
    let narrower = TargetScope::parse(&["https://example.com", "b.example.org"])?;
    assert!(scope.covers(&narrower), "narrower is covered");
    assert!(!narrower.covers(&scope), "broader is not covered");
    assert!(
        scope.covers(&TargetScope::default()),
        "empty is covered by anything"
    );
    assert!(
        TargetScope::parse(&["example.com", "*.*"]).is_err(),
        "one bad pattern fails the scope"
    );
    Ok(())
}
