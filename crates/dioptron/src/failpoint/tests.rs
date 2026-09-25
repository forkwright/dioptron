use phylake::store::{Boundary, Phase};

use super::AbortAt;
use crate::Error;

#[test]
fn parse_accepts_every_phase_and_boundary() {
    for phase in ["before_commit", "after_commit"] {
        for boundary in Boundary::ALL {
            let text = format!("{phase}:{}", boundary.name());
            let parsed = AbortAt::parse(&text);
            assert!(parsed.is_ok(), "{text} parses: {parsed:?}");
        }
    }
}

#[test]
fn parsed_failpoint_fires_only_at_its_point() -> Result<(), Error> {
    let point = AbortAt::parse("after_commit:B2")?;

    assert!(
        point.fires(Boundary::Dispatch, Phase::AfterCommit),
        "after B2 fires"
    );
    assert!(
        !point.fires(Boundary::Dispatch, Phase::BeforeCommit),
        "before B2 does not"
    );
    assert!(
        !point.fires(Boundary::CompleteTransfer, Phase::AfterCommit),
        "after B3 does not"
    );
    Ok(())
}

#[test]
fn parse_rejects_malformed_text() {
    for text in [
        "",
        "after_commit",
        "during:B2",
        "after_commit:B9",
        "B2:after_commit",
    ] {
        let parsed = AbortAt::parse(text);
        assert!(
            matches!(parsed, Err(Error::Usage { .. })),
            "{text:?} is refused: {parsed:?}"
        );
    }
}
