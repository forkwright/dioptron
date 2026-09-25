use std::path::PathBuf;

use syntheke::{GrantId, TenantClass, TenantId};

use super::{Command, Serve, parse, parse_key};
use crate::Error;

const TENANT: &str = "01J8K7R3V9ZQ4N5M6P7S8TNT0A";
const GRANT: &str = "01J8K7R3V9ZQ4N5M6P7S8GRN0A";
const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn parse_reads_every_command() -> Result<(), Error> {
    assert_eq!(
        parse(Vec::<String>::new())?,
        Command::Help,
        "no words is help"
    );
    assert_eq!(parse(words("help"))?, Command::Help, "help");
    assert_eq!(
        parse(words("keygen /k"))?,
        Command::Keygen {
            path: PathBuf::from("/k")
        },
        "keygen"
    );
    assert_eq!(
        parse(words("init --store /s --root-key /k"))?,
        Command::Init {
            store: PathBuf::from("/s"),
            root_key: PathBuf::from("/k"),
        },
        "init"
    );
    assert_eq!(
        parse(words(
            "serve --store /s --root-key /k --socket-dir /d --producer fixture:/f"
        ))?,
        Command::Serve(Serve {
            store: PathBuf::from("/s"),
            root_key: PathBuf::from("/k"),
            socket_dir: PathBuf::from("/d"),
            fixture: Some(PathBuf::from("/f")),
        }),
        "serve with a fixture"
    );
    Ok(())
}

#[test]
fn parse_serve_defaults_to_the_unavailable_producer() -> Result<(), Error> {
    for text in [
        "serve --store /s --root-key /k --socket-dir /d",
        "serve --store /s --root-key /k --socket-dir /d --producer unavailable",
    ] {
        let Command::Serve(serve) = parse(words(text))? else {
            return Err(Error::Usage {
                message: "not serve".to_owned(),
                location: snafu::location!(),
            });
        };
        assert_eq!(serve.fixture, None, "{text} fetches nothing");
    }
    Ok(())
}

#[test]
fn parse_reads_tenant_add() -> Result<(), Error> {
    let text = format!(
        "tenant add --store /s --root-key /k --tenant {TENANT} --class operator \
         --verifying-key {KEY} --uid 1000 --uid 1001 --root-grant {GRANT} \
         --target example.com --target *.example.org --not-before 0 \
         --expires-at 9000 --max-depth 3"
    );

    let Command::TenantAdd(add) = parse(words(&text))? else {
        return Err(Error::Usage {
            message: "not tenant add".to_owned(),
            location: snafu::location!(),
        });
    };

    assert_eq!(Some(add.tenant), TENANT.parse::<TenantId>().ok(), "tenant");
    assert_eq!(add.class, TenantClass::Operator, "class");
    assert_eq!(add.uids, vec![1000, 1001], "repeatable uid");
    assert_eq!(add.root_grant, GRANT.parse::<GrantId>().ok(), "root grant");
    assert_eq!(add.targets, vec!["example.com", "*.example.org"], "targets");
    assert_eq!(
        (add.not_before, add.expires_at, add.max_depth),
        (Some(0), Some(9000), Some(3)),
        "validity and depth"
    );
    assert_eq!(add.verifying_key.get(1), Some(&0x11), "hex key");
    Ok(())
}

#[test]
fn parse_rejects_malformed_command_lines() {
    let cases = [
        "launch".to_owned(),
        "keygen".to_owned(),
        "init --store /s".to_owned(),
        "init --store /s --root-key /k --extra 1".to_owned(),
        "init --store /s --store /t --root-key /k".to_owned(),
        "init --store".to_owned(),
        "init store /s".to_owned(),
        "serve --store /s --root-key /k --socket-dir /d --producer http".to_owned(),
        "serve --store /s --root-key /k --socket-dir /d --producer fixture:".to_owned(),
        format!(
            "tenant add --store /s --root-key /k --tenant {TENANT} --class boss --verifying-key {KEY} --uid 1"
        ),
        format!(
            "tenant add --store /s --root-key /k --tenant {TENANT} --class agent --verifying-key 00 --uid 1"
        ),
        format!(
            "tenant add --store /s --root-key /k --tenant {TENANT} --class agent --verifying-key {KEY}"
        ),
        format!(
            "tenant add --store /s --root-key /k --tenant nope --class agent --verifying-key {KEY} --uid 1"
        ),
        format!(
            "tenant add --store /s --root-key /k --tenant {TENANT} --class agent --verifying-key {KEY} --uid x"
        ),
        "init --root-key /k --store --x".to_owned(),
        "serve --store /s --root-key /k --socket-dir --producer".to_owned(),
        format!(
            "tenant add --store /s --root-key /k --tenant {TENANT} --class agent --verifying-key {KEY} --uid 1 --target example.com"
        ),
        format!(
            "tenant add --store /s --root-key /k --tenant {TENANT} --class sub-agent --verifying-key {KEY} --uid 1 --expires-at 5"
        ),
        format!(
            "tenant add --store /s --root-key /k --tenant {TENANT} --class agent --verifying-key {KEY} --uid 1 --max-depth 2"
        ),
    ];

    for case in cases {
        let parsed = parse(words(&case));
        assert!(
            matches!(parsed, Err(Error::Usage { .. })),
            "{case:?} is a usage error: {parsed:?}"
        );
    }
}

#[test]
fn parse_key_needs_64_hex_digits() {
    let upper = KEY.to_uppercase();
    let bad_digit = format!("zz{}", KEY.get(2..).unwrap_or_default());

    assert!(parse_key(&upper).is_ok(), "upper case hex parses");
    assert!(parse_key(&bad_digit).is_err(), "a non-hex digit is refused");
    assert!(
        parse_key(&"+0".repeat(32)).is_err(),
        "a sign is not a hex digit"
    );
    assert!(
        parse_key(KEY.get(..62).unwrap_or_default()).is_err(),
        "a short key is refused"
    );
}
