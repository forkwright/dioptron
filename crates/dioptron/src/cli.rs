//! The `dioptron` command line.
//!
//! ```text
//! dioptron keygen <root-key-file>
//! dioptron init --store <dir> --root-key <file>
//! dioptron tenant add --store <dir> --root-key <file> --tenant <ulid>
//!     --class operator|agent|sub-agent --verifying-key <hex> --uid <n>...
//!     [--parent <ulid>] [--root-grant <ulid>] [--target <pattern>]...
//!     [--not-before <ms>] [--expires-at <ms>] [--max-depth <n>]
//! dioptron serve --store <dir> --root-key <file> --socket-dir <dir>
//!     [--producer unavailable|fixture:<script>]
//! ```
//!
//! `tenant add` registers a tenant with its Ed25519 verifying key and the
//! local user ids it may connect from. For an operator it also installs
//! the root grant: every capability, the operator's default audit scope
//! (`All`, D17.7), session scope `Own`, the given target patterns (default
//! `*`), and the given validity (default: now for one year).
//!
//! `serve` opens the store (a missing or wrong root key fails closed before
//! anything binds), runs restart recovery, binds `<socket-dir>/dioptron.sock`,
//! prints `ready <socket path>` on standard output, and serves until
//! `SIGINT` or `SIGTERM`. Its producer is `unavailable` unless a fixture
//! script is named explicitly, so it never fetches anything by default.

mod args;
mod serve;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use epitrope::default_audit_scope;
use phylake::StoreOptions;
use phylake::keyfile::RootKey;
use phylake::store::{RootGrant, TenantRegistration};
use snafu::ResultExt as _;
use syntheke::{Capability, GrantId, TenantClass, TenantId, Timestamp};

use self::args::Args;
pub use self::serve::SOCKET_NAME;
use crate::clock::daemon_clock;
use crate::error::{Error, StoreSnafu, UsageSnafu};

/// Default root grant lifetime: one year, in milliseconds.
const DEFAULT_LIFETIME_MS: i64 = 365 * 24 * 60 * 60 * 1_000;

/// Default maximum delegation depth of an operator root grant.
const DEFAULT_MAX_DEPTH: u8 = 8;

/// The usage text printed for `help` and for a malformed command line.
pub const USAGE: &str = "usage:
  dioptron keygen <root-key-file>
  dioptron init --store <dir> --root-key <file>
  dioptron tenant add --store <dir> --root-key <file> --tenant <ulid>
      --class operator|agent|sub-agent --verifying-key <hex> --uid <n>...
      [--parent <ulid>] [--root-grant <ulid>] [--target <pattern>]...
      [--not-before <ms>] [--expires-at <ms>] [--max-depth <n>]
  dioptron serve --store <dir> --root-key <file> --socket-dir <dir>
      [--producer unavailable|fixture:<script>]";

/// One parsed command.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// Print the usage text.
    Help,
    /// Create a root key file.
    Keygen {
        /// Where to write it.
        path: PathBuf,
    },
    /// Create an empty store.
    Init {
        /// The store directory.
        store: PathBuf,
        /// The root key file.
        root_key: PathBuf,
    },
    /// Register a tenant.
    TenantAdd(Box<TenantAdd>),
    /// Serve the socket.
    Serve(Serve),
}

/// The arguments of `tenant add`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TenantAdd {
    /// The store directory.
    pub store: PathBuf,
    /// The root key file.
    pub root_key: PathBuf,
    /// The tenant.
    pub tenant: TenantId,
    /// Its class.
    pub class: TenantClass,
    /// Its Ed25519 verifying key.
    pub verifying_key: [u8; 32],
    /// The local user ids it may connect from.
    pub uids: Vec<u32>,
    /// Its parent tenant.
    pub parent: Option<TenantId>,
    /// The operator root grant's id; generated when absent.
    pub root_grant: Option<GrantId>,
    /// The root grant's target patterns.
    pub targets: Vec<String>,
    /// Start of the root grant's validity, in Unix milliseconds.
    pub not_before: Option<i64>,
    /// End of the root grant's validity, in Unix milliseconds.
    pub expires_at: Option<i64>,
    /// The root grant's maximum delegation depth.
    pub max_depth: Option<u8>,
}

/// The arguments of `serve`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Serve {
    /// The store directory.
    pub store: PathBuf,
    /// The root key file.
    pub root_key: PathBuf,
    /// The directory the socket is bound in.
    pub socket_dir: PathBuf,
    /// The fixture script, when the producer is a fixture.
    pub fixture: Option<PathBuf>,
}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// [`Error::Usage`] for an unknown command or flag, a missing or repeated
/// value, or a value that does not parse.
pub fn parse<I, S>(args: I) -> Result<Command, Error>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let words: Vec<String> = args.into_iter().map(Into::into).collect();
    let (command, rest) = match words.as_slice() {
        [] => return Ok(Command::Help),
        [first, rest @ ..] => (first.as_str(), rest),
    };
    match (command, rest) {
        ("help" | "--help" | "-h", []) => Ok(Command::Help),
        ("keygen", [path]) => Ok(Command::Keygen {
            path: PathBuf::from(path),
        }),
        ("init", flags) => {
            let mut args = Args::parse(flags, &[])?;
            let command = Command::Init {
                store: args.path("--store")?,
                root_key: args.path("--root-key")?,
            };
            args.finish()?;
            Ok(command)
        }
        ("tenant", [sub, flags @ ..]) if sub == "add" => {
            parse_tenant_add(flags).map(|add| Command::TenantAdd(Box::new(add)))
        }
        ("serve", flags) => parse_serve(flags).map(Command::Serve),
        _ => UsageSnafu {
            message: format!("unknown command {command}"),
        }
        .fail(),
    }
}

fn parse_tenant_add(flags: &[String]) -> Result<TenantAdd, Error> {
    let mut args = Args::parse(flags, &["--uid", "--target"])?;
    let add = TenantAdd {
        store: args.path("--store")?,
        root_key: args.path("--root-key")?,
        tenant: args.parsed("--tenant")?,
        class: args
            .required("--class")
            .and_then(|text| parse_class(&text))?,
        verifying_key: args
            .required("--verifying-key")
            .and_then(|text| parse_key(&text))?,
        uids: args.all_parsed("--uid")?,
        parent: args.optional_parsed("--parent")?,
        root_grant: args.optional_parsed("--root-grant")?,
        targets: args.all("--target"),
        not_before: args.optional_parsed("--not-before")?,
        expires_at: args.optional_parsed("--expires-at")?,
        max_depth: args.optional_parsed("--max-depth")?,
    };
    args.finish()?;
    let root_grant_flags = add.root_grant.is_some()
        || !add.targets.is_empty()
        || add.not_before.is_some()
        || add.expires_at.is_some()
        || add.max_depth.is_some();
    if add.class != TenantClass::Operator && root_grant_flags {
        return UsageSnafu {
            message: "only an operator gets a root grant: --root-grant, --target, \
                      --not-before, --expires-at, and --max-depth need --class operator",
        }
        .fail();
    }
    if add.uids.is_empty() {
        return UsageSnafu {
            message: "tenant add needs at least one --uid",
        }
        .fail();
    }
    Ok(add)
}

fn parse_serve(flags: &[String]) -> Result<Serve, Error> {
    let mut args = Args::parse(flags, &[])?;
    let serve = Serve {
        store: args.path("--store")?,
        root_key: args.path("--root-key")?,
        socket_dir: args.path("--socket-dir")?,
        fixture: match args.optional("--producer").as_deref() {
            None | Some("unavailable") => None,
            Some(other) => match other.strip_prefix("fixture:") {
                Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
                _ => {
                    return UsageSnafu {
                        message: format!("unknown producer {other}"),
                    }
                    .fail();
                }
            },
        },
    };
    args.finish()?;
    Ok(serve)
}

/// Parses a tenant class name.
fn parse_class(text: &str) -> Result<TenantClass, Error> {
    match text {
        "operator" => Ok(TenantClass::Operator),
        "agent" => Ok(TenantClass::Agent),
        "sub-agent" => Ok(TenantClass::SubAgent),
        other => UsageSnafu {
            message: format!("unknown tenant class {other}"),
        }
        .fail(),
    }
}

/// Parses 64 hexadecimal digits into a 32-byte key.
fn parse_key(text: &str) -> Result<[u8; 32], Error> {
    let bad = || {
        UsageSnafu {
            message: "a verifying key is 64 hexadecimal digits",
        }
        .build()
    };
    // WHY check every digit first: `from_str_radix` accepts a leading
    // `+`, so `+f` would parse as a byte.
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let mut key = [0_u8; 32];
    for (byte, pair) in key.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_utf8| bad())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_digit| bad())?;
    }
    Ok(key)
}

/// Runs `command`, writing its result to standard output.
///
/// # Errors
///
/// [`Error::Store`] from the custody store, [`Error::Usage`] for an
/// inconsistent request, or any error `serve` meets.
pub fn run(command: Command) -> Result<(), Error> {
    match command {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::Keygen { path } => RootKey::generate(&path).map(drop).context(StoreSnafu),
        Command::Init { store, root_key } => {
            let root = RootKey::load(&root_key).context(StoreSnafu)?;
            StoreOptions::new(store, daemon_clock())
                .create(&root)
                .map(drop)
                .context(StoreSnafu)
        }
        Command::TenantAdd(add) => tenant_add(&add),
        Command::Serve(serve) => serve::serve(&serve),
    }
}

/// Opens the store at `path` under the key at `root_key`.
pub(crate) fn open_store(
    path: &Path,
    root_key: &Path,
    clock: Arc<dyn epitrope::Clock + Send + Sync>,
) -> Result<phylake::Store, Error> {
    let root = RootKey::load(root_key).context(StoreSnafu)?;
    StoreOptions::new(path, clock)
        .open(&root)
        .context(StoreSnafu)
}

fn tenant_add(add: &TenantAdd) -> Result<(), Error> {
    let clock = daemon_clock();
    let store = open_store(&add.store, &add.root_key, Arc::clone(&clock))?;
    let mut registration = TenantRegistration::new(add.tenant, add.class, add.verifying_key);
    registration.bound_uids.clone_from(&add.uids);
    registration.parent = add.parent;
    store.register_tenant(&registration).context(StoreSnafu)?;
    println!("tenant {}", add.tenant);
    if add.class != TenantClass::Operator {
        return Ok(());
    }
    let now = clock.now().unix_millis();
    let grant = match add.root_grant {
        Some(grant) => grant,
        None => GrantId::from_bytes(crate::orchestrator::fresh_id(clock.now())?),
    };
    let targets = if add.targets.is_empty() {
        vec!["*".to_owned()]
    } else {
        add.targets.clone()
    };
    let not_before = add.not_before.unwrap_or(now);
    let validity = (
        Timestamp::from_unix_millis(not_before),
        Timestamp::from_unix_millis(
            add.expires_at
                .unwrap_or_else(|| not_before.saturating_add(DEFAULT_LIFETIME_MS)),
        ),
    );
    let mut root = RootGrant::new(
        grant,
        add.tenant,
        Capability::ALL.iter().copied().collect(),
        targets,
        validity,
        add.max_depth.unwrap_or(DEFAULT_MAX_DEPTH),
    );
    root.audit_scope = default_audit_scope(add.class);
    store.install_root_grant(&root).context(StoreSnafu)?;
    println!("grant {grant}");
    Ok(())
}

#[cfg(test)]
mod tests;
