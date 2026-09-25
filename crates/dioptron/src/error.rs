//! The crate error type.

use std::io;
use std::path::PathBuf;

use snafu::Snafu;

/// Errors that stop the daemon from starting or serving.
///
/// Per-connection failures never surface here: the server answers them on
/// the wire (a single `Fault` frame where possible) and closes that one
/// connection.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum Error {
    /// The socket path names no parent directory.
    #[snafu(display("socket path {} has no parent directory", path.display()))]
    NoSocketParent {
        /// The configured socket path.
        path: PathBuf,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The socket's parent directory could not be created or inspected.
    #[snafu(display("cannot prepare socket directory {}", path.display()))]
    SocketDir {
        /// The directory.
        path: PathBuf,
        /// The filesystem error.
        source: io::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The socket's parent is not a directory the daemon owns with no group
    /// or other permission bits.
    #[snafu(display(
        "socket directory {} must be a directory owned by the daemon with mode 0700, found mode {mode:o} owner {owner}",
        path.display()
    ))]
    InsecureSocketDir {
        /// The directory.
        path: PathBuf,
        /// Its full mode, file type bits included.
        mode: u32,
        /// Its owning user id.
        owner: u32,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// Something other than a socket owned by the directory's owner sits at
    /// the socket path.
    #[snafu(display("socket path {} is occupied by something other than the daemon's socket", path.display()))]
    SocketPathOccupied {
        /// The socket path.
        path: PathBuf,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A live listener answers at the socket path, or another daemon holds
    /// the socket directory's lock.
    #[snafu(display("socket path {} is in use by another daemon", path.display()))]
    SocketInUse {
        /// The socket path.
        path: PathBuf,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The existing socket path could not be inspected, probed, or removed.
    #[snafu(display("cannot inspect or clear socket path {}", path.display()))]
    InspectSocket {
        /// The socket path.
        path: PathBuf,
        /// The filesystem or socket error.
        source: io::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The socket could not be bound, restricted to mode 0600, or
    /// registered with the runtime.
    #[snafu(display("cannot bind socket {}", path.display()))]
    Bind {
        /// The socket path.
        path: PathBuf,
        /// The socket error.
        source: io::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The operating system random source failed while deriving the
    /// handshake's dummy verifying key.
    #[snafu(display("the operating system random source failed"))]
    RandomSource {
        /// The random source error.
        source: getrandom::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A shutdown signal handler could not be installed.
    #[snafu(display("cannot install a shutdown signal handler"))]
    Signal {
        /// The registration error.
        source: io::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A fixture script or one of the files it names cannot be read.
    #[snafu(display("cannot read fixture {}", path.display()))]
    FixtureIo {
        /// The file.
        path: PathBuf,
        /// The filesystem error.
        source: io::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A fixture script line does not parse.
    #[snafu(display("fixture {} line {line}: {reason}", path.display()))]
    FixtureSyntax {
        /// The script.
        path: PathBuf,
        /// The 1-based line number; 0 for the path itself.
        line: usize,
        /// What is wrong with it.
        reason: String,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The custody store refused or failed an operation.
    #[snafu(display("custody store operation failed"))]
    Store {
        /// The store error.
        #[snafu(source(from(phylake::Error, Box::new)))]
        source: Box<phylake::Error>,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// An authorization decision could not be made.
    #[snafu(display("authorization decision failed"))]
    Authz {
        /// The authorization error.
        #[snafu(source(from(epitrope::Error, Box::new)))]
        source: Box<epitrope::Error>,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A read through the store's authorization view failed.
    #[snafu(display("authorization view read failed"))]
    View {
        /// The view error.
        #[snafu(source(from(epitrope::ViewError, Box::new)))]
        source: Box<epitrope::ViewError>,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A contract value could not be encoded.
    #[snafu(display("contract encoding failed"))]
    Encode {
        /// The contract error.
        #[snafu(source(from(syntheke::Error, Box::new)))]
        source: Box<syntheke::Error>,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// A blocking store task panicked or was cancelled.
    #[snafu(display("a store task did not complete"))]
    Task {
        /// The join error.
        #[snafu(source(from(tokio::task::JoinError, Box::new)))]
        source: Box<tokio::task::JoinError>,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The command line is not valid.
    #[snafu(display("{message}"))]
    Usage {
        /// What is wrong.
        message: String,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },

    /// The async runtime could not be built.
    #[snafu(display("cannot start the async runtime"))]
    Runtime {
        /// The runtime error.
        source: io::Error,
        /// Where the error was raised.
        #[snafu(implicit)]
        location: snafu::Location,
    },
}
