//! A scripted producer for tests and demonstrations.
//!
//! [`FixtureProducer`] answers each target with the outcome its script
//! names and counts every call. It performs no acquisition: its envelopes
//! are bytes read from files when the script loads.
//!
//! # Script format
//!
//! One line per target, fields separated by a tab; blank lines and lines
//! starting with `#` are skipped. File names are relative to the script's
//! directory.
//!
//! ```text
//! <target>  deliver            <envelope-file> <schema-id> <revision> <fingerprint> <text-file | ->
//! <target>  deliver-on-cancel  <envelope-file> <schema-id> <revision> <fingerprint> <text-file | ->
//! <target>  unavailable        <contacted: true | false>
//! <target>  transfer           <TransferClass name>
//! <target>  extraction         <ExtractionClass name>
//! <target>  stall              <effect-started: true | false>
//! ```
//!
//! `deliver` returns the output at once. `deliver-on-cancel` waits for the
//! cancel signal or the deadline and then returns the output, modeling an
//! acquisition that completed while the call was being cancelled. `stall`
//! waits the same way and reports `Cancelled`. A target with no line is
//! `Unavailable { contacted: false }`.
//!
//! With a call log, each call appends the target and a newline to the log
//! before it answers, so another process can count calls.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use snafu::{OptionExt as _, ResultExt as _};
use syntheke::{ExtractionClass, SourceRef, TransferClass};
use tokio::time::{Instant, sleep_until};
use tracing::warn;

use crate::cancel::CancelSignal;
use crate::error::{Error, FixtureIoSnafu, FixtureSyntaxSnafu};
use crate::producer::{AcquireRequest, Producer, ProducerError, ProducerOutput};

/// What the fixture does for one target.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Script {
    /// Return this output at once.
    Deliver(ProducerOutput),
    /// Wait for the cancel signal or the deadline, then return this output.
    DeliverOnCancel(ProducerOutput),
    /// Return this failure at once.
    Fail(ProducerError),
    /// Wait for the cancel signal or the deadline, then report `Cancelled`.
    Stall {
        /// Whether the reported cancellation says the effect had started.
        effect_started: bool,
    },
}

/// A deterministic producer that replays [`Script`]s by target.
#[derive(Debug, Default)]
pub struct FixtureProducer {
    scripts: HashMap<String, Script>,
    calls: AtomicU64,
    call_log: Option<PathBuf>,
}

impl FixtureProducer {
    /// A producer with no scripts: every target is unavailable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces the script for `target`.
    #[must_use]
    pub fn with(mut self, target: impl Into<String>, script: Script) -> Self {
        self.scripts.insert(target.into(), script);
        self
    }

    /// Appends one line per call to `path`.
    #[must_use]
    pub fn with_call_log(mut self, path: impl Into<PathBuf>) -> Self {
        self.call_log = Some(path.into());
        self
    }

    /// Loads a script file (see the module docs for the format).
    ///
    /// # Errors
    ///
    /// [`Error::FixtureIo`] when a file cannot be read,
    /// [`Error::FixtureSyntax`] for a malformed line.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).context(FixtureIoSnafu { path })?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let mut producer = Self::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let line_no = index.saturating_add(1);
            let (target, script) = parse_line(base, line).map_err(|reason| {
                FixtureSyntaxSnafu {
                    path,
                    line: line_no,
                    reason,
                }
                .build()
            })?;
            producer = producer.with(target, script);
        }
        Ok(producer)
    }

    /// Calls answered so far by this instance.
    #[must_use]
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// Counts one call and appends it to the call log.
    fn record(&self, target: &str) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Some(path) = &self.call_log else {
            return;
        };
        let appended = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| writeln!(file, "{target}"));
        if let Err(error) = appended {
            warn!(%error, "fixture call log not written");
        }
    }
}

impl Producer for FixtureProducer {
    fn acquire(
        &self,
        request: AcquireRequest,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> impl Future<Output = Result<ProducerOutput, ProducerError>> + Send {
        // NOTE: the call log append is one short write; it runs before the
        // outcome so a daemon aborted after this point still counts it.
        self.record(&request.target);
        let script = self.scripts.get(&request.target).cloned();
        let max_transfer = request.limits.max_transfer_bytes;
        async move {
            let result = match script {
                None => Err(ProducerError::Unavailable { contacted: false }),
                Some(Script::Deliver(output)) => Ok(output),
                Some(Script::Fail(error)) => Err(error),
                Some(Script::DeliverOnCancel(output)) => {
                    stopped(&cancel, deadline).await;
                    Ok(output)
                }
                Some(Script::Stall { effect_started }) => {
                    stopped(&cancel, deadline).await;
                    Err(ProducerError::Cancelled { effect_started })
                }
            };
            result.and_then(|output| within_transfer(output, max_transfer))
        }
    }
}

/// Refuses an envelope over the caller's transfer bound, as a real
/// producer stops a transfer at its limit.
fn within_transfer(
    output: ProducerOutput,
    max_transfer: Option<u64>,
) -> Result<ProducerOutput, ProducerError> {
    let len = u64::try_from(output.envelope.len()).unwrap_or(u64::MAX);
    match max_transfer {
        Some(max) if len > max => Err(ProducerError::Transfer {
            class: TransferClass::TooLarge,
        }),
        _ => Ok(output),
    }
}

/// Completes when `cancel` fires or `deadline` passes.
async fn stopped(cancel: &CancelSignal, deadline: Instant) {
    tokio::select! {
        () = cancel.cancelled() => {}
        () = sleep_until(deadline) => {}
    }
}

/// Parses one script line into its target and script.
fn parse_line(base: &Path, line: &str) -> Result<(String, Script), String> {
    let fields: Vec<&str> = line.split('\t').collect();
    let [target, verb, rest @ ..] = fields.as_slice() else {
        return Err("expected a target and a verb".to_owned());
    };
    let script = match (*verb, rest) {
        ("deliver", args) => Script::Deliver(parse_output(base, args)?),
        ("deliver-on-cancel", args) => Script::DeliverOnCancel(parse_output(base, args)?),
        ("unavailable", [contacted]) => Script::Fail(ProducerError::Unavailable {
            contacted: parse_bool(contacted)?,
        }),
        ("transfer", [class]) => Script::Fail(ProducerError::Transfer {
            class: TransferClass::from_name(class)
                .ok_or_else(|| format!("unknown transfer class {class}"))?,
        }),
        ("extraction", [class]) => Script::Fail(ProducerError::Extraction {
            class: ExtractionClass::from_name(class)
                .ok_or_else(|| format!("unknown extraction class {class}"))?,
        }),
        ("stall", [started]) => Script::Stall {
            effect_started: parse_bool(started)?,
        },
        (verb, _) => return Err(format!("unknown verb or wrong field count for {verb}")),
    };
    Ok(((*target).to_owned(), script))
}

/// Parses the fields of a delivering line.
fn parse_output(base: &Path, args: &[&str]) -> Result<ProducerOutput, String> {
    let [envelope, schema_id, revision, fingerprint, text] = args else {
        return Err("a deliver line takes five fields after the verb".to_owned());
    };
    let envelope = read(base, envelope)?;
    let text_view = match *text {
        "-" => None,
        file => Some(String::from_utf8(read(base, file)?).map_err(|_utf8| "text is not UTF-8")?),
    };
    let source = SourceRef {
        fingerprint: (*fingerprint).to_owned(),
        schema_id: (*schema_id).to_owned(),
        producer_revision: (*revision).to_owned(),
    };
    Ok(ProducerOutput::new(envelope, source, text_view))
}

/// Reads `name` relative to `base`.
fn read(base: &Path, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(base.join(name)).map_err(|error| format!("cannot read {name}: {error}"))
}

/// Parses `true` or `false`.
fn parse_bool(text: &str) -> Result<bool, String> {
    match text {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("expected true or false, found {other}")),
    }
}

/// The call log of a script: the script's path with `.calls` appended.
///
/// # Errors
///
/// [`Error::FixtureSyntax`] when the path names no file.
pub(crate) fn call_log_for(script: &Path) -> Result<PathBuf, Error> {
    let name = script
        .file_name()
        .context(FixtureSyntaxSnafu {
            path: script,
            line: 0_usize,
            reason: "the script path names no file".to_owned(),
        })?
        .to_string_lossy()
        .into_owned();
    Ok(script.with_file_name(format!("{name}.calls")))
}

#[cfg(test)]
mod tests;
