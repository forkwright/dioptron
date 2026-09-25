//! `--flag value` pairs.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use snafu::OptionExt as _;

use crate::error::{Error, UsageSnafu};

/// The flags of one command, consumed as they are read.
pub(super) struct Args {
    values: BTreeMap<String, Vec<String>>,
}

impl Args {
    /// Pairs every flag with its value. Only the flags in `repeatable` may
    /// appear more than once.
    pub(super) fn parse(words: &[String], repeatable: &[&str]) -> Result<Self, Error> {
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut words = words.iter();
        while let Some(flag) = words.next() {
            if !flag.starts_with("--") {
                return UsageSnafu {
                    message: format!("expected a flag, found {flag}"),
                }
                .fail();
            }
            // WHY refuse a value that looks like a flag: `--store --root-key k`
            // is a missing value, not a store named `--root-key`.
            let value = words
                .next()
                .filter(|value| !value.starts_with("--"))
                .context(UsageSnafu {
                    message: format!("{flag} needs a value"),
                })?;
            let entry = values.entry(flag.clone()).or_default();
            if !entry.is_empty() && !repeatable.contains(&flag.as_str()) {
                return UsageSnafu {
                    message: format!("{flag} given twice"),
                }
                .fail();
            }
            entry.push(value.clone());
        }
        Ok(Self { values })
    }

    /// Takes the one value of `flag`, if given.
    pub(super) fn optional(&mut self, flag: &str) -> Option<String> {
        self.values.remove(flag).and_then(|mut values| values.pop())
    }

    /// Takes the one value of `flag`.
    pub(super) fn required(&mut self, flag: &str) -> Result<String, Error> {
        self.optional(flag).context(UsageSnafu {
            message: format!("{flag} is required"),
        })
    }

    /// Takes the one value of `flag` as a path.
    pub(super) fn path(&mut self, flag: &str) -> Result<PathBuf, Error> {
        self.required(flag).map(PathBuf::from)
    }

    /// Takes and parses the one value of `flag`.
    pub(super) fn parsed<T: FromStr>(&mut self, flag: &str) -> Result<T, Error> {
        let text = self.required(flag)?;
        parse_value(flag, &text)
    }

    /// Takes and parses the one value of `flag`, if given.
    pub(super) fn optional_parsed<T: FromStr>(&mut self, flag: &str) -> Result<Option<T>, Error> {
        self.optional(flag)
            .map(|text| parse_value(flag, &text))
            .transpose()
    }

    /// Takes every value of `flag`.
    pub(super) fn all(&mut self, flag: &str) -> Vec<String> {
        self.values.remove(flag).unwrap_or_default()
    }

    /// Takes and parses every value of `flag`.
    pub(super) fn all_parsed<T: FromStr>(&mut self, flag: &str) -> Result<Vec<T>, Error> {
        self.all(flag)
            .iter()
            .map(|text| parse_value(flag, text))
            .collect()
    }

    /// Fails when a flag was given that the command does not take.
    pub(super) fn finish(self) -> Result<(), Error> {
        match self.values.keys().next() {
            Some(flag) => UsageSnafu {
                message: format!("unknown flag {flag}"),
            }
            .fail(),
            None => Ok(()),
        }
    }
}

/// Parses `text`, the value of `flag`.
fn parse_value<T: FromStr>(flag: &str, text: &str) -> Result<T, Error> {
    text.parse().ok().context(UsageSnafu {
        message: format!("{flag}: cannot parse {text}"),
    })
}
