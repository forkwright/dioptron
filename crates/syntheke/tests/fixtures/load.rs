//! Reading fixture files and parsing their values.

use std::path::Path;
use std::str::FromStr;

use syntheke::{Error, IdempotencyKey, Timestamp};
use toml::{Table, Value};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/contract/fixtures");

/// One fixture file: its stem and its three tables.
pub(crate) struct Fixture {
    pub(crate) name: String,
    pub(crate) meta: Table,
    pub(crate) request: Table,
    pub(crate) expected: Table,
}

fn table(root: &Table, key: &str, name: &str) -> TestResult<Table> {
    match root.get(key) {
        Some(Value::Table(inner)) => Ok(inner.clone()),
        _ => Err(format!("{name}: missing [{key}] table").into()),
    }
}

/// Every `*.toml` fixture, sorted by name. A missing directory is an error.
pub(crate) fn load() -> TestResult<Vec<Fixture>> {
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

/// The fixture called `name`.
pub(crate) fn fixture(name: &str) -> TestResult<Fixture> {
    load()?
        .into_iter()
        .find(|f| f.name == name)
        .ok_or_else(|| format!("fixture {name} missing").into())
}

/// Whether the whitespace-separated `list` holds `word` exactly.
pub(crate) fn has_word(list: &str, word: &str) -> bool {
    list.split_whitespace().any(|item| item == word)
}

pub(crate) fn text<'a>(t: &'a Table, key: &str) -> Option<&'a str> {
    t.get(key).and_then(Value::as_str)
}

pub(crate) fn need_text<'a>(t: &'a Table, key: &str, name: &str) -> TestResult<&'a str> {
    text(t, key).ok_or_else(|| format!("{name}: missing string `{key}`").into())
}

pub(crate) fn int<T: TryFrom<i64>>(t: &Table, key: &str, name: &str) -> TestResult<Option<T>> {
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

pub(crate) fn flag(t: &Table, key: &str) -> Option<bool> {
    t.get(key).and_then(Value::as_bool)
}

pub(crate) fn strings<'a>(t: &'a Table, key: &str, name: &str) -> TestResult<Vec<&'a str>> {
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

pub(crate) fn id<T>(t: &Table, key: &str, name: &str) -> TestResult<Option<T>>
where
    T: FromStr<Err = Error> + ToString,
{
    text(t, key)
        .map(|value| parse_id(value, key, name))
        .transpose()
}

pub(crate) fn need_id<T>(t: &Table, key: &str, name: &str) -> TestResult<T>
where
    T: FromStr<Err = Error> + ToString,
{
    id(t, key, name)?.ok_or_else(|| format!("{name}: missing id `{key}`").into())
}

/// Parses a fixture ULID and checks it displays back to the same text.
pub(crate) fn parse_id<T>(value: &str, key: &str, name: &str) -> TestResult<T>
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

pub(crate) fn named<T>(
    value: &str,
    parse: fn(&str) -> Option<T>,
    what: &str,
    name: &str,
) -> TestResult<T> {
    parse(value).ok_or_else(|| format!("{name}: {value:?} is not a contract {what}").into())
}

pub(crate) fn hex(value: &str, name: &str) -> TestResult<Vec<u8>> {
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
pub(crate) fn rfc3339(value: &str, name: &str) -> TestResult<Timestamp> {
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

pub(crate) fn idempotency_key(t: &Table, name: &str) -> TestResult<Option<IdempotencyKey>> {
    text(t, "idempotency_key")
        .map(|value| Ok(IdempotencyKey::new(hex(value, name)?)?))
        .transpose()
}
