use epitrope::Clock as _;

use super::SystemClock;

#[test]
fn system_clock_reads_after_2020() {
    // 2020-01-01T00:00:00Z in Unix milliseconds.
    let floor = 1_577_836_800_000;

    assert!(
        SystemClock.now().unix_millis() > floor,
        "the system clock reads a current time"
    );
}

#[cfg(feature = "test-clock")]
#[test]
fn file_clock_reads_the_file_and_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("clock");
    let clock = super::FileClock::new(&path);
    let missing = clock.now().unix_millis();
    std::fs::write(&path, "1234\n")?;
    let set = clock.now().unix_millis();
    std::fs::write(&path, "not a time")?;
    let garbled = clock.now().unix_millis();

    assert_eq!(missing, i64::MAX, "a missing file expires everything");
    assert_eq!(set, 1234, "the file's value is the time");
    assert_eq!(garbled, i64::MAX, "an unparsable file expires everything");
    Ok(())
}
