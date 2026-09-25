//! Process-level checks of the `dioptron` binary.

// NOTE: clippy's tests_outside_test_module (denied workspace-wide) also
// applies to integration test crates, hence the module wrapper.
#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn exits_failure_when_no_command_is_implemented() -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_dioptron")).output()?;

        assert_eq!(
            output.status.code(),
            Some(1),
            "a daemon with no commands must not report success"
        );
        let stderr = String::from_utf8(output.stderr)?;
        let expected = format!(
            "dioptron {}: no commands are implemented yet\n",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(stderr, expected, "stderr must name the binary and version");
        assert!(output.stdout.is_empty(), "stdout must stay empty");
        Ok(())
    }
}
