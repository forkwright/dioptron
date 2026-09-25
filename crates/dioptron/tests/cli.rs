//! Process-level checks of the `dioptron` command line.

// NOTE: clippy's tests_outside_test_module (denied workspace-wide) also
// applies to integration test crates, hence the module wrapper.
#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::{Command, Output};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn dioptron(args: &[&str]) -> std::io::Result<Output> {
        Command::new(env!("CARGO_BIN_EXE_dioptron"))
            .args(args)
            .env_remove("DIOPTRON_FAILPOINT")
            .env_remove("DIOPTRON_TEST_CLOCK")
            .output()
    }

    fn text(path: &Path) -> String {
        path.display().to_string()
    }

    #[test]
    fn no_arguments_prints_usage() -> TestResult {
        let output = dioptron(&[])?;

        assert_eq!(output.status.code(), Some(0), "bare invocation is help");
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.starts_with("usage:"), "help prints the usage text");
        Ok(())
    }

    #[test]
    fn unknown_command_is_a_usage_error() -> TestResult {
        let output = dioptron(&["launch"])?;

        assert_eq!(output.status.code(), Some(2), "a usage error exits 2");
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stderr.starts_with("dioptron: unknown command launch"),
            "stderr names the problem: {stderr}"
        );
        Ok(())
    }

    #[test]
    fn keygen_refuses_to_overwrite_a_key() -> TestResult {
        let dir = tempfile::tempdir()?;
        let key = dir.path().join("root.key");

        let first = dioptron(&["keygen", &text(&key)])?;
        let second = dioptron(&["keygen", &text(&key)])?;

        assert!(first.status.success(), "keygen writes a key");
        assert_eq!(std::fs::read(&key)?.len(), 32, "a 32-byte root key");
        assert_eq!(second.status.code(), Some(1), "an existing key is kept");
        Ok(())
    }

    #[test]
    fn serve_fails_closed_on_a_wrong_or_missing_root_key() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (key, other, store) = (
            dir.path().join("root.key"),
            dir.path().join("other.key"),
            dir.path().join("store"),
        );
        let sockets = dir.path().join("sock");
        assert!(
            dioptron(&["keygen", &text(&key)])?.status.success(),
            "keygen"
        );
        assert!(
            dioptron(&["keygen", &text(&other)])?.status.success(),
            "keygen"
        );
        let init = dioptron(&["init", "--store", &text(&store), "--root-key", &text(&key)])?;
        assert!(init.status.success(), "init creates the store");

        for root in [&other, &dir.path().join("absent.key")] {
            let output = dioptron(&[
                "serve",
                "--store",
                &text(&store),
                "--root-key",
                &text(root),
                "--socket-dir",
                &text(&sockets),
            ])?;
            assert_eq!(
                output.status.code(),
                Some(1),
                "a locked store refuses to serve"
            );
            assert!(
                !sockets.join("dioptron.sock").exists(),
                "nothing is bound before the store opens"
            );
        }
        Ok(())
    }

    #[test]
    fn tenant_add_refuses_a_root_grant_for_an_agent() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (key, store) = (dir.path().join("root.key"), dir.path().join("store"));
        assert!(
            dioptron(&["keygen", &text(&key)])?.status.success(),
            "keygen"
        );
        assert!(
            dioptron(&["init", "--store", &text(&store), "--root-key", &text(&key)])?
                .status
                .success(),
            "init"
        );

        let output = dioptron(&[
            "tenant",
            "add",
            "--store",
            &text(&store),
            "--root-key",
            &text(&key),
            "--tenant",
            "01J8K7R3V9ZQ4N5M6P7S8TNT0B",
            "--class",
            "agent",
            "--verifying-key",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "--uid",
            "1000",
            "--root-grant",
            "01J8K7R3V9ZQ4N5M6P7S8GRN0B",
        ])?;

        assert_eq!(
            output.status.code(),
            Some(2),
            "only an operator gets a root grant"
        );
        Ok(())
    }
}
