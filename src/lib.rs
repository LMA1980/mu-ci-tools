//! mu-ci-tools: Compile-time modular `ToolAdapter` trait registry for typed CI/CD tools.

pub mod adapter;
pub mod adapters;
pub mod error;
pub mod registry;
pub mod sanitize;

pub use adapter::{
    ParsedBenchmark, ParsedTestCase, SandboxProfileRequirement, TestCaseStatus, ToolAdapter,
    ToolExecutionMetrics, ToolInvocation,
};
pub use adapters::{
    CargoAuditAdapter, CargoBenchAdapter, CargoBuildAdapter, CargoClippyAdapter, CargoFmtAdapter,
    CargoLlvmCovAdapter, CargoMiriAdapter, CargoPublishAdapter, CargoTestAdapter, MdformatAdapter,
    TrunkAdapter,
};
pub use error::{MetricParseError, ToolBuildError, ToolError, ToolValidationError};
pub use registry::ToolRegistry;
pub use sanitize::{
    is_prohibited_shell_wrapper, validate_invocation_base, validate_path_within_working_dir,
    validate_safe_arg, validate_safe_relative_path,
};

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::Arc;

    use super::*;

    struct MockEchoTool;

    impl ToolAdapter for MockEchoTool {
        fn name(&self) -> &'static str {
            "mock-tool"
        }

        fn validate(&self, inv: &ToolInvocation) -> Result<(), ToolValidationError> {
            validate_invocation_base(inv)?;
            for arg in &inv.args {
                if arg != "--check" && arg != "--all" {
                    return Err(ToolValidationError::UnsupportedFlag {
                        tool: self.name().to_string(),
                        flag: arg.clone(),
                    });
                }
            }
            Ok(())
        }

        fn build_argv(&self, inv: &ToolInvocation) -> Result<Vec<OsString>, ToolBuildError> {
            self.validate(inv)?;
            let mut argv = vec![OsString::from("mock-bin")];
            for arg in &inv.args {
                argv.push(OsString::from(arg));
            }
            Ok(argv)
        }

        fn sandbox_profile(&self, _inv: &ToolInvocation) -> SandboxProfileRequirement {
            SandboxProfileRequirement {
                allow_network: false,
                allowed_egress_hosts: Vec::new(),
                writable_dirs: vec!["target".to_string()],
                readable_dirs: vec![".".to_string()],
                exec_binaries: vec!["mock-bin".to_string()],
                required_memlock_kb: 0,
            }
        }

        fn parse_metrics(
            &self,
            stdout: &[u8],
            _stderr: &[u8],
            exit_code: i32,
        ) -> Result<ToolExecutionMetrics, MetricParseError> {
            let text = std::str::from_utf8(stdout).map_err(|_| MetricParseError::InvalidUtf8)?;
            Ok(ToolExecutionMetrics {
                duration_ms: 12,
                exit_code,
                tests_passed: Some(u32::from(text.contains("ok"))),
                tests_failed: Some(0),
                warnings_count: Some(0),
                ..ToolExecutionMetrics::default()
            })
        }
    }

    #[test]
    fn test_adapter_trait_and_registry_dispatch() {
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(MockEchoTool));

        assert_eq!(registry.tool_names(), vec!["mock-tool"]);

        let inv = ToolInvocation::new("mock-tool", ["--check", "--all"]);
        let (argv, profile) = registry
            .validate_and_build(&inv)
            .expect("valid invocation should succeed");

        assert_eq!(
            argv,
            vec![
                OsString::from("mock-bin"),
                OsString::from("--check"),
                OsString::from("--all"),
            ]
        );
        assert!(!profile.allow_network);
        assert_eq!(profile.exec_binaries, vec!["mock-bin".to_string()]);

        let adapter = registry
            .get("mock-tool")
            .expect("mock-tool should be registered");
        let metrics = adapter
            .parse_metrics(b"test result: ok", b"", 0)
            .expect("metrics should parse");
        assert_eq!(metrics.exit_code, 0);
        assert_eq!(metrics.tests_passed, Some(1));
    }

    #[test]
    fn test_registry_rejects_unregistered_and_shell_tools() {
        let registry = ToolRegistry::with_builtin_adapters();

        for forbidden in ["bash", "sh", "python", "curl", "wget", "nc", "unknown-tool"] {
            let err = registry
                .get(forbidden)
                .expect_err("unregistered tool must fail lookup");
            assert_eq!(err, ToolValidationError::UnknownTool(forbidden.to_string()));
        }

        let python_inv = ToolInvocation::new("python", ["-V"]);
        assert_eq!(
            registry.validate_and_build(&python_inv),
            Err(ToolError::Validation(ToolValidationError::UnknownTool(
                "python".to_string()
            )))
        );

        let bash_inv = ToolInvocation::new("bash", ["-c", "echo pwned"]);
        assert_eq!(
            registry.validate_and_build(&bash_inv),
            Err(ToolError::Validation(
                ToolValidationError::ProhibitedShellWrapper("bash".to_string())
            ))
        );
    }

    #[test]
    fn test_validate_safe_arg_forbids_shell_expansion_and_wrappers() {
        assert!(validate_safe_arg("--workspace").is_ok());
        assert!(validate_safe_arg("--target").is_ok());
        assert!(validate_safe_arg("riscv64gc-unknown-linux-gnu").is_ok());

        // Shell metacharacters and operators
        for (bad_arg, expected_token) in [
            ("foo;rm -rf /", ";"),
            ("foo | cat /etc/passwd", "|"),
            ("foo && bar", "&&"),
            ("foo || bar", "||"),
            ("foo &", "&"),
            ("`id`", "`"),
            ("$(whoami)", "$("),
            ("${IFS}", "${"),
            ("foo > /tmp/out", ">"),
            ("foo >> /tmp/out", ">>"),
            ("foo < /etc/shadow", "<"),
            ("foo << EOF", "<<"),
        ] {
            assert_eq!(
                validate_safe_arg(bad_arg),
                Err(ToolValidationError::ShellMetacharacterDetected {
                    arg: bad_arg.to_string(),
                    token: expected_token.to_string(),
                })
            );
        }

        // Control characters
        for ctrl in ["foo\nbar", "foo\rbar", "foo\0bar", "foo\x1bbar", "foo\x7f"] {
            assert_eq!(
                validate_safe_arg(ctrl),
                Err(ToolValidationError::ControlCharacterDetected(
                    ctrl.to_string()
                ))
            );
        }

        // Prohibited shell wrappers and execution flags
        for wrapper in [
            "bash",
            "sh",
            "zsh",
            "dash",
            "fish",
            "ksh",
            "csh",
            "tcsh",
            "cmd",
            "powershell",
            "pwsh",
            "eval",
            "exec",
            "-c",
            "/bin/sh",
            "/bin/bash",
            "/usr/bin/env",
            "build.rustc-wrapper=/bin/sh",
            "--config",
            "--config=build.rustc-wrapper='sh'",
        ] {
            assert_eq!(
                validate_safe_arg(wrapper),
                Err(ToolValidationError::ProhibitedShellWrapper(
                    wrapper.to_string()
                ))
            );
        }
    }

    #[test]
    fn test_validate_safe_relative_path_and_working_dir_containment() {
        assert!(validate_safe_relative_path("README.md").is_ok());
        assert!(validate_safe_relative_path("src/lib.rs").is_ok());
        assert!(validate_safe_relative_path("docs/architecture/overview.md").is_ok());

        for abs in ["/etc/passwd", "/tmp/evil", "\\Windows\\System32", "C:\\foo"] {
            assert_eq!(
                validate_safe_relative_path(abs),
                Err(ToolValidationError::AbsolutePathForbidden(abs.to_string()))
            );
        }

        for traversal in [
            "..",
            "../secret",
            "docs/../../etc/passwd",
            "a/b/..",
            "a\\..\\b",
        ] {
            assert_eq!(
                validate_safe_relative_path(traversal),
                Err(ToolValidationError::PathTraversalDetected(
                    traversal.to_string()
                ))
            );
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let sub = temp.path().join("docs");
        std::fs::create_dir_all(&sub).expect("create docs dir");
        let file_path = sub.join("guide.md");
        std::fs::write(&file_path, "# Guide\n").expect("write guide.md");

        assert!(validate_path_within_working_dir(temp.path(), "docs/guide.md").is_ok());
        assert_eq!(
            validate_path_within_working_dir(temp.path(), "../outside.md"),
            Err(ToolValidationError::PathTraversalDetected(
                "../outside.md".to_string()
            ))
        );
    }

    #[test]
    fn test_validate_invocation_base_rejects_bad_env_and_working_dir() {
        let bad_env = ToolInvocation::new("cargo-test", ["--workspace"])
            .with_env("LD_PRELOAD", "/tmp/evil.so");
        assert_eq!(
            validate_invocation_base(&bad_env),
            Err(ToolValidationError::ProhibitedShellWrapper(
                "LD_PRELOAD".to_string()
            ))
        );

        let bad_wrapper_env =
            ToolInvocation::new("cargo-test", ["--workspace"]).with_env("RUSTC_WRAPPER", "/bin/sh");
        assert_eq!(
            validate_invocation_base(&bad_wrapper_env),
            Err(ToolValidationError::ProhibitedShellWrapper(
                "RUSTC_WRAPPER".to_string()
            ))
        );

        let bad_wd =
            ToolInvocation::new("cargo-test", ["--workspace"]).with_working_dir("../escape");
        assert_eq!(
            validate_invocation_base(&bad_wd),
            Err(ToolValidationError::PathTraversalDetected(
                "../escape".to_string()
            ))
        );
    }
}
