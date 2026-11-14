//! Core `ToolAdapter` trait and structured invocation, sandbox, and metrics types.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{MetricParseError, ToolBuildError, ToolValidationError};

/// Expected scalar or list kind for a declared [`ToolParamSpec`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ToolParamKind {
    /// Single UTF-8 string value.
    String,
    /// Boolean toggle value.
    Bool,
    /// Signed 64-bit integer value.
    Integer,
    /// Ordered list of UTF-8 string values.
    StringList,
}

/// Typed parameter value passed cleanly in [`ToolInvocation::params`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum ToolParamValue {
    /// UTF-8 scalar string parameter.
    String(String),
    /// Boolean toggle parameter.
    Bool(bool),
    /// Signed 64-bit integer parameter.
    Integer(i64),
    /// Ordered list of UTF-8 string values.
    StringList(Vec<String>),
}

impl ToolParamValue {
    /// Return the [`ToolParamKind`] corresponding to this value variant.
    #[must_use]
    pub const fn kind(&self) -> ToolParamKind {
        match self {
            Self::String(_) => ToolParamKind::String,
            Self::Bool(_) => ToolParamKind::Bool,
            Self::Integer(_) => ToolParamKind::Integer,
            Self::StringList(_) => ToolParamKind::StringList,
        }
    }

    /// Borrow the inner string slice if this value is [`ToolParamValue::String`].
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Extract the boolean value if this value is [`ToolParamValue::Bool`].
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Extract the signed 64-bit integer if this value is [`ToolParamValue::Integer`].
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Extract a non-negative integer as `u64` if this value is a non-negative [`ToolParamValue::Integer`].
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Integer(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }

    /// Borrow the inner string slice vector if this value is [`ToolParamValue::StringList`].
    #[must_use]
    pub fn as_string_list(&self) -> Option<&[String]> {
        match self {
            Self::StringList(list) => Some(list.as_slice()),
            _ => None,
        }
    }
}

impl From<String> for ToolParamValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for ToolParamValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<bool> for ToolParamValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for ToolParamValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<i32> for ToolParamValue {
    fn from(value: i32) -> Self {
        Self::Integer(i64::from(value))
    }
}

impl From<u32> for ToolParamValue {
    fn from(value: u32) -> Self {
        Self::Integer(i64::from(value))
    }
}

impl From<Vec<String>> for ToolParamValue {
    fn from(value: Vec<String>) -> Self {
        Self::StringList(value)
    }
}

impl From<Vec<&str>> for ToolParamValue {
    fn from(value: Vec<&str>) -> Self {
        Self::StringList(value.into_iter().map(str::to_string).collect())
    }
}

/// Declarative typed parameter specification exposed by a [`ToolAdapter`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ToolParamSpec {
    /// Canonical parameter key used in [`ToolInvocation::params`].
    pub name: String,
    /// Expected typed value representation.
    pub kind: ToolParamKind,
    /// Whether the parameter must be supplied explicitly.
    pub required: bool,
    /// Concise description of parameter semantics.
    pub description: String,
}

/// Structured representation of a requested tool execution.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct ToolInvocation {
    /// Canonical tool identifier (e.g., `"cargo-clippy"`, `"cargo-test"`).
    pub tool_name: String,
    /// Structured command-line arguments passed to the tool adapter.
    pub args: Vec<String>,
    /// Optional workspace working directory.
    pub working_dir: Option<PathBuf>,
    /// Environment variables passed to the tool invocation.
    pub env_vars: BTreeMap<String, String>,
    /// Typed key-value parameters passed directly to parameterized adapters.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ToolParamValue>,
}

impl ToolInvocation {
    /// Create a new [`ToolInvocation`] with the given tool name and argument list.
    #[must_use]
    pub fn new(
        tool_name: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            args: args.into_iter().map(Into::into).collect(),
            working_dir: None,
            env_vars: BTreeMap::new(),
            params: BTreeMap::new(),
        }
    }

    /// Attach a working directory to the invocation.
    #[must_use]
    pub fn with_working_dir(mut self, working_dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(working_dir.into());
        self
    }

    /// Insert an environment variable into the invocation.
    #[must_use]
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    /// Insert a typed parameter into the invocation.
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<ToolParamValue>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    /// Look up a typed parameter by key.
    #[must_use]
    pub fn param(&self, key: &str) -> Option<&ToolParamValue> {
        self.params.get(key)
    }
}

/// Declarative sandbox requirements advertised by a [`ToolAdapter`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct SandboxProfileRequirement {
    /// Whether the tool is permitted outbound network access.
    pub allow_network: bool,
    /// Explicit allowlist of outbound hosts permitted when `allow_network` is `true`.
    pub allowed_egress_hosts: Vec<String>,
    /// Workspace or temporary directories that the tool may write to.
    pub writable_dirs: Vec<String>,
    /// System, toolchain, or workspace directories that the tool may read from.
    pub readable_dirs: Vec<String>,
    /// Executables that the sandboxed process is permitted to `execve`.
    pub exec_binaries: Vec<String>,
    /// Required locked-memory budget (`RLIMIT_MEMLOCK`) in KiB.
    pub required_memlock_kb: u64,
}

/// Outcome status of an individual parsed test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCaseStatus {
    /// The test case passed (`ok`).
    Passed,
    /// The test case failed (`FAILED`).
    Failed,
    /// The test case was ignored (`ignored`).
    Ignored,
}

/// Granular per-test case result extracted from test runner output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTestCase {
    /// Canonical test identifier (e.g., `"module::tests::test_foo"`).
    pub test_name: String,
    /// Execution status of the test case.
    pub status: TestCaseStatus,
    /// Optional per-test execution duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Optional captured stdout/stderr failure block when `status == TestCaseStatus::Failed`.
    pub failure_snippet: Option<String>,
}

/// Granular per-benchmark statistical result extracted from benchmark output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedBenchmark {
    /// Canonical benchmark name (e.g., `"kernels::gemm_q4_0"`).
    pub bench_name: String,
    /// Point estimate of nanoseconds per iteration.
    pub ns_per_iter: f64,
    /// Variance / half-width / MAD in nanoseconds (`+/- <V>` or `(high - low) / 2`).
    pub variance_ns: f64,
    /// Optional throughput in megabytes per second (`MB/s`).
    pub throughput_mb_s: Option<f64>,
    /// Optional target architecture tag (`"riscv64"`, `"x86_64"`, `"aarch64"`).
    pub arch: Option<String>,
    /// Optional CPU cluster tag (`"X100"`, `"A100"`, `"generic"`).
    pub cpu_cluster: Option<String>,
    /// Optional RISC-V vector length in bits (`256`, `1024`).
    pub vlen_bits: Option<u32>,
}

/// Verified two-tier license classification enforced prior to registry staging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    /// Library/IPC/trait/sandboxing crates licensed under `LGPL-3.0-only WITH LGPL-3.0-linking-exception`.
    Tier1LgplLinkingException,
    /// Standalone daemons, controllers, agents, registries, and web frontends licensed under `AGPL-3.0-only`.
    Tier2Agpl3,
}

impl LicenseTier {
    /// Return the canonical SPDX expression enforced for this licensing tier.
    #[must_use]
    pub const fn as_spdx(self) -> &'static str {
        match self {
            Self::Tier1LgplLinkingException => "LGPL-3.0-only WITH LGPL-3.0-linking-exception",
            Self::Tier2Agpl3 => "AGPL-3.0-only",
        }
    }
}

/// Per-crate staging result emitted inside [`CdStagingRunReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StagedCrateReport {
    /// Crate package name published in topological dependency order.
    pub name: String,
    /// Validated SemVer package version.
    pub version: String,
    /// Verified licensing tier for this crate.
    pub license_tier: LicenseTier,
    /// Verified SPDX expression in `Cargo.toml`.
    pub license_spdx: String,
    /// Whether `cargo publish` ran for this crate (`false` when `--dry-run` or skipped as already indexed).
    pub published: bool,
    /// Whether the version already existed in `muregist` before this staging run.
    pub skipped_existing: bool,
    /// Sparse index `ETag` observed after publishing (when online publish runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Relative sparse index path polled on `muregist` (e.g., `"mu/-/mu-ci-tools"`).
    pub index_path: String,
    /// Duration of this crate's staging and index poll step in milliseconds.
    pub duration_ms: u64,
}

/// Result of isolated clean-room consumer resolution (`cargo check --tests`) against `muregist`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct ConsumerCheckReport {
    /// Whether consumer verification ran (typically `false` during `--dry-run`).
    pub executed: bool,
    /// Whether clean-room `cargo check --tests` succeeded strictly against `muregist`.
    pub passed: bool,
    /// Whether an isolated temporary `CARGO_HOME` was used.
    pub isolated_cargo_home: bool,
    /// Whether `crates.io` egress was explicitly blocked in `.cargo/config.toml`.
    pub crates_io_blocked: bool,
    /// Workspace crates directly imported by the clean-room consumer test crate.
    #[serde(default)]
    pub checked_packages: Vec<String>,
    /// Elapsed milliseconds for consumer verification.
    pub duration_ms: u64,
    /// Failure diagnostic if clean-room resolution failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Ecosystem-tagged CD staging report emitted by `CargoDeployAdapter` for `mu-cd-controller` ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CdStagingRunReport {
    /// Unique identifier for this staging run.
    pub run_id: String,
    /// Ecosystem tag consumed by `mu-cd-controller` (`"cargo"`).
    pub ecosystem: String,
    /// Target Cargo registry alias (`"muregist"`).
    pub registry: String,
    /// Base URL of the `muregist` sparse index / API server, when configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_url: Option<String>,
    /// Canonical workspace root path validated by `cargo metadata`.
    pub workspace_root: String,
    /// Whether execution ran in rehearsal `--dry-run` mode without publishing or mutating index state.
    pub dry_run: bool,
    /// Terminal staging status (`"passed"` or `"failed"`).
    pub status: String,
    /// Start timestamp in Unix epoch milliseconds.
    pub started_epoch_ms: u64,
    /// Completion timestamp in Unix epoch milliseconds.
    pub finished_epoch_ms: u64,
    /// Total elapsed execution time in milliseconds.
    pub duration_ms: u64,
    /// Crates staged and verified in deterministic topological publish order.
    #[serde(default)]
    pub publish_order: Vec<StagedCrateReport>,
    /// Clean-room consumer compilation check against the staged `muregist` sparse index.
    pub consumer_check: ConsumerCheckReport,
    /// Stage identifier if the run failed (e.g., `"plan"`, `"license_gate"`, `"publish"`, `"index_poll"`, `"consumer_check"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_stage: Option<String>,
    /// Structured error detail if the run failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_detail: Option<String>,
}

impl Default for CdStagingRunReport {
    fn default() -> Self {
        Self {
            run_id: String::new(),
            ecosystem: "cargo".to_string(),
            registry: "muregist".to_string(),
            registry_url: None,
            workspace_root: String::new(),
            dry_run: false,
            status: String::new(),
            started_epoch_ms: 0,
            finished_epoch_ms: 0,
            duration_ms: 0,
            publish_order: Vec::new(),
            consumer_check: ConsumerCheckReport::default(),
            failure_stage: None,
            failure_detail: None,
        }
    }
}

/// Structured metrics extracted after a tool execution completes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ToolExecutionMetrics {
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
    /// Process exit status code.
    pub exit_code: i32,
    /// Number of unit/integration tests that passed, if applicable.
    pub tests_passed: Option<u32>,
    /// Number of unit/integration tests that failed, if applicable.
    pub tests_failed: Option<u32>,
    /// Number of unit/integration tests that were ignored, if applicable.
    #[serde(default)]
    pub tests_ignored: Option<u32>,
    /// Number of compiler or linter warnings emitted, if applicable.
    pub warnings_count: Option<u32>,
    /// Line or region test coverage percentage (`0.0..=100.0`), if applicable.
    pub coverage_pct: Option<f64>,
    /// Aggregate benchmark latency in nanoseconds per iteration, if applicable.
    #[serde(default)]
    pub bench_ns_per_iter: Option<f64>,
    /// Aggregate benchmark throughput in megabytes per second, if applicable.
    #[serde(default)]
    pub bench_mb_per_sec: Option<f64>,
    /// Relative paths or identifiers of generated build/coverage artifacts.
    pub artifacts: Vec<String>,
    /// Granular per-test execution outcomes extracted from test output.
    #[serde(default)]
    pub test_cases: Vec<ParsedTestCase>,
    /// Granular per-benchmark statistical results extracted from benchmark output.
    #[serde(default)]
    pub benchmarks: Vec<ParsedBenchmark>,
    /// Ecosystem-tagged CD staging report emitted by `cargo-deploy`, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cd_staging_report: Option<CdStagingRunReport>,
}

/// Core interface for compile-time typed CI/CD tool execution without shell interpolation.
pub trait ToolAdapter: Send + Sync {
    /// Canonical adapter identifier (e.g., `"cargo-clippy"`, `"cargo-llvm-cov"`).
    fn name(&self) -> &'static str;

    /// Declare optional typed parameters accepted in [`ToolInvocation::params`].
    fn param_specs(&self) -> Vec<ToolParamSpec> {
        Vec::new()
    }

    /// Validate all arguments, paths, and environment variables in `inv`.
    ///
    /// # Errors
    ///
    /// Returns [`ToolValidationError`] if any argument, path, or environment variable
    /// violates the adapter's strict allowlist or sanitization rules.
    fn validate(&self, inv: &ToolInvocation) -> Result<(), ToolValidationError>;

    /// Construct a deterministic `argv` vector suitable for direct `execve` without a shell.
    ///
    /// The first element of the returned vector is the executable name or path, followed
    /// by fixed subcommands and validated flags.
    ///
    /// # Errors
    ///
    /// Returns [`ToolBuildError`] if validation fails or the `argv` vector cannot be constructed.
    fn build_argv(&self, inv: &ToolInvocation) -> Result<Vec<OsString>, ToolBuildError>;

    /// Return the declarative sandbox profile required to execute `inv`.
    fn sandbox_profile(&self, inv: &ToolInvocation) -> SandboxProfileRequirement;

    /// Parse structured execution metrics from `stdout`, `stderr`, and `exit_code`.
    ///
    /// # Errors
    ///
    /// Returns [`MetricParseError`] if `stdout` or `stderr` is not valid UTF-8 or fails
    /// expected format parsing.
    fn parse_metrics(
        &self,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: i32,
    ) -> Result<ToolExecutionMetrics, MetricParseError>;
}

impl std::fmt::Debug for dyn ToolAdapter + '_ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolAdapter")
            .field("name", &self.name())
            .finish()
    }
}
