# mu-ci-tools

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/mu-ci-tools/card.svg" alt="mu-ci-tools Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-ci-tools/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-ci-tools/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-ci-tools/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-ci-tools/benchmark.svg" alt="Benchmark"/></a>
</p>

______________________________________________________________________

Compile-time modular Rust `ToolAdapter` trait registry for typed CI/CD tools across the [`mu-ci`](https://github.com/LMA1980/mu-ci) ecosystem.

`mu-ci-tools` enforces structured, deterministic execution across [`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller) (task planning, DAG scheduling, capability matching) and [`mu-ci-worker`](https://github.com/LMA1980/mu-ci-worker) (isolated sandboxed execution).

______________________________________________________________________

## Core Principles

- **Strict Shell Prohibition**: Arbitrary shell execution (`bash -c`, `sh -c`, `eval`, or ad-hoc scripts) is strictly forbidden. All workflow steps must map to the 12 registered, compile-time verified tool adapters.
- **Typed Argument Vectors**: Tool adapters construct strict, validated `Vec<OsString>` arguments directly passed to `execve`-style invocations without shell interpolation.
- **Declarative Sandbox Profiling**: Adapters declare their exact sandbox resource requirements (filesystem paths, network egress, memory limits, environment variables) for consumption by [`mu-ci-isolation`](https://github.com/LMA1980/mu-ci-isolation).
- **Structured Metric Extraction**: Standardizes stdout/stderr parsing into strongly typed pipeline telemetry (`ToolExecutionMetrics`: pass ratios, line coverage, advisory audits, micro-benchmark summaries, and `CdStagingRunReport` for `cargo-deploy`) surfaced in [`mu-ci-web`](https://github.com/LMA1980/mu-ci-web) and [`mu-console`](https://github.com/LMA1980/mu-console).

______________________________________________________________________

## Supported Typed Tools (`12` Adapters)

| Tool Adapter          | Target Binary | Primary Subcommands & Roles                                                                                                | Sandbox Egress Default                                                                         |
| --------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `CargoBuildAdapter`   | `cargo`       | `build --workspace --release` (release binary compilation)                                                                 | Offline (`none`)                                                                               |
| `CargoFmtAdapter`     | `cargo`       | `fmt --check` (code hygiene and formatting validation)                                                                     | Offline (`none`)                                                                               |
| `CargoClippyAdapter`  | `cargo`       | `clippy --all-targets -- -D warnings` (static analysis)                                                                    | Offline (`none`)                                                                               |
| `CargoTestAdapter`    | `cargo`       | `test --workspace` (unit, integration, and doc tests)                                                                      | Offline (`none`)                                                                               |
| `CargoBenchAdapter`   | `cargo`       | `bench --workspace` (micro-benchmarking performance regressions)                                                           | Offline (`none`)                                                                               |
| `CargoAuditAdapter`   | `cargo`       | `audit` (vulnerability audit against RustSec advisory-db)                                                                  | Offline (`/var/lib/action-runner/.cargo/advisory-db`)                                          |
| `CargoLlvmCovAdapter` | `cargo`       | `llvm-cov --workspace --json` (source-based code coverage)                                                                 | Offline (`none`)                                                                               |
| `CargoMiriAdapter`    | `cargo`       | `miri test` (undefined behavior detection on nightly)                                                                      | Offline (`none`)                                                                               |
| `CargoPublishAdapter` | `cargo`       | `publish --registry <target>` (sparse artifact publishing)                                                                 | Restricted ([`mu-registry`](https://github.com/LMA1980/mu-registry) mTLS)                      |
| `CargoDeployAdapter`  | `cargo`       | `deploy --registry muregist` (topological DAG, two-tier license gate, sparse-index `ETag` poll, clean-room consumer check) | Restricted ([`mu-registry`](https://github.com/LMA1980/mu-registry) mTLS; `crates.io` blocked) |
| `TrunkAdapter`        | `trunk`       | `build --release` (WASM application bundling for [`mu-ci-web`](https://github.com/LMA1980/mu-ci-web) CSR SPA)              | Offline (`none`)                                                                               |
| `MdformatAdapter`     | `mdformat`    | `--check` / GFM Markdown table and documentation hygiene                                                                   | Offline (`none`)                                                                               |

______________________________________________________________________

## ToolAdapter Architecture

Each tool implements the `ToolAdapter` trait (`src/adapter.rs`):

```rust
use std::ffi::OsString;

/// Core interface for compile-time typed CI/CD tool execution without shell interpolation.
pub trait ToolAdapter: Send + Sync {
    /// Canonical adapter identifier (e.g., "cargo-clippy", "cargo-llvm-cov").
    fn name(&self) -> &'static str;

    /// Declare optional typed parameters accepted in ToolInvocation::params.
    fn param_specs(&self) -> Vec<ToolParamSpec> {
        Vec::new()
    }

    /// Validate all arguments, paths, and environment variables in inv.
    fn validate(&self, inv: &ToolInvocation) -> Result<(), ToolValidationError>;

    /// Construct a deterministic argv vector suitable for direct execve without a shell.
    fn build_argv(&self, inv: &ToolInvocation) -> Result<Vec<OsString>, ToolBuildError>;

    /// Return the declarative sandbox profile required to execute inv.
    fn sandbox_profile(&self, inv: &ToolInvocation) -> SandboxProfileRequirement;

    /// Parse structured execution metrics from stdout, stderr, and exit_code.
    fn parse_metrics(
        &self,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: i32,
    ) -> Result<ToolExecutionMetrics, MetricParseError>;
}
```

______________________________________________________________________

## Security & Operational Invariants

1. **No Subshell Spawning**: Execution is performed via direct process dispatch into kernel or hypervisor sandboxes.
1. **Argument Sanitization**: Reject null bytes, path traversal sequences (`../`), and unrecognized command-line flags at the `validate()` phase.
1. **Deterministic Output Parsing**: Metric parsing must fail closed (`MetricParseError`) on corrupt, truncated, or ambiguous tool outputs.

______________________________________________________________________

## License

Licensed under the GNU Lesser General Public License v3.0 with the LGPL-3.0 Linking Exception (LGPL-3.0-only WITH LGPL-3.0-linking-exception). See [LICENSE](LICENSE) for details.
