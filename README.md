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

---

Compile-time modular Rust `ToolAdapter` trait registry for typed CI/CD tools across the **ActionRunner** ecosystem.

`mu-ci-tools` enforces structured, deterministic execution across `ActionRunner-controller` (task planning, DAG scheduling, capability matching) and `ActionRunner-rs` (isolated sandboxed execution).

---

## Core Principles

- **Strict Shell Prohibition**: Arbitrary shell execution (`bash -c`, `sh -c`, `eval`, or ad-hoc scripts) is strictly forbidden. All workflow steps must map to registered, compile-time verified tool adapters.
- **Typed Argument Vectors**: Tool adapters construct strict, validated `Vec<OsString>` arguments directly passed to `execve`-style invocations without shell interpolation.
- **Declarative Sandbox Profiling**: Adapters declare their exact sandbox resource requirements (filesystem paths, network egress, memory limits, environment variables) for consumption by `MuIsolation`.
- **Structured Metric Extraction**: Standardizes stdout/stderr parsing into strongly typed pipeline telemetry (pass ratios, line coverage, advisory audits, micro-benchmark summaries).

---

## Supported Typed Tools

| Tool Adapter | Target Binary | Primary Subcommands & Roles | Sandbox Egress Default |
|---|---|---|---|
| `CargoBuildAdapter` | `cargo` | `build --workspace --release` (release binary compilation) | Offline (`none`) |
| `CargoFmtAdapter` | `cargo` | `fmt --check` (code hygiene and formatting validation) | Offline (`none`) |
| `CargoClippyAdapter` | `cargo` | `clippy --all-targets -- -D warnings` (static analysis) | Offline (`none`) |
| `CargoTestAdapter` | `cargo` | `test --workspace` (unit, integration, and doc tests) | Offline (`none`) |
| `CargoBenchAdapter` | `cargo` | `bench --workspace` (micro-benchmarking performance regressions)| Offline (`none`) |
| `CargoAuditAdapter` | `cargo` | `audit` (vulnerability audit against RustSec advisory-db) | Offline (`/var/lib/action-runner/advisory-db`) |
| `CargoLlvmCovAdapter` | `cargo` | `llvm-cov --workspace --json` (source-based code coverage) | Offline (`none`) |
| `CargoMiriAdapter` | `cargo` | `miri test` (undefined behavior detection on nightly) | Offline (`none`) |
| `CargoPublishAdapter` | `cargo` | `publish --registry <target>` (sparse artifact publishing) | Restricted (`MuRegist` mTLS endpoint) |
| `TrunkAdapter` | `trunk` | `build --release` (WASM application bundling for `ActionRunner-web` CSR SPA) | Offline (`none`) |
| `MdformatAdapter` | `mdformat` | `--check` / GFM Markdown table and documentation hygiene | Offline (`none`) |

---

## ToolAdapter Architecture

Each tool implements the `ToolAdapter` trait:

```rust
use std::ffi::OsString;
use std::path::Path;

/// Core interface for compile-time typed tool execution
pub trait ToolAdapter: Send + Sync {
    /// Canonical adapter identifier (e.g., "cargo-clippy", "cargo-llvm-cov")
    fn name(&self) -> &'static str;

    /// Validate task configuration parameters before scheduling
    fn validate(&self, invocation: &ToolInvocation) -> Result<(), ToolValidationError>;

    /// Build deterministic argument vector without shell interpolation
    fn build_argv(&self, invocation: &ToolInvocation) -> Result<Vec<OsString>, ToolBuildError>;

    /// Emit required isolation sandbox requirements for MuIsolation
    fn sandbox_profile(&self, invocation: &ToolInvocation) -> SandboxProfileRequirement;

    /// Parse process exit code and streams into standardized factory metrics
    fn parse_metrics(
        &self,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: i32,
    ) -> Result<ToolExecutionMetrics, MetricParseError>;
}
```

---

## Security & Operational Invariants

1. **No Subshell Spawning**: Execution is performed via direct process dispatch into kernel or hypervisor sandboxes.
2. **Argument Sanitization**: Reject null bytes, path traversal sequences (`../`), and unrecognized command-line flags at the `validate()` phase.
3. **Deterministic Output Parsing**: Metric parsing must fail closed (`MetricParseError`) on corrupt, truncated, or ambiguous tool outputs.

---

## License

Licensed under the GNU Lesser General Public License v3.0 with the LGPL-3.0 Linking Exception (LGPL-3.0-only WITH LGPL-3.0-linking-exception). See LICENSE for details.
