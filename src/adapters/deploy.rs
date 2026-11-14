//! `CargoDeployAdapter`: topological staging, two-tier license verification, `muregist` sparse-index
//! `ETag` polling, and clean-room consumer resolution (`crates.io` egress blocked).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::adapter::{
    CdStagingRunReport, ConsumerCheckReport, LicenseTier, SandboxProfileRequirement,
    StagedCrateReport, ToolAdapter, ToolExecutionMetrics, ToolInvocation, ToolParamKind,
    ToolParamSpec, ToolParamValue,
};
use crate::adapters::cargo::CargoPublishAdapter;
use crate::error::{MetricParseError, ToolBuildError, ToolValidationError};
use crate::sanitize::{
    validate_invocation_base, validate_path_within_working_dir, validate_safe_arg,
    validate_safe_relative_path,
};

/// Only target Cargo registry alias accepted by `cargo-deploy`.
pub const REQUIRED_REGISTRY: &str = "muregist";
/// Default maximum wait time (seconds) when polling sparse index `ETag` availability.
pub const DEFAULT_POLL_TIMEOUT_SECS: u64 = 30;
/// Upper bound (seconds) permitted for sparse index `ETag` polling.
pub const MAX_POLL_TIMEOUT_SECS: u64 = 600;
/// Default interval between sparse index `ETag` poll requests.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 250;
/// Tier-1 SPDX expression for library, IPC, trait, and sandboxing crates.
pub const TIER1_LICENSE_SPDX: &str = "LGPL-3.0-only WITH LGPL-3.0-linking-exception";
/// Tier-2 SPDX expression for standalone daemons, controllers, agents, registries, and web SPAs.
pub const TIER2_LICENSE_SPDX: &str = "AGPL-3.0-only";
/// Marker line prefix emitted on stdout when printing a serialized [`CdStagingRunReport`].
pub const CD_STAGING_REPORT_PREFIX: &str = "MU_CD_STAGING_REPORT:";

const DEPLOY_TOOL_NAME: &str = "cargo-deploy";

/// Two-tier licensing verification mode enforced before publishing crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LicensePolicyMode {
    /// Classify pure library/proc-macro crates as Tier 1 and binary crates as Tier 2.
    #[default]
    Auto,
    /// Require Tier-1 `LGPL-3.0-only WITH LGPL-3.0-linking-exception` on every staged crate.
    RequireTier1,
    /// Require Tier-2 `AGPL-3.0-only` on every staged crate.
    RequireTier2,
    /// Accept either Tier-1 or Tier-2 as long as `Cargo.toml` and `LICENSE` match cleanly.
    EitherTier,
}

impl LicensePolicyMode {
    /// Parse a CLI/param mode identifier (`"auto"`, `"tier1"`, `"tier2"`, `"either"`).
    ///
    /// # Errors
    ///
    /// Returns an explanation string if `raw` is not one of the supported policy mode names.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "tier1" | "tier-1" | "lgpl" => Ok(Self::RequireTier1),
            "tier2" | "tier-2" | "agpl" => Ok(Self::RequireTier2),
            "either" => Ok(Self::EitherTier),
            other => Err(format!(
                "unsupported license_tier '{other}'; expected auto, tier1, tier2, or either"
            )),
        }
    }

    /// Canonical CLI flag string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::RequireTier1 => "tier1",
            Self::RequireTier2 => "tier2",
            Self::EitherTier => "either",
        }
    }
}

/// Errors returned while planning, license-checking, publishing, or consumer-verifying crates.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeployError {
    /// Invocation parameter or flag validation failed.
    #[error("validation error: {0}")]
    Validation(#[from] ToolValidationError),

    /// Executing `cargo metadata` failed.
    #[error("cargo metadata failed: {0}")]
    MetadataCommandFailed(String),

    /// Parsing `cargo metadata` JSON failed.
    #[error("invalid cargo metadata JSON: {0}")]
    InvalidMetadataJson(String),

    /// One or more requested packages are missing from the workspace.
    #[error("unknown workspace package(s): {}", .0.join(", "))]
    UnknownPackages(Vec<String>),

    /// A workspace package, dependency, or config attempted to use a non-`muregist` or `crates.io` registry.
    #[error("forbidden registry configuration for package '{package}': {detail}")]
    ForbiddenRegistry {
        /// Crate package triggering the registry violation.
        package: String,
        /// Detailed explanation of the forbidden registry configuration.
        detail: String,
    },

    /// A publishable crate or its non-dev workspace dependency lacked a valid explicit version.
    #[error("missing explicit version for package '{package}': {detail}")]
    MissingVersion {
        /// Package missing a version or declaring an unversioned dependency.
        package: String,
        /// Optional workspace dependency missing an explicit version requirement.
        dependency: Option<String>,
        /// Detailed explanation of the missing version constraint.
        detail: String,
    },

    /// Workspace publish dependencies contain a cycle preventing topological ordering.
    #[error("cyclic workspace publish dependency detected: {}", cycle.join(" -> "))]
    CyclicDependency {
        /// Ordered node names illustrating the cycle.
        cycle: Vec<String>,
    },

    /// A staged crate failed two-tier `Cargo.toml` / `LICENSE` verification.
    #[error("license policy violation for package '{package}': {detail}")]
    LicensePolicyViolation {
        /// Crate failing license verification.
        package: String,
        /// Explanation of the missing or mismatched SPDX / `LICENSE` text.
        detail: String,
    },

    /// `cargo publish` failed for a staged package.
    #[error("cargo publish failed for '{package}' (exit {exit_code}): {stderr}")]
    PublishCommandFailed {
        /// Crate whose publish command failed.
        package: String,
        /// Subprocess exit code.
        exit_code: i32,
        /// Captured stderr output.
        stderr: String,
    },

    /// Polling the `muregist` sparse index timed out before observing the expected version and `ETag`.
    #[error(
        "timed out after {timeout_secs}s polling sparse index '{index_path}' for {package}@{version}"
    )]
    IndexPollTimeout {
        /// Crate name polled.
        package: String,
        /// Crate version expected in sparse index JSON.
        version: String,
        /// Relative sparse index path queried.
        index_path: String,
        /// Configured polling timeout in seconds.
        timeout_secs: u64,
        /// Last HTTP/network diagnostic observed while polling.
        last_error: Option<String>,
    },

    /// Isolated clean-room consumer `cargo check --tests` failed.
    #[error("clean-room consumer verification failed: {detail}")]
    ConsumerCheckFailed {
        /// Diagnostic from clean-room compilation.
        detail: String,
    },

    /// Filesystem or network I/O error.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for DeployError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// Wrapper pairing a terminal [`DeployError`] with the structured [`CdStagingRunReport`].
#[derive(Debug, Error)]
#[error("{error}")]
pub struct DeployRunFailure {
    /// Underlying failure reason.
    pub error: DeployError,
    /// Structured staging report capturing completed stages and failure diagnostics.
    pub report: CdStagingRunReport,
}

/// Typed configuration parsed from [`ToolInvocation::params`] and [`ToolInvocation::args`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDeployParams {
    /// Target registry alias; always `"muregist"`.
    pub registry: String,
    /// Optional `muregist` base or sparse index URL (never `crates.io`).
    pub registry_url: Option<String>,
    /// Optional explicit list of workspace crates to stage.
    pub packages: Vec<String>,
    /// Optional workspace-relative path to root `Cargo.toml`.
    pub manifest_path: Option<String>,
    /// Two-tier licensing policy mode.
    pub license_mode: LicensePolicyMode,
    /// Run validation and `cargo publish --dry-run` without uploading tarballs or polling live index.
    pub dry_run: bool,
    /// Pass `--allow-dirty` to `cargo publish`.
    pub allow_dirty: bool,
    /// Pass `--locked` to `cargo publish` and consumer checks.
    pub locked: bool,
    /// Pass `--no-verify` to `cargo publish`.
    pub no_verify: bool,
    /// Run isolated clean-room consumer `cargo check --tests` after staging.
    pub consumer_check: bool,
    /// Bounded sparse-index `ETag` poll timeout in seconds.
    pub poll_timeout_secs: u64,
    /// Optional environment variable name carrying the `muregist` publish bearer token.
    pub token_env: Option<String>,
}

impl Default for CargoDeployParams {
    fn default() -> Self {
        Self {
            registry: REQUIRED_REGISTRY.to_string(),
            registry_url: None,
            packages: Vec::new(),
            manifest_path: None,
            license_mode: LicensePolicyMode::Auto,
            dry_run: false,
            allow_dirty: false,
            locked: false,
            no_verify: false,
            consumer_check: true,
            poll_timeout_secs: DEFAULT_POLL_TIMEOUT_SECS,
            token_env: None,
        }
    }
}

impl CargoDeployParams {
    /// Validate and normalize [`CargoDeployParams`] from typed `params` and CLI `args`.
    ///
    /// # Errors
    ///
    /// Returns [`ToolValidationError`] if any parameter type, value, flag, URL, or environment
    /// variable violates strict `muregist`-only, zero-`crates.io`, or path-safety invariants.
    pub fn from_invocation(inv: &ToolInvocation) -> Result<Self, ToolValidationError> {
        validate_invocation_base(inv)?;
        validate_registry_env_vars(&inv.env_vars)?;

        let mut parsed = Self::default();
        let mut license_tier_str: Option<String> = None;
        let mut registry_seen = false;
        let mut consumer_check_explicit: Option<bool> = None;

        apply_typed_params(
            inv,
            &mut parsed,
            &mut license_tier_str,
            &mut registry_seen,
            &mut consumer_check_explicit,
        )?;
        apply_cli_args(
            inv,
            &mut parsed,
            &mut license_tier_str,
            &mut registry_seen,
            &mut consumer_check_explicit,
        )?;

        if let Some(mode_raw) = license_tier_str {
            parsed.license_mode = LicensePolicyMode::parse(&mode_raw)
                .map_err(|reason| invalid_arg("license_tier", &mode_raw, reason))?;
        }
        if let Some(url) = &parsed.registry_url {
            validate_registry_url(url, "registry_url")?;
        }
        if let Some(manifest) = &parsed.manifest_path {
            validate_manifest_rel_path(inv, manifest)?;
        }
        if let Some(token_env) = &parsed.token_env {
            validate_token_env_name(token_env)?;
        }
        if parsed.poll_timeout_secs == 0 || parsed.poll_timeout_secs > MAX_POLL_TIMEOUT_SECS {
            return Err(invalid_arg(
                "poll_timeout_secs",
                &parsed.poll_timeout_secs.to_string(),
                format!("poll_timeout_secs must be between 1 and {MAX_POLL_TIMEOUT_SECS}"),
            ));
        }

        Ok(parsed)
    }
}

fn invalid_arg(flag: &str, value: &str, reason: impl Into<String>) -> ToolValidationError {
    ToolValidationError::InvalidArgValue {
        tool: DEPLOY_TOOL_NAME.to_string(),
        flag: flag.to_string(),
        value: value.to_string(),
        reason: reason.into(),
    }
}

fn validate_registry_name(value: &str, flag: &str) -> Result<(), ToolValidationError> {
    if value != REQUIRED_REGISTRY {
        return Err(invalid_arg(
            flag,
            value,
            format!(
                "only '{REQUIRED_REGISTRY}' registry is permitted; upstream crates.io and alternative registries are forbidden"
            ),
        ));
    }
    Ok(())
}

/// Return `true` when `raw` targets `crates.io`, `*.crates.io`, or the upstream crates.io index.
#[must_use]
pub fn is_forbidden_crates_io_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    let stripped = trimmed.strip_prefix("sparse+").unwrap_or(trimmed);
    let lower = stripped.to_ascii_lowercase();
    if lower.contains("crates.io-index") || lower.contains("crates.io") {
        return true;
    }

    if let Some((_, rest)) = lower.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host_port = authority.rsplit('@').next().unwrap_or("");
        let host = host_port.split(':').next().unwrap_or("");
        if host == "crates.io" || host.ends_with(".crates.io") {
            return true;
        }
    }

    false
}

fn validate_registry_url(raw: &str, flag: &str) -> Result<(), ToolValidationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid_arg(flag, raw, "registry URL must not be empty"));
    }
    validate_safe_arg(trimmed)?;
    if is_forbidden_crates_io_url(trimmed) {
        return Err(invalid_arg(
            flag,
            raw,
            "crates.io registry/index URLs are strictly forbidden",
        ));
    }
    let without_sparse = trimmed.strip_prefix("sparse+").unwrap_or(trimmed);
    let Some((scheme, rest)) = without_sparse.split_once("://") else {
        return Err(invalid_arg(
            flag,
            raw,
            "registry URL must include http:// or https:// scheme",
        ));
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid_arg(
            flag,
            raw,
            "registry URL scheme must be http or https",
        ));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains(char::is_whitespace) {
        return Err(invalid_arg(
            flag,
            raw,
            "registry URL is missing a valid host",
        ));
    }
    Ok(())
}

fn validate_registry_env_vars(
    env_vars: &BTreeMap<String, String>,
) -> Result<(), ToolValidationError> {
    for (key, value) in env_vars {
        let upper_key = key.trim().to_ascii_uppercase();
        if upper_key == "CARGO_REGISTRY_DEFAULT" && value.trim() != REQUIRED_REGISTRY {
            return Err(invalid_arg(
                key,
                value,
                format!("CARGO_REGISTRY_DEFAULT must be '{REQUIRED_REGISTRY}'"),
            ));
        }
        if upper_key.starts_with("CARGO_REGISTRIES_CRATES_IO") || is_forbidden_crates_io_url(value)
        {
            return Err(invalid_arg(
                key,
                value,
                "environment variables targeting crates.io are strictly forbidden",
            ));
        }
    }
    Ok(())
}

fn validate_manifest_rel_path(inv: &ToolInvocation, path: &str) -> Result<(), ToolValidationError> {
    validate_safe_relative_path(path)?;
    if path != "Cargo.toml" && !path.ends_with("/Cargo.toml") {
        return Err(invalid_arg(
            "manifest_path",
            path,
            "manifest_path must point to a Cargo.toml file",
        ));
    }
    if let Some(work_dir) = &inv.working_dir {
        validate_path_within_working_dir(work_dir, path)?;
    }
    Ok(())
}

fn validate_token_env_name(name: &str) -> Result<(), ToolValidationError> {
    let trimmed = name.trim();
    let valid_ident = !trimmed.is_empty()
        && !trimmed.as_bytes()[0].is_ascii_digit()
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !valid_ident {
        return Err(invalid_arg(
            "token_env",
            name,
            "token_env must be a valid POSIX environment variable identifier",
        ));
    }
    Ok(())
}

fn validate_package_name(pkg: &str, flag: &str) -> Result<(), ToolValidationError> {
    validate_safe_arg(pkg)?;
    let valid = !pkg.is_empty()
        && !pkg.starts_with('-')
        && pkg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid {
        return Err(invalid_arg(
            flag,
            pkg,
            "package name must contain only ASCII alphanumerics, '-', or '_'",
        ));
    }
    Ok(())
}

fn push_unique_package(target: &mut Vec<String>, pkg: String) {
    if !target.iter().any(|existing| existing == &pkg) {
        target.push(pkg);
    }
}

fn expect_param_str<'a>(
    key: &str,
    val: &'a ToolParamValue,
) -> Result<&'a str, ToolValidationError> {
    val.as_str()
        .ok_or_else(|| invalid_arg(key, &format!("{val:?}"), "expected string parameter"))
}

fn expect_param_bool(key: &str, val: &ToolParamValue) -> Result<bool, ToolValidationError> {
    val.as_bool()
        .ok_or_else(|| invalid_arg(key, &format!("{val:?}"), "expected boolean parameter"))
}

fn expect_param_u64(key: &str, val: &ToolParamValue) -> Result<u64, ToolValidationError> {
    val.as_u64().ok_or_else(|| {
        invalid_arg(
            key,
            &format!("{val:?}"),
            "expected non-negative integer parameter",
        )
    })
}

fn apply_typed_params(
    inv: &ToolInvocation,
    parsed: &mut CargoDeployParams,
    license_tier_str: &mut Option<String>,
    registry_seen: &mut bool,
    consumer_check_explicit: &mut Option<bool>,
) -> Result<(), ToolValidationError> {
    for (key, value) in &inv.params {
        match key.as_str() {
            "registry" => {
                let s = expect_param_str(key, value)?;
                validate_registry_name(s, "registry")?;
                *registry_seen = true;
            }
            "registry_url" => {
                let s = expect_param_str(key, value)?;
                validate_registry_url(s, "registry_url")?;
                parsed.registry_url = Some(s.trim().to_string());
            }
            "packages" => {
                let list = value.as_string_list().ok_or_else(|| {
                    invalid_arg(key, &format!("{value:?}"), "expected string_list parameter")
                })?;
                for pkg in list {
                    validate_package_name(pkg, "packages")?;
                    push_unique_package(&mut parsed.packages, pkg.clone());
                }
            }
            "manifest_path" => {
                let s = expect_param_str(key, value)?;
                parsed.manifest_path = Some(s.to_string());
            }
            "license_tier" => {
                let s = expect_param_str(key, value)?;
                *license_tier_str = Some(s.to_string());
            }
            "dry_run" => parsed.dry_run = expect_param_bool(key, value)?,
            "allow_dirty" => parsed.allow_dirty = expect_param_bool(key, value)?,
            "locked" => parsed.locked = expect_param_bool(key, value)?,
            "no_verify" => parsed.no_verify = expect_param_bool(key, value)?,
            "consumer_check" => {
                let b = expect_param_bool(key, value)?;
                parsed.consumer_check = b;
                *consumer_check_explicit = Some(b);
            }
            "poll_timeout_secs" => {
                parsed.poll_timeout_secs = expect_param_u64(key, value)?;
            }
            "token_env" => {
                let s = expect_param_str(key, value)?;
                parsed.token_env = Some(s.trim().to_string());
            }
            other => {
                return Err(invalid_arg(
                    other,
                    other,
                    "unsupported parameter for cargo-deploy",
                ));
            }
        }
    }
    Ok(())
}

fn next_flag_value<'a>(
    args: &'a [String],
    idx: &mut usize,
    flag: &str,
) -> Result<&'a str, ToolValidationError> {
    *idx += 1;
    let Some(val) = args.get(*idx) else {
        return Err(invalid_arg(flag, "", "flag requires an explicit value"));
    };
    Ok(val.as_str())
}

fn assign_opt_string(
    slot: &mut Option<String>,
    val: &str,
    flag: &str,
) -> Result<(), ToolValidationError> {
    if let Some(existing) = slot {
        if existing != val {
            return Err(invalid_arg(
                flag,
                val,
                format!("conflicts with typed parameter value '{existing}'"),
            ));
        }
    }
    *slot = Some(val.to_string());
    Ok(())
}

fn apply_cli_args(
    inv: &ToolInvocation,
    parsed: &mut CargoDeployParams,
    license_tier_str: &mut Option<String>,
    registry_seen: &mut bool,
    consumer_check_explicit: &mut Option<bool>,
) -> Result<(), ToolValidationError> {
    let args = &inv.args;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        validate_safe_arg(arg)?;
        if let Some(val) = arg.strip_prefix("--registry=") {
            validate_registry_name(val, "--registry")?;
            *registry_seen = true;
        } else if arg == "--registry" {
            let val = next_flag_value(args, &mut i, "--registry")?;
            validate_registry_name(val, "--registry")?;
            *registry_seen = true;
        } else if let Some(val) = arg.strip_prefix("--registry-url=") {
            validate_registry_url(val, "--registry-url")?;
            assign_opt_string(&mut parsed.registry_url, val.trim(), "--registry-url")?;
        } else if arg == "--registry-url" {
            let val = next_flag_value(args, &mut i, "--registry-url")?;
            validate_registry_url(val, "--registry-url")?;
            assign_opt_string(&mut parsed.registry_url, val.trim(), "--registry-url")?;
        } else if let Some(val) = arg.strip_prefix("--package=") {
            validate_package_name(val, "--package")?;
            push_unique_package(&mut parsed.packages, val.to_string());
        } else if arg == "-p" || arg == "--package" {
            let val = next_flag_value(args, &mut i, arg)?;
            validate_package_name(val, arg)?;
            push_unique_package(&mut parsed.packages, val.to_string());
        } else if let Some(val) = arg.strip_prefix("--manifest-path=") {
            assign_opt_string(&mut parsed.manifest_path, val, "--manifest-path")?;
        } else if arg == "--manifest-path" {
            let val = next_flag_value(args, &mut i, "--manifest-path")?;
            assign_opt_string(&mut parsed.manifest_path, val, "--manifest-path")?;
        } else if let Some(val) = arg.strip_prefix("--license-tier=") {
            assign_opt_string(license_tier_str, val, "--license-tier")?;
        } else if arg == "--license-tier" {
            let val = next_flag_value(args, &mut i, "--license-tier")?;
            assign_opt_string(license_tier_str, val, "--license-tier")?;
        } else if let Some(val) = arg.strip_prefix("--poll-timeout-secs=") {
            parsed.poll_timeout_secs = parse_poll_secs(val, "--poll-timeout-secs")?;
        } else if arg == "--poll-timeout-secs" {
            let val = next_flag_value(args, &mut i, "--poll-timeout-secs")?;
            parsed.poll_timeout_secs = parse_poll_secs(val, "--poll-timeout-secs")?;
        } else if let Some(val) = arg.strip_prefix("--token-env=") {
            assign_opt_string(&mut parsed.token_env, val.trim(), "--token-env")?;
        } else if arg == "--token-env" {
            let val = next_flag_value(args, &mut i, "--token-env")?;
            assign_opt_string(&mut parsed.token_env, val.trim(), "--token-env")?;
        } else if arg == "--dry-run" {
            parsed.dry_run = true;
        } else if arg == "--allow-dirty" {
            parsed.allow_dirty = true;
        } else if arg == "--locked" {
            parsed.locked = true;
        } else if arg == "--no-verify" {
            parsed.no_verify = true;
        } else if arg == "--skip-consumer-check" {
            if *consumer_check_explicit == Some(true) {
                return Err(invalid_arg(
                    "--skip-consumer-check",
                    arg,
                    "conflicts with consumer_check=true parameter",
                ));
            }
            parsed.consumer_check = false;
        } else {
            return Err(invalid_arg(
                arg,
                arg,
                "unsupported argument for cargo-deploy",
            ));
        }
        i += 1;
    }
    let _ = *registry_seen;
    Ok(())
}

fn parse_poll_secs(raw: &str, flag: &str) -> Result<u64, ToolValidationError> {
    raw.trim()
        .parse::<u64>()
        .map_err(|_| invalid_arg(flag, raw, "expected positive integer seconds"))
}

/// Extract `host[:port]` from a validated HTTP(S) registry URL for sandbox allowlisting.
fn extract_url_host_port(raw: &str) -> Option<String> {
    let stripped = raw.trim().strip_prefix("sparse+").unwrap_or(raw.trim());
    let (_, rest) = stripped.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    if host_port.is_empty() {
        None
    } else {
        Some(host_port.to_string())
    }
}

/// Adapter for topological Cargo deployment staging, two-tier licensing checks,
/// sparse-index `ETag` polling, and isolated consumer verification against `muregist`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CargoDeployAdapter;

impl ToolAdapter for CargoDeployAdapter {
    fn name(&self) -> &'static str {
        DEPLOY_TOOL_NAME
    }

    fn param_specs(&self) -> Vec<ToolParamSpec> {
        vec![
            ToolParamSpec {
                name: "registry".to_string(),
                kind: ToolParamKind::String,
                required: false,
                description: "Target Cargo registry alias (must equal 'muregist').".to_string(),
            },
            ToolParamSpec {
                name: "registry_url".to_string(),
                kind: ToolParamKind::String,
                required: false,
                description:
                    "Base or sparse index URL of the muregist service (crates.io forbidden)."
                        .to_string(),
            },
            ToolParamSpec {
                name: "packages".to_string(),
                kind: ToolParamKind::StringList,
                required: false,
                description: "Optional subset of workspace crate names to stage in DAG order."
                    .to_string(),
            },
            ToolParamSpec {
                name: "manifest_path".to_string(),
                kind: ToolParamKind::String,
                required: false,
                description: "Workspace-relative path to root Cargo.toml.".to_string(),
            },
            ToolParamSpec {
                name: "license_tier".to_string(),
                kind: ToolParamKind::String,
                required: false,
                description: "Licensing gate mode: auto, tier1, tier2, or either.".to_string(),
            },
            ToolParamSpec {
                name: "dry_run".to_string(),
                kind: ToolParamKind::Bool,
                required: false,
                description: "Run DAG, license, and cargo publish --dry-run checks only."
                    .to_string(),
            },
            ToolParamSpec {
                name: "allow_dirty".to_string(),
                kind: ToolParamKind::Bool,
                required: false,
                description: "Forward --allow-dirty to cargo publish invocations.".to_string(),
            },
            ToolParamSpec {
                name: "locked".to_string(),
                kind: ToolParamKind::Bool,
                required: false,
                description: "Forward --locked to cargo publish and clean-room consumer checks."
                    .to_string(),
            },
            ToolParamSpec {
                name: "no_verify".to_string(),
                kind: ToolParamKind::Bool,
                required: false,
                description: "Forward --no-verify to cargo publish invocations.".to_string(),
            },
            ToolParamSpec {
                name: "consumer_check".to_string(),
                kind: ToolParamKind::Bool,
                required: false,
                description: "Run isolated consumer cargo check --tests strictly against muregist."
                    .to_string(),
            },
            ToolParamSpec {
                name: "poll_timeout_secs".to_string(),
                kind: ToolParamKind::Integer,
                required: false,
                description: "Bounded sparse-index ETag poll timeout in seconds (1..=600)."
                    .to_string(),
            },
            ToolParamSpec {
                name: "token_env".to_string(),
                kind: ToolParamKind::String,
                required: false,
                description: "Environment variable name supplying the muregist publish token."
                    .to_string(),
            },
        ]
    }

    fn validate(&self, inv: &ToolInvocation) -> Result<(), ToolValidationError> {
        let _ = CargoDeployParams::from_invocation(inv)?;
        Ok(())
    }

    fn build_argv(&self, inv: &ToolInvocation) -> Result<Vec<OsString>, ToolBuildError> {
        let params = CargoDeployParams::from_invocation(inv)?;
        let mut argv = vec![
            OsString::from("cargo"),
            OsString::from("deploy"),
            OsString::from("--registry"),
            OsString::from(params.registry),
        ];

        if let Some(url) = params.registry_url {
            argv.push(OsString::from("--registry-url"));
            argv.push(OsString::from(url));
        }
        if let Some(manifest) = params.manifest_path {
            argv.push(OsString::from("--manifest-path"));
            argv.push(OsString::from(manifest));
        }
        for pkg in params.packages {
            argv.push(OsString::from("-p"));
            argv.push(OsString::from(pkg));
        }
        if params.license_mode != LicensePolicyMode::Auto {
            argv.push(OsString::from("--license-tier"));
            argv.push(OsString::from(params.license_mode.as_str()));
        }
        if params.dry_run {
            argv.push(OsString::from("--dry-run"));
        }
        if params.allow_dirty {
            argv.push(OsString::from("--allow-dirty"));
        }
        if params.locked {
            argv.push(OsString::from("--locked"));
        }
        if params.no_verify {
            argv.push(OsString::from("--no-verify"));
        }
        if !params.consumer_check {
            argv.push(OsString::from("--skip-consumer-check"));
        }
        if params.poll_timeout_secs != DEFAULT_POLL_TIMEOUT_SECS {
            argv.push(OsString::from("--poll-timeout-secs"));
            argv.push(OsString::from(params.poll_timeout_secs.to_string()));
        }
        if let Some(token_env) = params.token_env {
            argv.push(OsString::from("--token-env"));
            argv.push(OsString::from(token_env));
        }

        Ok(argv)
    }

    fn sandbox_profile(&self, inv: &ToolInvocation) -> SandboxProfileRequirement {
        let mut profile = CargoPublishAdapter.sandbox_profile(inv);
        if !profile.writable_dirs.iter().any(|dir| dir == "/tmp") {
            profile.writable_dirs.push("/tmp".to_string());
        }
        if let Ok(params) = CargoDeployParams::from_invocation(inv) {
            if let Some(url) = params.registry_url {
                if let Some(host_port) = extract_url_host_port(&url) {
                    if !profile.allowed_egress_hosts.contains(&host_port) {
                        profile.allowed_egress_hosts.push(host_port);
                    }
                }
            }
        }
        profile
    }

    fn parse_metrics(
        &self,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: i32,
    ) -> Result<ToolExecutionMetrics, MetricParseError> {
        let stdout_str = std::str::from_utf8(stdout).map_err(|_| MetricParseError::InvalidUtf8)?;
        let _stderr_str = std::str::from_utf8(stderr).map_err(|_| MetricParseError::InvalidUtf8)?;

        if let Some(report) = extract_report_from_stdout(stdout_str)? {
            let artifacts = report
                .publish_order
                .iter()
                .map(|c| match &c.etag {
                    Some(etag) => format!("{}@{} ({etag})", c.name, c.version),
                    None if c.skipped_existing => {
                        format!("{}@{} (existing)", c.name, c.version)
                    }
                    None => format!("{}@{} (staged)", c.name, c.version),
                })
                .collect();

            return Ok(ToolExecutionMetrics {
                duration_ms: report.duration_ms,
                exit_code,
                artifacts,
                cd_staging_report: Some(report),
                ..ToolExecutionMetrics::default()
            });
        }

        Ok(ToolExecutionMetrics {
            exit_code,
            ..ToolExecutionMetrics::default()
        })
    }
}

fn extract_report_from_stdout(
    stdout: &str,
) -> Result<Option<CdStagingRunReport>, MetricParseError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if let Some(marker_line) = stdout
        .lines()
        .rev()
        .find_map(|line| line.trim_start().strip_prefix(CD_STAGING_REPORT_PREFIX))
    {
        return parse_report_json(marker_line.trim()).map(Some);
    }

    if trimmed.starts_with('{') {
        return parse_report_json(trimmed).map(Some);
    }

    Ok(None)
}

fn parse_report_json(json_str: &str) -> Result<CdStagingRunReport, MetricParseError> {
    let report: CdStagingRunReport = serde_json::from_str(json_str).map_err(|err| {
        MetricParseError::MalformedOutput(format!("invalid CdStagingRunReport JSON: {err}"))
    })?;
    if report.ecosystem != "cargo" {
        return Err(MetricParseError::MalformedOutput(format!(
            "expected CdStagingRunReport ecosystem 'cargo', found '{}'",
            report.ecosystem
        )));
    }
    if report.registry != REQUIRED_REGISTRY {
        return Err(MetricParseError::MalformedOutput(format!(
            "expected CdStagingRunReport registry '{REQUIRED_REGISTRY}', found '{}'",
            report.registry
        )));
    }
    Ok(report)
}

/// Subset of `cargo metadata --format-version 1` schema required for publish planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceMetadata {
    /// Packages present in the workspace.
    pub packages: Vec<MetadataPackage>,
    /// Package IDs belonging to workspace members.
    pub workspace_members: Vec<String>,
    /// Canonical workspace root path.
    pub workspace_root: String,
}

/// Package entry inside `cargo metadata` output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataPackage {
    /// Crate package name.
    pub name: String,
    /// Package SemVer string.
    pub version: String,
    /// Canonical Cargo package ID.
    pub id: String,
    /// Declared SPDX license expression from `Cargo.toml`.
    #[serde(default)]
    pub license: Option<String>,
    /// Optional `license-file` relative path from `Cargo.toml`.
    #[serde(default)]
    pub license_file: Option<String>,
    /// Declared dependencies.
    #[serde(default)]
    pub dependencies: Vec<MetadataDep>,
    /// Cargo compilation targets (`lib`, `bin`, `test`, etc.).
    #[serde(default)]
    pub targets: Vec<MetadataTarget>,
    /// Path to package `Cargo.toml`.
    pub manifest_path: String,
    /// Optional Cargo `publish` registry list (`None` = unrestricted, `Some([])` = disabled).
    #[serde(default)]
    pub publish: Option<Vec<String>>,
}

/// Dependency entry inside `MetadataPackage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataDep {
    /// Target crate package name.
    pub name: String,
    /// Optional registry/git source string.
    #[serde(default)]
    pub source: Option<String>,
    /// Version requirement (`"*"` when omitted in a local path/git dependency).
    #[serde(default)]
    pub req: String,
    /// Dependency kind (`None` = normal, `Some("build")`, `Some("dev")`).
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional target registry specified in `Cargo.toml`.
    #[serde(default)]
    pub registry: Option<String>,
}

/// Target descriptor inside `MetadataPackage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataTarget {
    /// Target name.
    pub name: String,
    /// Target kind list (e.g., `["lib"]`, `["bin"]`, `["proc-macro"]`).
    #[serde(default)]
    pub kind: Vec<String>,
}

/// Validated crate scheduled inside a topological [`PublishPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPackage {
    /// Cargo package ID.
    pub id: String,
    /// Crate package name.
    pub name: String,
    /// Validated SemVer version.
    pub version: String,
    /// Path to crate `Cargo.toml`.
    pub manifest_path: PathBuf,
    /// Directory containing crate `Cargo.toml`.
    pub package_dir: PathBuf,
    /// Declared `package.license` string.
    pub license: Option<String>,
    /// Declared `package.license_file` string.
    pub license_file: Option<String>,
    /// Whether this crate exports a library/proc-macro target importable by consumers.
    pub has_lib_target: bool,
    /// Whether this crate declares any binary (`bin`) target.
    pub has_bin_target: bool,
}

/// Deterministic topological publish plan across workspace packages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishPlan {
    /// Workspace root directory.
    pub workspace_root: PathBuf,
    /// Staged packages ordered so dependencies precede dependents.
    pub ordered_packages: Vec<PlannedPackage>,
}

/// Execute `cargo metadata --format-version 1 --no-deps --offline` for `manifest_path`.
///
/// # Errors
///
/// Returns [`DeployError::MetadataCommandFailed`] or [`DeployError::InvalidMetadataJson`]
/// if `cargo metadata` fails or outputs unexpected JSON.
pub fn load_cargo_metadata(manifest_path: &Path) -> Result<WorkspaceMetadata, DeployError> {
    load_cargo_metadata_with_registry(manifest_path, None)
}

/// Execute `cargo metadata --format-version 1 --no-deps --offline` with optional `muregist` URL injection.
///
/// # Errors
///
/// Returns [`DeployError::Validation`], [`DeployError::MetadataCommandFailed`], or
/// [`DeployError::InvalidMetadataJson`] if validation fails, `cargo metadata` exits non-zero,
/// or stdout is invalid JSON.
pub fn load_cargo_metadata_with_registry(
    manifest_path: &Path,
    registry_url: Option<&str>,
) -> Result<WorkspaceMetadata, DeployError> {
    let mut cmd = Command::new("cargo");
    if let Some(parent) = manifest_path.parent() {
        if !parent.as_os_str().is_empty() {
            cmd.current_dir(parent);
        }
    }
    if let Some(url) = registry_url {
        let (_, sparse_index) = normalize_registry_urls(url)?;
        cmd.env("CARGO_REGISTRIES_MUREGIST_INDEX", sparse_index);
    }

    let output = cmd
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
        ])
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(DeployError::MetadataCommandFailed(stderr));
    }

    serde_json::from_slice::<WorkspaceMetadata>(&output.stdout)
        .map_err(|err| DeployError::InvalidMetadataJson(err.to_string()))
}

fn validate_semver_strict(raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("package version must not be empty".to_string());
    }
    let without_build = trimmed.split('+').next().unwrap_or("");
    let core = without_build.split('-').next().unwrap_or("");
    let mut parts = core.split('.');
    let major = parts.next().unwrap_or("");
    let minor = parts.next().unwrap_or("");
    let patch = parts.next().unwrap_or("");
    if parts.next().is_some()
        || [major, minor, patch]
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("invalid SemVer '{trimmed}'"));
    }
    Ok(())
}

fn normalized_index_match_key(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    trimmed
        .strip_prefix("sparse+")
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

fn validate_package_registry_rules(
    pkg: &MetadataPackage,
    expected_registry_index: Option<&str>,
) -> Result<(), DeployError> {
    if let Some(publish_list) = &pkg.publish {
        if publish_list.is_empty() {
            return Err(DeployError::ForbiddenRegistry {
                package: pkg.name.clone(),
                detail: "package sets publish = false / [] and cannot be published".to_string(),
            });
        }
        if !publish_list.iter().any(|entry| entry == REQUIRED_REGISTRY) {
            return Err(DeployError::ForbiddenRegistry {
                package: pkg.name.clone(),
                detail: format!(
                    "package publish list [{}] excludes '{REQUIRED_REGISTRY}'",
                    publish_list.join(", ")
                ),
            });
        }
    }

    for dep in &pkg.dependencies {
        if let Some(dep_registry) = &dep.registry {
            if is_forbidden_crates_io_url(dep_registry) {
                return Err(DeployError::ForbiddenRegistry {
                    package: pkg.name.clone(),
                    detail: format!(
                        "dependency '{}' targets forbidden crates.io registry '{}'",
                        dep.name, dep_registry
                    ),
                });
            }
            if dep_registry == REQUIRED_REGISTRY {
                continue;
            }
            if let Some(expected_index) = expected_registry_index {
                if normalized_index_match_key(dep_registry)
                    != normalized_index_match_key(expected_index)
                {
                    return Err(DeployError::ForbiddenRegistry {
                        package: pkg.name.clone(),
                        detail: format!(
                            "dependency '{}' pins non-muregist registry '{}' (expected '{expected_index}')",
                            dep.name, dep_registry
                        ),
                    });
                }
            } else if validate_registry_url(dep_registry, "dep.registry").is_err() {
                return Err(DeployError::ForbiddenRegistry {
                    package: pkg.name.clone(),
                    detail: format!(
                        "dependency '{}' pins non-muregist registry '{}'",
                        dep.name, dep_registry
                    ),
                });
            }
        }
    }

    Ok(())
}

fn is_normal_or_build_dep(dep: &MetadataDep) -> bool {
    !matches!(dep.kind.as_deref(), Some("dev"))
}

fn is_missing_dep_version_req(req: &str) -> bool {
    let trimmed = req.trim();
    trimmed.is_empty() || trimmed == "*"
}

/// Compute a deterministic topological publish plan from `metadata`.
///
/// Validates package SemVer versions, non-dev dependency explicit version requirements,
/// strict `muregist` registry constraints, and dependency acyclicity.
///
/// # Errors
///
/// Returns [`DeployError::UnknownPackages`], [`DeployError::ForbiddenRegistry`],
/// [`DeployError::MissingVersion`], or [`DeployError::CyclicDependency`].
pub fn compute_publish_plan(
    metadata: &WorkspaceMetadata,
    requested_packages: &[String],
) -> Result<PublishPlan, DeployError> {
    compute_publish_plan_with_registry(metadata, requested_packages, None)
}

/// Compute a deterministic topological publish plan validating resolved dependency registries
/// against an explicit `muregist` index URL when supplied.
///
/// # Errors
///
/// Returns [`DeployError::UnknownPackages`], [`DeployError::ForbiddenRegistry`],
/// [`DeployError::MissingVersion`], [`DeployError::CyclicDependency`], or [`DeployError::Validation`].
pub fn compute_publish_plan_with_registry(
    metadata: &WorkspaceMetadata,
    requested_packages: &[String],
    registry_url: Option<&str>,
) -> Result<PublishPlan, DeployError> {
    let expected_sparse_index = match registry_url {
        Some(url) => Some(normalize_registry_urls(url)?.1),
        None => None,
    };

    let member_ids: BTreeSet<&str> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    let workspace_pkgs: BTreeMap<String, &MetadataPackage> = metadata
        .packages
        .iter()
        .filter(|pkg| member_ids.is_empty() || member_ids.contains(pkg.id.as_str()))
        .map(|pkg| (pkg.name.clone(), pkg))
        .collect();

    let selected_names = select_packages_to_stage(&workspace_pkgs, requested_packages)?;
    let selected_set: BTreeSet<&str> = selected_names.iter().map(String::as_str).collect();

    for name in &selected_names {
        let pkg = workspace_pkgs[name.as_str()];
        validate_semver_strict(&pkg.version).map_err(|detail| DeployError::MissingVersion {
            package: pkg.name.clone(),
            dependency: None,
            detail,
        })?;
        validate_package_registry_rules(pkg, expected_sparse_index.as_deref())?;
    }

    let mut edges: BTreeMap<String, BTreeSet<String>> = selected_names
        .iter()
        .map(|name| (name.clone(), BTreeSet::new()))
        .collect();
    let mut indegree: BTreeMap<String, usize> = selected_names
        .iter()
        .map(|name| (name.clone(), 0))
        .collect();

    for name in &selected_names {
        let pkg = workspace_pkgs[name.as_str()];
        for dep in &pkg.dependencies {
            if !is_normal_or_build_dep(dep) {
                continue;
            }
            if workspace_pkgs.contains_key(&dep.name) {
                if is_missing_dep_version_req(&dep.req) {
                    return Err(DeployError::MissingVersion {
                        package: pkg.name.clone(),
                        dependency: Some(dep.name.clone()),
                        detail: format!(
                            "workspace dependency '{}' requires an explicit SemVer constraint (found '{}')",
                            dep.name, dep.req
                        ),
                    });
                }
                if !selected_set.contains(dep.name.as_str()) {
                    return Err(DeployError::ForbiddenRegistry {
                        package: pkg.name.clone(),
                        detail: format!(
                            "depends on unpublished workspace member '{}' excluded from staging",
                            dep.name
                        ),
                    });
                }
                if dep.name == pkg.name {
                    return Err(DeployError::CyclicDependency {
                        cycle: vec![pkg.name.clone(), pkg.name.clone()],
                    });
                }
                if edges
                    .get_mut(&dep.name)
                    .is_some_and(|dependents| dependents.insert(pkg.name.clone()))
                {
                    if let Some(deg) = indegree.get_mut(&pkg.name) {
                        *deg += 1;
                    }
                }
            } else if is_missing_dep_version_req(&dep.req) {
                return Err(DeployError::MissingVersion {
                    package: pkg.name.clone(),
                    dependency: Some(dep.name.clone()),
                    detail: format!(
                        "dependency '{}' requires an explicit SemVer constraint (found '{}')",
                        dep.name, dep.req
                    ),
                });
            }
        }
    }

    let order = kahn_topological_order(&edges, &mut indegree)?;
    let ordered_packages = order
        .into_iter()
        .map(|name| build_planned_package(workspace_pkgs[name.as_str()]))
        .collect();

    Ok(PublishPlan {
        workspace_root: PathBuf::from(&metadata.workspace_root),
        ordered_packages,
    })
}

fn select_packages_to_stage(
    workspace_pkgs: &BTreeMap<String, &MetadataPackage>,
    requested_packages: &[String],
) -> Result<Vec<String>, DeployError> {
    if requested_packages.is_empty() {
        let mut selected = Vec::new();
        for (name, pkg) in workspace_pkgs {
            if pkg.publish.as_ref().is_some_and(Vec::is_empty) {
                continue;
            }
            selected.push(name.clone());
        }
        return Ok(selected);
    }

    let missing: Vec<String> = requested_packages
        .iter()
        .filter(|pkg| !workspace_pkgs.contains_key(pkg.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(DeployError::UnknownPackages(missing));
    }

    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for pkg in requested_packages {
        if seen.insert(pkg.clone()) {
            selected.push(pkg.clone());
        }
    }
    Ok(selected)
}

fn kahn_topological_order(
    edges: &BTreeMap<String, BTreeSet<String>>,
    indegree: &mut BTreeMap<String, usize>,
) -> Result<Vec<String>, DeployError> {
    let mut ready: BTreeSet<String> = indegree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(name, _)| name.clone())
        .collect();
    let mut ordered = Vec::with_capacity(edges.len());

    while let Some(node) = ready.pop_first() {
        ordered.push(node.clone());
        if let Some(dependents) = edges.get(&node) {
            for dep in dependents {
                if let Some(deg) = indegree.get_mut(dep) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        ready.insert(dep.clone());
                    }
                }
            }
        }
    }

    if ordered.len() != edges.len() {
        let cycle = find_cycle_path(edges, indegree);
        return Err(DeployError::CyclicDependency { cycle });
    }

    Ok(ordered)
}

fn find_cycle_path(
    edges: &BTreeMap<String, BTreeSet<String>>,
    indegree: &BTreeMap<String, usize>,
) -> Vec<String> {
    let remaining: BTreeSet<&str> = indegree
        .iter()
        .filter_map(|(name, deg)| (*deg > 0).then_some(name.as_str()))
        .collect();

    let mut state: BTreeMap<&str, u8> = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();

    for &start in &remaining {
        if state.contains_key(start) {
            continue;
        }
        if let Some(cycle) = dfs_cycle(start, edges, &remaining, &mut state, &mut stack) {
            return cycle;
        }
    }

    remaining.into_iter().map(str::to_string).collect()
}

fn dfs_cycle<'a>(
    node: &'a str,
    edges: &'a BTreeMap<String, BTreeSet<String>>,
    remaining: &BTreeSet<&str>,
    state: &mut BTreeMap<&'a str, u8>,
    stack: &mut Vec<String>,
) -> Option<Vec<String>> {
    state.insert(node, 1);
    stack.push(node.to_string());

    if let Some(neighbors) = edges.get(node) {
        for next in neighbors {
            let next_str = next.as_str();
            if !remaining.contains(next_str) {
                continue;
            }
            match state.get(next_str).copied() {
                Some(1) => {
                    let pos = stack.iter().position(|item| item == next_str).unwrap_or(0);
                    let mut cycle = stack[pos..].to_vec();
                    cycle.push(next_str.to_string());
                    return Some(cycle);
                }
                Some(_) => {}
                None => {
                    if let Some(found) = dfs_cycle(next_str, edges, remaining, state, stack) {
                        return Some(found);
                    }
                }
            }
        }
    }

    stack.pop();
    state.insert(node, 2);
    None
}

fn build_planned_package(pkg: &MetadataPackage) -> PlannedPackage {
    let manifest_path = PathBuf::from(&pkg.manifest_path);
    let package_dir = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let has_bin_target = pkg
        .targets
        .iter()
        .any(|t| t.kind.iter().any(|k| k == "bin"));
    let has_lib_target = pkg.targets.iter().any(|t| {
        t.kind.iter().any(|k| {
            matches!(
                k.as_str(),
                "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
            )
        })
    });

    PlannedPackage {
        id: pkg.id.clone(),
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        manifest_path,
        package_dir,
        license: pkg.license.clone(),
        license_file: pkg.license_file.clone(),
        has_lib_target,
        has_bin_target,
    }
}

/// Verify two-tier licensing invariants across every crate in `plan`.
///
/// Checks both `Cargo.toml` `license` expressions (`LGPL-3.0-only WITH LGPL-3.0-linking-exception`
/// vs `AGPL-3.0-only`) and the on-disk `LICENSE` (and optional `COPYING`) text.
///
/// # Errors
///
/// Returns [`DeployError::LicensePolicyViolation`] on any unapproved, missing, or mismatched
/// license manifest or `LICENSE` file.
pub fn verify_workspace_licenses(
    plan: &PublishPlan,
    mode: LicensePolicyMode,
) -> Result<BTreeMap<String, LicenseTier>, DeployError> {
    let mut verified = BTreeMap::new();

    for pkg in &plan.ordered_packages {
        let tier = verify_package_license(pkg, &plan.workspace_root, mode)?;
        verified.insert(pkg.name.clone(), tier);
    }

    Ok(verified)
}

fn verify_package_license(
    pkg: &PlannedPackage,
    workspace_root: &Path,
    mode: LicensePolicyMode,
) -> Result<LicenseTier, DeployError> {
    let declared = pkg.license.as_deref().map(str::trim).unwrap_or("");
    let expected_tier = resolve_expected_license_tier(pkg, declared, mode)?;

    if declared != expected_tier.as_spdx() {
        return Err(DeployError::LicensePolicyViolation {
            package: pkg.name.clone(),
            detail: format!(
                "Cargo.toml license '{}' does not match required tier expression '{}'",
                if declared.is_empty() {
                    "<missing>"
                } else {
                    declared
                },
                expected_tier.as_spdx()
            ),
        });
    }

    verify_license_files_on_disk(pkg, workspace_root, expected_tier)?;
    Ok(expected_tier)
}

fn resolve_expected_license_tier(
    pkg: &PlannedPackage,
    declared: &str,
    mode: LicensePolicyMode,
) -> Result<LicenseTier, DeployError> {
    match mode {
        LicensePolicyMode::RequireTier1 => Ok(LicenseTier::Tier1LgplLinkingException),
        LicensePolicyMode::RequireTier2 => Ok(LicenseTier::Tier2Agpl3),
        LicensePolicyMode::Auto => {
            if pkg.has_bin_target {
                Ok(LicenseTier::Tier2Agpl3)
            } else {
                Ok(LicenseTier::Tier1LgplLinkingException)
            }
        }
        LicensePolicyMode::EitherTier => match declared {
            TIER1_LICENSE_SPDX => Ok(LicenseTier::Tier1LgplLinkingException),
            TIER2_LICENSE_SPDX => Ok(LicenseTier::Tier2Agpl3),
            other => Err(DeployError::LicensePolicyViolation {
                package: pkg.name.clone(),
                detail: format!(
                    "unapproved license '{}'; expected '{}' or '{}'",
                    if other.is_empty() { "<missing>" } else { other },
                    TIER1_LICENSE_SPDX,
                    TIER2_LICENSE_SPDX
                ),
            }),
        },
    }
}

fn resolve_license_file_path(pkg: &PlannedPackage, workspace_root: &Path) -> Option<PathBuf> {
    if let Some(rel) = &pkg.license_file {
        let candidate = pkg.package_dir.join(rel);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let pkg_license = pkg.package_dir.join("LICENSE");
    if pkg_license.is_file() {
        return Some(pkg_license);
    }
    let ws_license = workspace_root.join("LICENSE");
    if ws_license.is_file() {
        return Some(ws_license);
    }
    None
}

fn verify_license_files_on_disk(
    pkg: &PlannedPackage,
    workspace_root: &Path,
    tier: LicenseTier,
) -> Result<(), DeployError> {
    let license_path = resolve_license_file_path(pkg, workspace_root).ok_or_else(|| {
        DeployError::LicensePolicyViolation {
            package: pkg.name.clone(),
            detail: format!(
                "missing LICENSE file in '{}' or workspace root '{}'",
                pkg.package_dir.display(),
                workspace_root.display()
            ),
        }
    })?;

    let raw_text =
        fs::read_to_string(&license_path).map_err(|err| DeployError::LicensePolicyViolation {
            package: pkg.name.clone(),
            detail: format!("failed to read {}: {err}", license_path.display()),
        })?;
    let lower = raw_text.to_ascii_lowercase();

    match tier {
        LicenseTier::Tier1LgplLinkingException => {
            if !lower.contains("gnu lesser general public license") {
                return Err(DeployError::LicensePolicyViolation {
                    package: pkg.name.clone(),
                    detail: format!(
                        "{} does not contain GNU Lesser General Public License v3 text",
                        license_path.display()
                    ),
                });
            }
            if lower.contains("gnu affero general public license") {
                return Err(DeployError::LicensePolicyViolation {
                    package: pkg.name.clone(),
                    detail: format!(
                        "{} declares GNU Affero GPL text for a Tier-1 LGPL crate",
                        license_path.display()
                    ),
                });
            }
            let has_exception_in_license =
                lower.contains("linking exception") || lower.contains("lgpl-3.0-linking-exception");
            let has_sibling_exception =
                read_optional_lowercase(&pkg.package_dir.join("LINKING-EXCEPTION"))
                    .or_else(|| read_optional_lowercase(&workspace_root.join("LINKING-EXCEPTION")))
                    .is_some_and(|txt| txt.contains("linking exception"));

            if !has_exception_in_license && !has_sibling_exception {
                return Err(DeployError::LicensePolicyViolation {
                    package: pkg.name.clone(),
                    detail: format!(
                        "{} is missing the required LGPL-3.0 linking exception clause",
                        license_path.display()
                    ),
                });
            }

            let copying_path = pkg.package_dir.join("COPYING");
            if copying_path.is_file() {
                let copying_lower = read_optional_lowercase(&copying_path).unwrap_or_default();
                if !copying_lower.contains("gnu general public license") {
                    return Err(DeployError::LicensePolicyViolation {
                        package: pkg.name.clone(),
                        detail: format!(
                            "{} does not contain companion GNU GPLv3 text",
                            copying_path.display()
                        ),
                    });
                }
            }
        }
        LicenseTier::Tier2Agpl3 => {
            if !lower.contains("gnu affero general public license") {
                return Err(DeployError::LicensePolicyViolation {
                    package: pkg.name.clone(),
                    detail: format!(
                        "{} does not contain GNU Affero General Public License v3 text required for Tier-2 AGPL crates",
                        license_path.display()
                    ),
                });
            }
        }
    }

    Ok(())
}

fn read_optional_lowercase(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.to_ascii_lowercase())
}

/// Compute the Cargo sparse-index relative path for `crate_name`.
///
/// Rules follow the Cargo registry index specification:
/// `1/{name}`, `2/{name}`, `3/{c0}/{name}`, or `{c0..2}/{c2..4}/{name}` (ASCII lowercase).
///
/// # Errors
///
/// Returns [`DeployError::Validation`] if `crate_name` is empty or contains invalid characters.
pub fn cargo_index_relative_path(crate_name: &str) -> Result<String, DeployError> {
    validate_package_name(crate_name, "crate_name")?;
    let lower = crate_name.to_ascii_lowercase();
    let rel = match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    };
    Ok(rel)
}

/// Parse newline-delimited Cargo sparse index JSON lines and verify whether `(crate_name, version)`
/// is present and unyanked.
#[must_use]
pub fn parse_index_has_version(body: &str, crate_name: &str, version: &str) -> bool {
    #[derive(Deserialize)]
    struct IndexRow {
        name: String,
        vers: String,
        #[serde(default)]
        yanked: bool,
    }

    body.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }
        serde_json::from_str::<IndexRow>(trimmed).is_ok_and(|row| {
            row.name.eq_ignore_ascii_case(crate_name) && row.vers == version && !row.yanked
        })
    })
}

/// Response returned by [`SparseIndexClient::fetch_index_entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseIndexResponse {
    /// HTTP status code (`200`, `304`, `404`, etc.).
    pub status_code: u16,
    /// `ETag` response header value when provided.
    pub etag: Option<String>,
    /// Response body string.
    pub body: String,
}

/// HTTP client abstraction for polling `muregist` sparse index metadata.
pub trait SparseIndexClient: Send + Sync {
    /// Fetch `/index/<index_rel_path>` from `registry_base_url`.
    ///
    /// # Errors
    ///
    /// Returns [`DeployError`] on transport, URL validation, or response parse failures.
    fn fetch_index_entry(
        &self,
        registry_base_url: &str,
        index_rel_path: &str,
        if_none_match: Option<&str>,
    ) -> Result<SparseIndexResponse, DeployError>;
}

/// Production HTTP/HTTPS client polling `muregist` sparse index endpoints.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpSparseIndexClient;

impl SparseIndexClient for HttpSparseIndexClient {
    fn fetch_index_entry(
        &self,
        registry_base_url: &str,
        index_rel_path: &str,
        if_none_match: Option<&str>,
    ) -> Result<SparseIndexResponse, DeployError> {
        let (_, sparse_index_base) = normalize_registry_urls(registry_base_url)?;
        let http_base = sparse_index_base
            .strip_prefix("sparse+")
            .unwrap_or(&sparse_index_base);
        let url = format!("{http_base}{index_rel_path}");

        if let Some(rest) = http_base.strip_prefix("http://") {
            let path =
                format!("/{}/{}", index_prefix_path(rest), index_rel_path).replace("//", "/");
            let host_port = rest.split('/').next().unwrap_or("");
            return http_plain_get(host_port, &path, if_none_match);
        }

        http_curl_get(&url, if_none_match)
    }
}

fn index_prefix_path(rest: &str) -> &str {
    rest.split_once('/')
        .map(|(_, path)| path.trim_matches('/'))
        .unwrap_or("")
}

/// Normalize `raw_url` into `(registry_http_base, sparse_index_url)` with trailing slash on index.
///
/// # Errors
///
/// Returns [`DeployError::Validation`] if `raw_url` targets `crates.io` or has an invalid scheme.
pub fn normalize_registry_urls(raw_url: &str) -> Result<(String, String), DeployError> {
    validate_registry_url(raw_url, "registry_url")?;
    let without_sparse = raw_url
        .trim()
        .strip_prefix("sparse+")
        .unwrap_or_else(|| raw_url.trim())
        .trim_end_matches('/');
    if let Some(base) = without_sparse.strip_suffix("/index") {
        Ok((base.to_string(), format!("sparse+{without_sparse}/")))
    } else {
        Ok((
            without_sparse.to_string(),
            format!("sparse+{without_sparse}/index/"),
        ))
    }
}

fn http_plain_get(
    host_port: &str,
    path: &str,
    if_none_match: Option<&str>,
) -> Result<SparseIndexResponse, DeployError> {
    let connect_target = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    let addr = connect_target
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| DeployError::Io(format!("unable to resolve '{connect_target}'")))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_port}\r\nAccept: text/plain, application/json\r\nConnection: close\r\n"
    );
    if let Some(etag) = if_none_match {
        req.push_str(&format!("If-None-Match: {etag}\r\n"));
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse_http_response(&raw)
}

fn http_curl_get(
    url: &str,
    if_none_match: Option<&str>,
) -> Result<SparseIndexResponse, DeployError> {
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "-i", "--max-time", "5"]);
    if let Some(etag) = if_none_match {
        cmd.arg("-H").arg(format!("If-None-Match: {etag}"));
    }
    cmd.arg(url);
    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(DeployError::Io(format!(
            "curl GET failed for {url}: {stderr}"
        )));
    }
    parse_http_response(&output.stdout)
}

/// Parse an HTTP/1.x raw byte response into [`SparseIndexResponse`].
///
/// # Errors
///
/// Returns [`DeployError::Io`] if headers or chunked transfer encoding cannot be parsed.
pub fn parse_http_response(raw: &[u8]) -> Result<SparseIndexResponse, DeployError> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            DeployError::Io("malformed HTTP response: missing header separator".into())
        })?;
    let header_bytes = &raw[..header_end];
    let body_bytes = &raw[header_end + 4..];

    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| DeployError::Io(format!("malformed HTTP status line: '{status_line}'")))?;

    let mut etag: Option<String> = None;
    let mut is_chunked = false;
    let mut content_len: Option<usize> = None;

    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let name_lower = name.trim().to_ascii_lowercase();
            let val_trimmed = val.trim();
            match name_lower.as_str() {
                "etag" if !val_trimmed.is_empty() => etag = Some(val_trimmed.to_string()),
                "transfer-encoding" if val_trimmed.to_ascii_lowercase().contains("chunked") => {
                    is_chunked = true;
                }
                "content-length" => content_len = val_trimmed.parse::<usize>().ok(),
                _ => {}
            }
        }
    }

    let decoded_bytes = if is_chunked {
        decode_chunked_body(body_bytes)?
    } else if let Some(len) = content_len {
        body_bytes[..len.min(body_bytes.len())].to_vec()
    } else {
        body_bytes.to_vec()
    };

    Ok(SparseIndexResponse {
        status_code,
        etag,
        body: String::from_utf8_lossy(&decoded_bytes).into_owned(),
    })
}

fn decode_chunked_body(mut input: &[u8]) -> Result<Vec<u8>, DeployError> {
    let mut out = Vec::new();
    loop {
        let Some(crlf) = input.windows(2).position(|w| w == b"\r\n") else {
            return Err(DeployError::Io("truncated HTTP chunk size".into()));
        };
        let size_line = String::from_utf8_lossy(&input[..crlf]);
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|_| DeployError::Io(format!("invalid HTTP chunk size '{hex_part}'")))?;
        input = &input[crlf + 2..];
        if chunk_len == 0 {
            break;
        }
        if input.len() < chunk_len + 2 {
            return Err(DeployError::Io("truncated HTTP chunk payload".into()));
        }
        out.extend_from_slice(&input[..chunk_len]);
        input = &input[chunk_len + 2..];
    }
    Ok(out)
}

/// Poll `muregist` sparse index until `(crate_name, version)` appears with a non-empty `ETag`.
///
/// # Errors
///
/// Returns [`DeployError::IndexPollTimeout`] when `timeout` expires before a matching unyanked
/// entry and `ETag` are observed.
pub fn poll_sparse_index_etag(
    client: &dyn SparseIndexClient,
    registry_base_url: &str,
    crate_name: &str,
    version: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(String, String), DeployError> {
    let index_path = cargo_index_relative_path(crate_name)?;
    let start = Instant::now();
    let mut last_error: Option<String>;

    loop {
        match client.fetch_index_entry(registry_base_url, &index_path, None) {
            Ok(resp) if resp.status_code == 200 => {
                let valid_version = parse_index_has_version(&resp.body, crate_name, version);
                match (valid_version, resp.etag) {
                    (true, Some(etag)) if !etag.trim().is_empty() => {
                        return Ok((index_path, etag));
                    }
                    (true, _) => {
                        last_error = Some("index entry present without ETag header".to_string());
                    }
                    (false, _) => {
                        last_error = Some(format!(
                            "version {version} not yet present in sparse index entry"
                        ));
                    }
                }
            }
            Ok(resp) => {
                last_error = Some(format!("HTTP status {}", resp.status_code));
            }
            Err(err) => {
                last_error = Some(err.to_string());
            }
        }

        if start.elapsed() >= timeout {
            return Err(DeployError::IndexPollTimeout {
                package: crate_name.to_string(),
                version: version.to_string(),
                index_path,
                timeout_secs: timeout.as_secs().max(1),
                last_error,
            });
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        thread::sleep(poll_interval.min(remaining));
    }
}

/// Request passed to [`CargoRunner::run_publish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishCommandRequest {
    /// Workspace root directory.
    pub workspace_root: PathBuf,
    /// Package manifest path.
    pub manifest_path: PathBuf,
    /// Crate name to publish.
    pub package_name: String,
    /// Optional `muregist` URL.
    pub registry_url: Option<String>,
    /// Optional token environment variable name.
    pub token_env: Option<String>,
    /// Pass `--dry-run`.
    pub dry_run: bool,
    /// Pass `--allow-dirty`.
    pub allow_dirty: bool,
    /// Pass `--locked`.
    pub locked: bool,
    /// Pass `--no-verify`.
    pub no_verify: bool,
}

/// Outcome returned by [`CargoRunner::run_publish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishCommandOutcome {
    /// Subprocess exit code.
    pub exit_code: i32,
    /// True when `muregist` reported the exact crate version already existed.
    pub already_uploaded: bool,
    /// Captured stderr output.
    pub stderr: String,
}

/// Request passed to [`CargoRunner::run_clean_room_consumer_check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerCheckRequest {
    /// Staged library crates `(name, version)` to resolve from `muregist`.
    pub library_packages: Vec<(String, String)>,
    /// `muregist` base or sparse index URL.
    pub registry_url: String,
    /// Pass `--locked` where applicable.
    pub locked: bool,
}

/// Outcome returned by [`CargoRunner::run_clean_room_consumer_check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerCheckOutcome {
    /// Library crates tested inside consumer crate.
    pub checked_packages: Vec<String>,
    /// Elapsed check time in milliseconds.
    pub duration_ms: u64,
}

/// Execution abstraction for running `cargo publish` and isolated consumer checks.
pub trait CargoRunner: Send + Sync {
    /// Execute `cargo publish --registry muregist` for a single crate.
    ///
    /// # Errors
    ///
    /// Returns [`DeployError::PublishCommandFailed`] on unexpected Cargo failures.
    fn run_publish(
        &self,
        req: &PublishCommandRequest,
    ) -> Result<PublishCommandOutcome, DeployError>;

    /// Generate an isolated temporary consumer crate blocking `crates.io` egress and execute
    /// `cargo check --tests` strictly against `muregist`.
    ///
    /// # Errors
    ///
    /// Returns [`DeployError::ConsumerCheckFailed`] if compilation or resolution fails.
    fn run_clean_room_consumer_check(
        &self,
        req: &ConsumerCheckRequest,
    ) -> Result<ConsumerCheckOutcome, DeployError>;
}

struct CleanRoomTempDir {
    path: PathBuf,
}

impl CleanRoomTempDir {
    fn create() -> std::io::Result<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        let pid = std::process::id();
        for _ in 0..64 {
            let seq = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let candidate = base.join(format!("mu-clean-room-{pid}-{seq}"));
            match fs::create_dir(&candidate) {
                Ok(()) => return Ok(Self { path: candidate }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "exhausted unique clean-room temporary directory attempts",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CleanRoomTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Production [`CargoRunner`] invoking `cargo` subprocesses directly without a shell.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCargoRunner;

impl CargoRunner for SystemCargoRunner {
    fn run_publish(
        &self,
        req: &PublishCommandRequest,
    ) -> Result<PublishCommandOutcome, DeployError> {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(&req.workspace_root).args([
            "publish",
            "--registry",
            REQUIRED_REGISTRY,
            "--package",
            &req.package_name,
        ]);

        if req.dry_run {
            cmd.arg("--dry-run");
        }
        if req.allow_dirty {
            cmd.arg("--allow-dirty");
        }
        if req.locked {
            cmd.arg("--locked");
        }
        if req.no_verify {
            cmd.arg("--no-verify");
        }

        if let Some(url) = &req.registry_url {
            let (_, sparse_index) = normalize_registry_urls(url)?;
            cmd.env("CARGO_REGISTRIES_MUREGIST_INDEX", sparse_index);
        }
        if let Some(token_env) = &req.token_env {
            if let Ok(token_val) = std::env::var(token_env) {
                let trimmed = token_val.trim();
                if !trimmed.is_empty() {
                    cmd.env("CARGO_REGISTRIES_MUREGIST_TOKEN", trimmed);
                }
            }
        }

        let output = cmd.output()?;
        let exit_code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if output.status.success() {
            return Ok(PublishCommandOutcome {
                exit_code,
                already_uploaded: false,
                stderr,
            });
        }

        let lower_err = stderr.to_ascii_lowercase();
        let already_uploaded = lower_err.contains("already uploaded")
            || lower_err.contains("already exists")
            || lower_err.contains("409");
        if already_uploaded {
            return Ok(PublishCommandOutcome {
                exit_code,
                already_uploaded: true,
                stderr,
            });
        }

        Err(DeployError::PublishCommandFailed {
            package: req.package_name.clone(),
            exit_code,
            stderr,
        })
    }

    fn run_clean_room_consumer_check(
        &self,
        req: &ConsumerCheckRequest,
    ) -> Result<ConsumerCheckOutcome, DeployError> {
        let started = Instant::now();
        let (_, sparse_index) = normalize_registry_urls(&req.registry_url)?;

        let temp_root =
            CleanRoomTempDir::create().map_err(|err| DeployError::ConsumerCheckFailed {
                detail: format!("failed to create clean-room tempdir: {err}"),
            })?;
        let cargo_home = temp_root.path().join("cargo_home");
        let consumer_dir = temp_root.path().join("consumer");
        let vendor_dir = consumer_dir.join("forbidden-crates-io-vendor");
        let dot_cargo = consumer_dir.join(".cargo");
        let src_dir = consumer_dir.join("src");
        let tests_dir = consumer_dir.join("tests");

        for dir in [&cargo_home, &vendor_dir, &dot_cargo, &src_dir, &tests_dir] {
            fs::create_dir_all(dir)?;
        }

        let cargo_config = format!(
            "[registries.{REQUIRED_REGISTRY}]\nindex = \"{sparse_index}\"\n\n\
             [source.crates-io]\nreplace-with = \"forbidden-crates-io\"\n\n\
             [source.forbidden-crates-io]\ndirectory = \"forbidden-crates-io-vendor\"\n"
        );
        fs::write(dot_cargo.join("config.toml"), cargo_config)?;

        let mut manifest = String::from(
            "[package]\nname = \"mu-clean-room-consumer\"\nversion = \"0.1.0\"\n\
             edition = \"2021\"\npublish = false\n\n[dependencies]\n",
        );
        let mut checked_packages = Vec::with_capacity(req.library_packages.len());
        let mut import_lines = String::new();
        for (name, version) in &req.library_packages {
            manifest.push_str(&format!(
                "{name} = {{ version = \"={version}\", registry = \"{REQUIRED_REGISTRY}\" }}\n"
            ));
            let ident = name.replace('-', "_");
            import_lines.push_str(&format!("use {ident} as _;\n"));
            checked_packages.push(name.clone());
        }
        fs::write(consumer_dir.join("Cargo.toml"), manifest)?;
        fs::write(src_dir.join("lib.rs"), &import_lines)?;
        fs::write(
            tests_dir.join("consumer_smoke.rs"),
            format!("{import_lines}\n#[test]\nfn consumer_resolves_from_muregist() {{}}\n"),
        )?;

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&consumer_dir)
            .env("CARGO_HOME", &cargo_home)
            .env_remove("CARGO_NET_OFFLINE")
            .args(["check", "--tests"]);
        if req.locked && consumer_dir.join("Cargo.lock").is_file() {
            cmd.arg("--locked");
        }

        let output = cmd.output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(DeployError::ConsumerCheckFailed {
                detail: format!("cargo check --tests failed: {stderr}"),
            });
        }

        Ok(ConsumerCheckOutcome {
            checked_packages,
            duration_ms: duration_u64_ms(started.elapsed()),
        })
    }
}

/// Complete execution configuration passed to [`execute_cargo_deploy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDeployExecutionConfig {
    /// Path to workspace root `Cargo.toml`.
    pub manifest_path: PathBuf,
    /// Verified `cargo-deploy` parameters.
    pub params: CargoDeployParams,
    /// Optional explicit run ID (auto-generated when `None`).
    pub run_id: Option<String>,
    /// Polling interval between sparse-index `ETag` requests.
    pub poll_interval: Duration,
}

impl CargoDeployExecutionConfig {
    /// Construct an execution config from workspace `manifest_path` and [`CargoDeployParams`].
    #[must_use]
    pub fn new(manifest_path: impl Into<PathBuf>, params: CargoDeployParams) -> Self {
        Self {
            manifest_path: manifest_path.into(),
            params,
            run_id: None,
            poll_interval: Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
        }
    }
}

/// Execute full topological staging (`cargo metadata` -> DAG -> two-tier license gate ->
/// staged `cargo publish --registry muregist` -> sparse-index `ETag` poll -> clean-room
/// consumer verification -> [`CdStagingRunReport`]).
///
/// # Errors
///
/// Returns boxed [`DeployRunFailure`] wrapping both the [`DeployError`] and partial
/// [`CdStagingRunReport`] recording the exact `failure_stage` and `failure_detail`.
pub fn execute_cargo_deploy(
    config: &CargoDeployExecutionConfig,
    cargo_runner: &dyn CargoRunner,
    index_client: &dyn SparseIndexClient,
) -> Result<CdStagingRunReport, Box<DeployRunFailure>> {
    let started_epoch_ms = unix_epoch_ms();
    let started = Instant::now();
    let mut report = CdStagingRunReport {
        run_id: config
            .run_id
            .clone()
            .unwrap_or_else(|| format!("cargo-deploy-{started_epoch_ms}")),
        ecosystem: "cargo".to_string(),
        registry: REQUIRED_REGISTRY.to_string(),
        registry_url: config.params.registry_url.clone(),
        workspace_root: config
            .manifest_path
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        dry_run: config.params.dry_run,
        status: "failed".to_string(),
        started_epoch_ms,
        finished_epoch_ms: started_epoch_ms,
        duration_ms: 0,
        publish_order: Vec::new(),
        consumer_check: ConsumerCheckReport {
            executed: false,
            passed: false,
            isolated_cargo_home: true,
            crates_io_blocked: true,
            checked_packages: Vec::new(),
            duration_ms: 0,
            error: None,
        },
        failure_stage: None,
        failure_detail: None,
    };

    let metadata = match load_cargo_metadata_with_registry(
        &config.manifest_path,
        config.params.registry_url.as_deref(),
    ) {
        Ok(m) => {
            report.workspace_root.clone_from(&m.workspace_root);
            m
        }
        Err(err) => return Err(fail_report(report, started, "metadata", err)),
    };

    execute_cargo_deploy_with_metadata(&metadata, config, cargo_runner, index_client)
}

/// Execute full staging given pre-loaded or test-constructed [`WorkspaceMetadata`].
///
/// # Errors
///
/// Returns boxed [`DeployRunFailure`] with `failure_stage` set to `"plan"`, `"license_gate"`,
/// `"publish"`, `"index_poll"`, or `"consumer_check"`.
pub fn execute_cargo_deploy_with_metadata(
    metadata: &WorkspaceMetadata,
    config: &CargoDeployExecutionConfig,
    cargo_runner: &dyn CargoRunner,
    index_client: &dyn SparseIndexClient,
) -> Result<CdStagingRunReport, Box<DeployRunFailure>> {
    let started_epoch_ms = unix_epoch_ms();
    let started = Instant::now();
    let mut report = CdStagingRunReport {
        run_id: config
            .run_id
            .clone()
            .unwrap_or_else(|| format!("cargo-deploy-{started_epoch_ms}")),
        ecosystem: "cargo".to_string(),
        registry: REQUIRED_REGISTRY.to_string(),
        registry_url: config.params.registry_url.clone(),
        workspace_root: metadata.workspace_root.clone(),
        dry_run: config.params.dry_run,
        status: "failed".to_string(),
        started_epoch_ms,
        finished_epoch_ms: started_epoch_ms,
        duration_ms: 0,
        publish_order: Vec::new(),
        consumer_check: ConsumerCheckReport {
            executed: false,
            passed: false,
            isolated_cargo_home: true,
            crates_io_blocked: true,
            checked_packages: Vec::new(),
            duration_ms: 0,
            error: None,
        },
        failure_stage: None,
        failure_detail: None,
    };

    let plan = match compute_publish_plan_with_registry(
        metadata,
        &config.params.packages,
        config.params.registry_url.as_deref(),
    ) {
        Ok(plan) => plan,
        Err(err) => return Err(fail_report(report, started, "plan", err)),
    };

    let license_map = match verify_workspace_licenses(&plan, config.params.license_mode) {
        Ok(map) => map,
        Err(err) => return Err(fail_report(report, started, "license_gate", err)),
    };

    if !config.params.dry_run && config.params.registry_url.is_none() {
        let err = DeployError::Validation(invalid_arg(
            "registry_url",
            "<none>",
            "registry_url is required for online sparse-index ETag polling and consumer checks",
        ));
        return Err(fail_report(report, started, "plan", err));
    }

    for pkg in &plan.ordered_packages {
        let crate_start = Instant::now();
        let tier = license_map[pkg.name.as_str()];
        let index_path = match cargo_index_relative_path(&pkg.name) {
            Ok(p) => p,
            Err(err) => return Err(fail_report(report, started, "publish", err)),
        };

        let publish_req = PublishCommandRequest {
            workspace_root: plan.workspace_root.clone(),
            manifest_path: pkg.manifest_path.clone(),
            package_name: pkg.name.clone(),
            registry_url: config.params.registry_url.clone(),
            token_env: config.params.token_env.clone(),
            dry_run: config.params.dry_run,
            allow_dirty: config.params.allow_dirty,
            locked: config.params.locked,
            no_verify: config.params.no_verify,
        };
        let publish_out = match cargo_runner.run_publish(&publish_req) {
            Ok(out) => out,
            Err(err) => return Err(fail_report(report, started, "publish", err)),
        };

        let mut etag = None;
        if !config.params.dry_run {
            let base_url = config.params.registry_url.as_deref().unwrap_or("");
            match poll_sparse_index_etag(
                index_client,
                base_url,
                &pkg.name,
                &pkg.version,
                Duration::from_secs(config.params.poll_timeout_secs),
                config.poll_interval,
            ) {
                Ok((_, observed_etag)) => etag = Some(observed_etag),
                Err(err) => return Err(fail_report(report, started, "index_poll", err)),
            }
        }

        report.publish_order.push(StagedCrateReport {
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            license_tier: tier,
            license_spdx: tier.as_spdx().to_string(),
            published: !config.params.dry_run && !publish_out.already_uploaded,
            skipped_existing: publish_out.already_uploaded,
            etag,
            index_path,
            duration_ms: duration_u64_ms(crate_start.elapsed()),
        });
    }

    if !config.params.dry_run && config.params.consumer_check {
        let library_packages: Vec<(String, String)> = plan
            .ordered_packages
            .iter()
            .filter(|p| p.has_lib_target)
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        let req = ConsumerCheckRequest {
            library_packages,
            registry_url: config.params.registry_url.clone().unwrap_or_default(),
            locked: config.params.locked,
        };
        report.consumer_check.executed = true;
        match cargo_runner.run_clean_room_consumer_check(&req) {
            Ok(outcome) => {
                report.consumer_check.passed = true;
                report.consumer_check.checked_packages = outcome.checked_packages;
                report.consumer_check.duration_ms = outcome.duration_ms;
            }
            Err(err) => {
                report.consumer_check.passed = false;
                report.consumer_check.error = Some(err.to_string());
                return Err(fail_report(report, started, "consumer_check", err));
            }
        }
    }

    report.status = "passed".to_string();
    report.finished_epoch_ms = unix_epoch_ms();
    report.duration_ms = duration_u64_ms(started.elapsed());
    Ok(report)
}

fn fail_report(
    mut report: CdStagingRunReport,
    started: Instant,
    stage: &str,
    error: DeployError,
) -> Box<DeployRunFailure> {
    report.status = "failed".to_string();
    report.finished_epoch_ms = unix_epoch_ms();
    report.duration_ms = duration_u64_ms(started.elapsed());
    report.failure_stage = Some(stage.to_string());
    report.failure_detail = Some(error.to_string());
    Box::new(DeployRunFailure { error, report })
}

fn duration_u64_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_epoch_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    u64::try_from(millis).unwrap_or(u64::MAX)
}

impl fmt::Display for LicensePolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn pkg_with_targets(
        name: &str,
        version: &str,
        license: Option<&str>,
        manifest_path: &Path,
        deps: Vec<MetadataDep>,
        kinds: Vec<&str>,
        publish: Option<Vec<String>>,
    ) -> MetadataPackage {
        MetadataPackage {
            name: name.to_string(),
            version: version.to_string(),
            id: format!("path+file://{}#{version}", manifest_path.display()),
            license: license.map(str::to_string),
            license_file: None,
            dependencies: deps,
            targets: kinds
                .into_iter()
                .map(|k| MetadataTarget {
                    name: name.replace('-', "_"),
                    kind: vec![k.to_string()],
                })
                .collect(),
            manifest_path: manifest_path.display().to_string(),
            publish,
        }
    }

    fn ws_dep(name: &str, req: &str, kind: Option<&str>) -> MetadataDep {
        MetadataDep {
            name: name.to_string(),
            source: None,
            req: req.to_string(),
            kind: kind.map(str::to_string),
            registry: None,
        }
    }

    fn write_tier1_license(dir: &Path) {
        fs::write(
            dir.join("LICENSE"),
            "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n\nLGPL-3.0 Linking Exception\n",
        )
        .expect("write tier1 LICENSE");
    }

    fn write_tier2_license(dir: &Path) {
        fs::write(
            dir.join("LICENSE"),
            "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n",
        )
        .expect("write tier2 LICENSE");
    }

    #[test]
    fn test_cargo_deploy_adapter_rejects_non_muregist_and_crates_io() {
        let adapter = CargoDeployAdapter;

        let err = adapter
            .validate(&ToolInvocation::new(
                "cargo-deploy",
                ["--registry", "crates-io"],
            ))
            .expect_err("crates-io registry must fail");
        assert!(matches!(err, ToolValidationError::InvalidArgValue { .. }));

        let err_param = adapter
            .validate(
                &ToolInvocation::new("cargo-deploy", Vec::<String>::new())
                    .with_param("registry", "upstream"),
            )
            .expect_err("non-muregist param must fail");
        assert!(matches!(
            err_param,
            ToolValidationError::InvalidArgValue { .. }
        ));

        let err_url = adapter
            .validate(
                &ToolInvocation::new("cargo-deploy", Vec::<String>::new())
                    .with_param("registry_url", "sparse+https://index.crates.io/"),
            )
            .expect_err("crates.io index URL must fail");
        assert!(matches!(
            err_url,
            ToolValidationError::InvalidArgValue { .. }
        ));

        let err_env = adapter
            .validate(
                &ToolInvocation::new("cargo-deploy", Vec::<String>::new())
                    .with_env("CARGO_REGISTRY_DEFAULT", "crates-io"),
            )
            .expect_err("CARGO_REGISTRY_DEFAULT != muregist must fail");
        assert!(matches!(
            err_env,
            ToolValidationError::InvalidArgValue { .. }
        ));
    }

    #[test]
    fn test_cargo_deploy_adapter_typed_params_build_argv_and_sandbox() {
        let adapter = CargoDeployAdapter;
        let inv = ToolInvocation::new("cargo-deploy", ["--locked"])
            .with_param("registry", "muregist")
            .with_param("registry_url", "https://registry.example.invalid:8444")
            .with_param("packages", vec!["crate-a", "crate-b"])
            .with_param("license_tier", "either")
            .with_param("dry_run", true)
            .with_param("poll_timeout_secs", 45_i64);

        adapter.validate(&inv).expect("valid invocation");
        let argv = adapter.build_argv(&inv).expect("build argv");
        let strings: Vec<String> = argv
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            strings,
            vec![
                "cargo",
                "deploy",
                "--registry",
                "muregist",
                "--registry-url",
                "https://registry.example.invalid:8444",
                "-p",
                "crate-a",
                "-p",
                "crate-b",
                "--license-tier",
                "either",
                "--dry-run",
                "--locked",
                "--poll-timeout-secs",
                "45",
            ]
        );

        let profile = adapter.sandbox_profile(&inv);
        assert!(profile.allow_network);
        assert!(profile
            .allowed_egress_hosts
            .iter()
            .any(|h| h == "registry.example.invalid:8444"));
        assert!(profile.writable_dirs.iter().any(|d| d == "/tmp"));
    }

    #[test]
    fn test_compute_publish_plan_topological_order_and_cycle_rejection() {
        let p_app = pkg_with_targets(
            "crate-app",
            "0.1.0",
            Some(TIER2_LICENSE_SPDX),
            Path::new("/ws/app/Cargo.toml"),
            vec![
                ws_dep("crate-mid", "^0.1", None),
                ws_dep("crate-core", "^0.1", None),
            ],
            vec!["bin"],
            None,
        );
        let p_mid = pkg_with_targets(
            "crate-mid",
            "0.1.0",
            Some(TIER1_LICENSE_SPDX),
            Path::new("/ws/mid/Cargo.toml"),
            vec![ws_dep("crate-core", "^0.1", None)],
            vec!["lib"],
            None,
        );
        let p_core = pkg_with_targets(
            "crate-core",
            "0.1.0",
            Some(TIER1_LICENSE_SPDX),
            Path::new("/ws/core/Cargo.toml"),
            vec![ws_dep("crate-app", "*", Some("dev"))],
            vec!["lib"],
            None,
        );
        let meta = WorkspaceMetadata {
            workspace_root: "/ws".to_string(),
            workspace_members: vec![p_app.id.clone(), p_mid.id.clone(), p_core.id.clone()],
            packages: vec![p_app, p_mid, p_core],
        };

        let plan = compute_publish_plan(&meta, &[]).expect("acyclic DAG");
        let names: Vec<&str> = plan
            .ordered_packages
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, vec!["crate-core", "crate-mid", "crate-app"]);

        // Introducing a normal dependency cycle must fail deterministically with cycle details.
        let mut cyclic = meta;
        cyclic.packages[2].dependencies = vec![ws_dep("crate-app", "^0.1", None)];
        let err = compute_publish_plan(&cyclic, &[]).expect_err("cyclic DAG must fail");
        match err {
            DeployError::CyclicDependency { cycle } => {
                assert!(cycle.len() >= 3);
                assert_eq!(cycle.first(), cycle.last());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_compute_publish_plan_rejects_missing_versions() {
        let p_empty = pkg_with_targets(
            "crate-core",
            "",
            Some(TIER1_LICENSE_SPDX),
            Path::new("/ws/core/Cargo.toml"),
            Vec::new(),
            vec!["lib"],
            None,
        );
        let missing_pkg_ver = WorkspaceMetadata {
            workspace_root: "/ws".to_string(),
            workspace_members: vec![p_empty.id.clone()],
            packages: vec![p_empty],
        };
        let err = compute_publish_plan(&missing_pkg_ver, &[]).expect_err("empty version fails");
        assert!(matches!(
            err,
            DeployError::MissingVersion {
                dependency: None,
                ..
            }
        ));

        let p_core = pkg_with_targets(
            "crate-core",
            "0.1.0",
            Some(TIER1_LICENSE_SPDX),
            Path::new("/ws/core/Cargo.toml"),
            Vec::new(),
            vec!["lib"],
            None,
        );
        let p_mid = pkg_with_targets(
            "crate-mid",
            "0.1.0",
            Some(TIER1_LICENSE_SPDX),
            Path::new("/ws/mid/Cargo.toml"),
            vec![ws_dep("crate-core", "*", None)],
            vec!["lib"],
            None,
        );
        let missing_dep_ver = WorkspaceMetadata {
            workspace_root: "/ws".to_string(),
            workspace_members: vec![p_core.id.clone(), p_mid.id.clone()],
            packages: vec![p_core, p_mid],
        };
        let dep_err =
            compute_publish_plan(&missing_dep_ver, &[]).expect_err("wildcard dep version fails");
        assert!(matches!(
            dep_err,
            DeployError::MissingVersion {
                dependency: Some(ref dep),
                ..
            } if dep == "crate-core"
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_verify_workspace_licenses_two_tier_enforcement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core_dir = dir.path().join("core");
        let svc_dir = dir.path().join("svc");
        fs::create_dir_all(&core_dir).expect("mkdir core");
        fs::create_dir_all(&svc_dir).expect("mkdir svc");
        write_tier1_license(&core_dir);
        write_tier2_license(&svc_dir);

        let p_core = pkg_with_targets(
            "core",
            "0.1.0",
            Some(TIER1_LICENSE_SPDX),
            &core_dir.join("Cargo.toml"),
            Vec::new(),
            vec!["lib"],
            None,
        );
        let p_svc = pkg_with_targets(
            "svc",
            "0.1.0",
            Some(TIER2_LICENSE_SPDX),
            &svc_dir.join("Cargo.toml"),
            vec![ws_dep("core", "^0.1", None)],
            vec!["lib", "bin"],
            None,
        );
        let meta = WorkspaceMetadata {
            workspace_root: dir.path().display().to_string(),
            workspace_members: vec![p_core.id.clone(), p_svc.id.clone()],
            packages: vec![p_core, p_svc],
        };

        let plan = compute_publish_plan(&meta, &[]).expect("valid plan");
        let verified = verify_workspace_licenses(&plan, LicensePolicyMode::Auto)
            .expect("auto mode verifies Tier-1 lib + Tier-2 bin");
        assert_eq!(verified["core"], LicenseTier::Tier1LgplLinkingException);
        assert_eq!(verified["svc"], LicenseTier::Tier2Agpl3);

        // Tamper svc LICENSE to plain MIT -> must fail license gate.
        fs::write(svc_dir.join("LICENSE"), "MIT License\n").expect("write MIT");
        let mismatch = verify_workspace_licenses(&plan, LicensePolicyMode::Auto)
            .expect_err("MIT LICENSE text must fail");
        assert!(matches!(
            mismatch,
            DeployError::LicensePolicyViolation { ref package, .. } if package == "svc"
        ));

        // Restore AGPL LICENSE, swap svc Cargo.toml to unapproved MIT -> must fail.
        write_tier2_license(&svc_dir);
        let mut bad_manifest = meta;
        bad_manifest.packages[1].license = Some("MIT".to_string());
        let bad_plan = compute_publish_plan(&bad_manifest, &[]).expect("plan");
        let spdx_err = verify_workspace_licenses(&bad_plan, LicensePolicyMode::EitherTier)
            .expect_err("MIT SPDX fails EitherTier");
        assert!(matches!(
            spdx_err,
            DeployError::LicensePolicyViolation { ref package, .. } if package == "svc"
        ));
    }

    #[test]
    fn test_cargo_index_relative_path_and_http_chunked_parsing() {
        assert_eq!(cargo_index_relative_path("a").unwrap(), "1/a");
        assert_eq!(cargo_index_relative_path("ab").unwrap(), "2/ab");
        assert_eq!(cargo_index_relative_path("foo").unwrap(), "3/f/foo");
        assert_eq!(
            cargo_index_relative_path("mu-ci-tools").unwrap(),
            "mu/-c/mu-ci-tools"
        );

        let chunk_payload = "{\"name\":\"k3\",\"vers\":\"0.1.0\"}\n";
        let raw = format!(
            "HTTP/1.1 200 OK\r\nETag: \"sha256:deadbeef\"\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{chunk_payload}\r\n0\r\n\r\n",
            chunk_payload.len()
        );
        let parsed = parse_http_response(raw.as_bytes()).expect("parse chunked response");
        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.etag.as_deref(), Some("\"sha256:deadbeef\""));
        assert!(parse_index_has_version(&parsed.body, "k3", "0.1.0"));
        assert!(!parse_index_has_version(&parsed.body, "k3", "0.2.0"));
    }

    struct MockIndex {
        responses: Mutex<BTreeMap<String, Vec<SparseIndexResponse>>>,
    }

    impl SparseIndexClient for MockIndex {
        fn fetch_index_entry(
            &self,
            _registry_base_url: &str,
            index_rel_path: &str,
            _if_none_match: Option<&str>,
        ) -> Result<SparseIndexResponse, DeployError> {
            let mut guard = self.responses.lock().expect("lock");
            let queue = guard
                .get_mut(index_rel_path)
                .ok_or_else(|| DeployError::Io("unexpected index path".into()))?;
            if queue.len() > 1 {
                Ok(queue.remove(0))
            } else {
                Ok(queue[0].clone())
            }
        }
    }

    struct MockCargoRunner {
        published: Mutex<Vec<String>>,
    }

    impl CargoRunner for MockCargoRunner {
        fn run_publish(
            &self,
            req: &PublishCommandRequest,
        ) -> Result<PublishCommandOutcome, DeployError> {
            self.published
                .lock()
                .expect("lock")
                .push(req.package_name.clone());
            Ok(PublishCommandOutcome {
                exit_code: 0,
                already_uploaded: false,
                stderr: String::new(),
            })
        }

        fn run_clean_room_consumer_check(
            &self,
            req: &ConsumerCheckRequest,
        ) -> Result<ConsumerCheckOutcome, DeployError> {
            assert!(!is_forbidden_crates_io_url(&req.registry_url));
            Ok(ConsumerCheckOutcome {
                checked_packages: req
                    .library_packages
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect(),
                duration_ms: 15,
            })
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_execute_cargo_deploy_staged_order_poll_and_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core_dir = dir.path().join("mu-core");
        let ctl_dir = dir.path().join("mu-ctl");
        fs::create_dir_all(&core_dir).expect("mkdir");
        fs::create_dir_all(&ctl_dir).expect("mkdir");
        write_tier1_license(&core_dir);
        write_tier2_license(&ctl_dir);

        let p_ctl = pkg_with_targets(
            "mu-ctl",
            "0.1.0",
            Some(TIER2_LICENSE_SPDX),
            &ctl_dir.join("Cargo.toml"),
            vec![ws_dep("mu-core", "^0.1", None)],
            vec!["lib", "bin"],
            None,
        );
        let p_core = pkg_with_targets(
            "mu-core",
            "0.1.0",
            Some(TIER1_LICENSE_SPDX),
            &core_dir.join("Cargo.toml"),
            Vec::new(),
            vec!["lib"],
            None,
        );
        let meta = WorkspaceMetadata {
            workspace_root: dir.path().display().to_string(),
            workspace_members: vec![p_core.id.clone(), p_ctl.id.clone()],
            packages: vec![p_ctl, p_core],
        };

        let mut map = BTreeMap::new();
        map.insert(
            cargo_index_relative_path("mu-core").unwrap(),
            vec![
                SparseIndexResponse {
                    status_code: 404,
                    etag: None,
                    body: String::new(),
                },
                SparseIndexResponse {
                    status_code: 200,
                    etag: Some("\"sha256:core123\"".to_string()),
                    body: "{\"name\":\"mu-core\",\"vers\":\"0.1.0\"}\n".to_string(),
                },
            ],
        );
        map.insert(
            cargo_index_relative_path("mu-ctl").unwrap(),
            vec![SparseIndexResponse {
                status_code: 200,
                etag: Some("\"sha256:ctl456\"".to_string()),
                body: "{\"name\":\"mu-ctl\",\"vers\":\"0.1.0\"}\n".to_string(),
            }],
        );
        let index = MockIndex {
            responses: Mutex::new(map),
        };
        let runner = MockCargoRunner {
            published: Mutex::new(Vec::new()),
        };

        let params = CargoDeployParams {
            registry_url: Some("http://127.0.0.1:8080".to_string()),
            poll_timeout_secs: 2,
            ..CargoDeployParams::default()
        };
        let mut cfg = CargoDeployExecutionConfig::new(dir.path().join("Cargo.toml"), params);
        cfg.run_id = Some("run-test-1".to_string());
        cfg.poll_interval = Duration::from_millis(1);

        let report = execute_cargo_deploy_with_metadata(&meta, &cfg, &runner, &index)
            .expect("deploy report");
        assert_eq!(report.ecosystem, "cargo");
        assert_eq!(report.registry, "muregist");
        assert_eq!(report.status, "passed");
        assert_eq!(
            *runner.published.lock().expect("lock"),
            vec!["mu-core".to_string(), "mu-ctl".to_string()]
        );
        assert_eq!(
            report.publish_order[0].etag.as_deref(),
            Some("\"sha256:core123\"")
        );
        assert_eq!(
            report.publish_order[1].etag.as_deref(),
            Some("\"sha256:ctl456\"")
        );
        assert!(report.consumer_check.passed);
        assert_eq!(
            report.consumer_check.checked_packages,
            vec!["mu-core".to_string(), "mu-ctl".to_string()]
        );

        let json = serde_json::to_string(&report).expect("serialize");
        let metrics = CargoDeployAdapter
            .parse_metrics(json.as_bytes(), b"", 0)
            .expect("parse metrics");
        assert_eq!(metrics.cd_staging_report, Some(report));
    }

    #[test]
    fn test_tool_param_value_serde_roundtrip_and_type_validation() {
        let inv = ToolInvocation::new("cargo-deploy", Vec::<String>::new())
            .with_param("registry", "muregist")
            .with_param("dry_run", true)
            .with_param("poll_timeout_secs", 42_i64)
            .with_param("packages", vec!["k3-core", "k3-engine"]);

        let encoded = serde_json::to_string(&inv).expect("serialize invocation");
        let decoded: ToolInvocation =
            serde_json::from_str(&encoded).expect("deserialize invocation");
        assert_eq!(decoded, inv);
        assert_eq!(
            decoded.param("registry").and_then(ToolParamValue::as_str),
            Some("muregist")
        );
        assert_eq!(
            decoded.param("dry_run").and_then(ToolParamValue::as_bool),
            Some(true)
        );
        assert_eq!(
            decoded
                .param("poll_timeout_secs")
                .and_then(ToolParamValue::as_u64),
            Some(42)
        );
        assert_eq!(
            decoded
                .param("packages")
                .and_then(ToolParamValue::as_string_list),
            Some(&["k3-core".to_string(), "k3-engine".to_string()][..])
        );

        let wrong_type = ToolInvocation::new("cargo-deploy", Vec::<String>::new())
            .with_param("dry_run", "not-a-bool");
        assert!(CargoDeployAdapter.validate(&wrong_type).is_err());

        let zero_timeout = ToolInvocation::new("cargo-deploy", Vec::<String>::new())
            .with_param("poll_timeout_secs", 0_i64);
        assert!(CargoDeployAdapter.validate(&zero_timeout).is_err());
    }
}
