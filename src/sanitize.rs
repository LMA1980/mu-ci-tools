//! Strict argument, path, and environment sanitization forbidding shell expansion and wrappers.

use std::path::{Component, Path};

use crate::adapter::{ToolInvocation, ToolParamValue};
use crate::error::ToolValidationError;

/// Multi-character and single-character shell operators and expansion tokens.
///
/// Ordered with multi-character tokens first so that `&&`, `||`, `>>`, `<<`, `$(`, and `${`
/// report the full operator token when matched.
const SHELL_METACHAR_TOKENS: &[&str] = &[
    "&&", "||", ">>", "<<", "$(", "${", ";", "|", "&", "`", ">", "<",
];

/// Prohibited shell binaries, command interpreters, and wrapper execution flags.
const PROHIBITED_SHELL_WRAPPERS: &[&str] = &[
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
    "/bin/zsh",
    "/bin/dash",
    "/usr/bin/env",
    "/usr/bin/sh",
    "/usr/bin/bash",
];

/// Prohibited environment variable names that can hijack process execution or compiler wrappers.
const PROHIBITED_ENV_KEYS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
];

/// Check whether `token` is a prohibited shell wrapper, interpreter, or wrapper flag.
#[must_use]
pub fn is_prohibited_shell_wrapper(token: &str) -> bool {
    let trimmed = token.trim();
    let lower = trimmed.to_ascii_lowercase();

    if PROHIBITED_SHELL_WRAPPERS.contains(&lower.as_str()) {
        return true;
    }

    if lower.starts_with("/bin/sh ")
        || lower.starts_with("/bin/bash ")
        || lower.starts_with("/usr/bin/env ")
        || lower.starts_with("bash ")
        || lower.starts_with("sh ")
        || lower.starts_with("zsh ")
        || lower.starts_with("dash ")
    {
        return true;
    }

    if lower.contains("rustc-wrapper") || lower == "--config" || lower.starts_with("--config=") {
        return true;
    }

    false
}

/// Validate that a string contains no ASCII control characters (`< 0x20` or `0x7F`) or shell
/// metacharacters.
fn validate_no_metachars_or_control(input: &str) -> Result<(), ToolValidationError> {
    for &token in SHELL_METACHAR_TOKENS {
        if input.contains(token) {
            return Err(ToolValidationError::ShellMetacharacterDetected {
                arg: input.to_string(),
                token: token.to_string(),
            });
        }
    }

    if input.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(ToolValidationError::ControlCharacterDetected(
            input.to_string(),
        ));
    }

    Ok(())
}

/// Validate that a single CLI argument is free of shell metacharacters, control characters,
/// and prohibited shell wrappers (`bash`, `sh`, `-c`, `rustc-wrapper`, `--config`, etc.).
///
/// # Errors
///
/// Returns [`ToolValidationError`] if the argument contains shell metacharacters, control
/// characters, or prohibited shell wrappers.
pub fn validate_safe_arg(arg: &str) -> Result<(), ToolValidationError> {
    validate_no_metachars_or_control(arg)?;

    if is_prohibited_shell_wrapper(arg) {
        return Err(ToolValidationError::ProhibitedShellWrapper(arg.to_string()));
    }

    Ok(())
}

/// Validate that `path` is a safe, relative path within a workspace (no leading `/`, no Windows
/// drive prefix, no `..` traversal components, and no shell metacharacters or control characters).
///
/// # Errors
///
/// Returns [`ToolValidationError`] if `path` is empty, absolute, contains `..` traversal,
/// or fails [`validate_safe_arg`].
pub fn validate_safe_relative_path(path: &str) -> Result<(), ToolValidationError> {
    if path.is_empty() {
        return Err(ToolValidationError::PathTraversalDetected(path.to_string()));
    }

    validate_safe_arg(path)?;

    // Reject leading POSIX or Windows root separators and Windows drive letters (e.g. `C:`).
    let bytes = path.as_bytes();
    if path.starts_with('/')
        || path.starts_with('\\')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || Path::new(path).is_absolute()
    {
        return Err(ToolValidationError::AbsolutePathForbidden(path.to_string()));
    }

    // Reject `..` segments across both POSIX (`/`) and Windows (`\`) separators.
    if path == ".."
        || path.starts_with("../")
        || path.ends_with("/..")
        || path.contains("/../")
        || path.starts_with("..\\")
        || path.ends_with("\\..")
        || path.contains("\\..\\")
        || path.split(['/', '\\']).any(|seg| seg == "..")
    {
        return Err(ToolValidationError::PathTraversalDetected(path.to_string()));
    }

    for component in Path::new(path).components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(ToolValidationError::PathTraversalDetected(path.to_string()));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ToolValidationError::AbsolutePathForbidden(path.to_string()));
            }
        }
    }

    Ok(())
}

/// Validate that `rel_path` is a safe relative path and, when resolved against `working_dir`
/// (including any existing symlinks on disk), remains strictly inside `working_dir`.
///
/// # Errors
///
/// Returns [`ToolValidationError`] if `rel_path` is not a valid relative path or resolves
/// outside `working_dir`.
pub fn validate_path_within_working_dir(
    working_dir: &Path,
    rel_path: &str,
) -> Result<(), ToolValidationError> {
    validate_safe_relative_path(rel_path)?;

    let wd_str = working_dir.to_str().ok_or_else(|| {
        ToolValidationError::PathTraversalDetected(working_dir.display().to_string())
    })?;
    validate_no_metachars_or_control(wd_str)?;

    if working_dir
        .components()
        .any(|c| matches!(c, Component::ParentDir))
        || wd_str.split(['/', '\\']).any(|seg| seg == "..")
    {
        return Err(ToolValidationError::PathTraversalDetected(
            wd_str.to_string(),
        ));
    }

    if working_dir.exists() {
        let canon_wd = working_dir
            .canonicalize()
            .map_err(|_| ToolValidationError::PathTraversalDetected(wd_str.to_string()))?;

        let mut current = canon_wd.clone();
        for component in Path::new(rel_path).components() {
            if let Component::Normal(part) = component {
                current.push(part);
                if current.symlink_metadata().is_ok() {
                    let canon_current = current.canonicalize().map_err(|_| {
                        ToolValidationError::PathTraversalDetected(rel_path.to_string())
                    })?;
                    if !canon_current.starts_with(&canon_wd) {
                        return Err(ToolValidationError::PathTraversalDetected(
                            rel_path.to_string(),
                        ));
                    }
                    current = canon_current;
                }
            }
        }
    }

    Ok(())
}

/// Perform baseline security validation on a [`ToolInvocation`] prior to adapter dispatch.
///
/// Rejects:
/// - Empty tool names or prohibited shell wrapper tool names (`bash`, `sh`, `-c`, etc.)
/// - Any CLI argument that fails [`validate_safe_arg`]
/// - Any `working_dir` containing `..` traversal, shell metacharacters, or control characters
/// - Any environment variable key/value containing shell metacharacters, control characters,
///   or prohibited execution hijack variables (`LD_PRELOAD`, `RUSTC_WRAPPER`,
///   `CARGO_BUILD_RUSTC_WRAPPER`, etc.)
///
/// # Errors
///
/// Returns [`ToolValidationError`] if any field of `inv` violates sanitization invariants.
pub fn validate_invocation_base(inv: &ToolInvocation) -> Result<(), ToolValidationError> {
    let tool_name = inv.tool_name.trim();
    if tool_name.is_empty() {
        return Err(ToolValidationError::UnknownTool(inv.tool_name.clone()));
    }

    validate_no_metachars_or_control(&inv.tool_name)?;

    if is_prohibited_shell_wrapper(tool_name) {
        return Err(ToolValidationError::ProhibitedShellWrapper(
            inv.tool_name.clone(),
        ));
    }

    for arg in &inv.args {
        validate_safe_arg(arg)?;
    }

    if let Some(ref wd) = inv.working_dir {
        let wd_str = wd
            .to_str()
            .ok_or_else(|| ToolValidationError::PathTraversalDetected(wd.display().to_string()))?;
        if wd_str.is_empty() {
            return Err(ToolValidationError::PathTraversalDetected(String::new()));
        }
        validate_no_metachars_or_control(wd_str)?;
        if wd.components().any(|c| matches!(c, Component::ParentDir))
            || wd_str.split(['/', '\\']).any(|seg| seg == "..")
        {
            return Err(ToolValidationError::PathTraversalDetected(
                wd_str.to_string(),
            ));
        }
    }

    for (key, value) in &inv.env_vars {
        let trimmed_key = key.trim();
        if trimmed_key.is_empty() {
            return Err(ToolValidationError::InvalidArgValue {
                tool: inv.tool_name.clone(),
                flag: "env".to_string(),
                value: key.clone(),
                reason: "environment variable name must not be empty".to_string(),
            });
        }

        validate_no_metachars_or_control(key)?;
        validate_no_metachars_or_control(value)?;

        let upper_key = trimmed_key.to_ascii_uppercase();
        if PROHIBITED_ENV_KEYS.contains(&upper_key.as_str()) || upper_key.contains("RUSTC_WRAPPER")
        {
            return Err(ToolValidationError::ProhibitedShellWrapper(key.clone()));
        }

        if is_prohibited_shell_wrapper(value) {
            return Err(ToolValidationError::ProhibitedShellWrapper(value.clone()));
        }
    }

    for (key, value) in &inv.params {
        let trimmed_key = key.trim();
        if trimmed_key.is_empty() {
            return Err(ToolValidationError::InvalidArgValue {
                tool: inv.tool_name.clone(),
                flag: "params".to_string(),
                value: key.clone(),
                reason: "parameter name must not be empty".to_string(),
            });
        }

        validate_safe_arg(key)?;
        let normalized_upper = trimmed_key.to_ascii_uppercase().replace('-', "_");
        if PROHIBITED_ENV_KEYS.contains(&normalized_upper.as_str())
            || normalized_upper.contains("RUSTC_WRAPPER")
        {
            return Err(ToolValidationError::ProhibitedShellWrapper(key.clone()));
        }

        match value {
            ToolParamValue::String(s) => validate_safe_arg(s)?,
            ToolParamValue::Bool(_) | ToolParamValue::Integer(_) => {}
            ToolParamValue::StringList(items) => {
                for item in items {
                    validate_safe_arg(item)?;
                }
            }
        }
    }

    Ok(())
}
