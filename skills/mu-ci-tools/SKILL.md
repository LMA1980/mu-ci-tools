---
name: mu-ci-tools
description: "Build and validate typed CI/CD ToolAdapter plugins, argument sanitizers, and structured metric parsers with mu-ci-tools."
---

# `mu-ci-tools` Modular `ToolAdapter` Registry

Use these guidelines when implementing or invoking CI/CD tool adapters with `mu-ci-tools`:

## 1. Compile-Time Typed `ToolAdapter` Trait

- Every CI tool integration implements `ToolAdapter` and registers in `ToolRegistry`.
- Never construct raw shell command strings (`sh -c ...`) from untrusted workflow parameters. Always produce an explicit executable + argument vector validated through `sanitize`.

## 2. Pre-PR Local & CI Gate Sequence (`fmt` -> `clippy`)

- When configuring or executing Rust tool adapters, always run formatting checks **before** linting so line-wrapping expansions do not trigger pedantic length lints (`clippy::too_many_lines`):
  1. `cargo fmt --all -- --check`
  2. `./scripts/format_docs.sh --check` (when present)
  3. `cargo clippy --workspace --all-targets -- -D warnings` (plus `--target riscv64gc-unknown-linux-gnu` where applicable)
