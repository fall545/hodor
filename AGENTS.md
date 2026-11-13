# AGENTS.md — Engineering Rules for AI Coding Agents

This file governs how all contributors (human and AI) write code in this repository.
Read it fully before making any change. When a rule here conflicts with your habit, the rule wins.

## Project Context

Hodor is a credential broker for AI agents (Rust, CLI-first, Linux/macOS/Windows).
The single non-negotiable invariant of this codebase:

> **Secret material must never appear in agent-visible output.** No tool, function,
> log line, or error message may ever return a raw secret. Only aliases (`{{alias}}`) exist outside the daemon's memory.

If your change could leak a secret through any channel (stdout, argv, env, files,
logs, error text), stop and redesign.

## Repository Layout

Cargo workspace. Dependency direction is fixed and one-way:

```
cli / mcp / supervisor  →  daemon  →  proto + guard + vfs + askpass + policy + scrub  →  core
```

- `core`, `scrub`, `policy` are **pure libraries**: no network, no process spawning, no filesystem writes. They are the security-audit surface — keep them minimal.
- New shared logic goes **down** into an existing lower crate. Never duplicate a capability across crates; never let a lower crate depend on a higher one.
- `vfs` must reuse `hodor-scrub` for substitution — file-read replacement and output scrubbing share one engine, never two.

## Code Style

- **Concise and clear beats clever.** Optimize for the reviewer reading it cold.
- **Flat control flow.** Prefer guard clauses and early returns over nested
  `if`/`match` arms. Target: at most 2 levels of nesting inside a function body.
  If a third level appears, extract a named helper.
- **One responsibility per function.** If you need "and" to describe what a
  function does, split it.
- **Reuse before write.** Before adding any function, check `core`/`scrub`/
  `policy`/`proto` for an existing one. Copy-pasted logic is a review-blocking defect.
- **High cohesion, low coupling.** Modules talk through `hodor-proto` types or
  their own public API — never by reaching into another module's internals.
- **Comments are in English** and only state constraints the code cannot express
  (invariants, security rationale, platform quirks). Never narrate what the next
  line does, never leave review-notes ("// fixed", "// TODO per user request").
- Public items get a one-sentence doc-comment (`///`) explaining *when* to use them,
  not *how* they work.

## Rust Conventions

- `cargo fmt` must produce no diff; `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- Error handling: `thiserror` types in libraries; `anyhow` only in `hodor-cli`/bin entry points. Never `unwrap()`/`expect()` on runtime paths (`expect` with a static message is allowed only in tests).
- Secret bytes are held in `SecretVec`/`zeroize`-wrapped types only. Raw `String`/`Vec<u8>` must never hold plaintext secrets for longer than a single statement.
- User-facing strings go through Fluent (`i18n/`) — **no hardcoded English or Chinese text** in messages, dialogs, help output, or errors shown to users.
- New protocol messages belong in `hodor-proto`; all serde types are `#[non_exhaustive]` with explicit `#[serde(deny_unknown_fields)]` where version compatibility matters.

## Testing

- Pure crates (`core`, `scrub`, `policy`) require unit tests next to the code they test; treat a new pure function without tests as incomplete.
- `scrub` substitution has a golden-test corpus: any change to detection logic must extend `crates/hodor-scrub/tests/corpus/` with the case that motivated it.
- Any fix starts with a failing test that reproduces it (regression protection for a security tool is not optional).
- Integration tests that touch the vault, supervisor, or FUSE layer are marked `#[ignore]`-by-default and run in CI with environment setup.

## Security Red Lines (review-blocking)

1. Never add an MCP tool, CLI flag, or log field that returns secret material.
2. Never log secrets — including partial matches, hashes of secrets, or vault keys.
3. Never print secret material into argv, environment, or a temp file.
4. Any command-execution path must go through `hodor-policy` evaluation — no direct `Command::new` on agent-supplied input.
5. New sudo-capable code paths require a test proving the blacklist engine intercepts them.
6. Audit-relevant events must append to the hash chain — no writes that bypass `core::audit`.

## Commits & Docs

- Commit messages: imperative subject line ≤ 72 chars, body explains *why*.
- Keep `docs/DESIGN.md` requirement IDs (`R1`–`R24`) referenced in PR descriptions when a change implements or alters one.
- `README.md` (English) and `README.zh-CN.md` (Chinese) must stay in sync — change one, change both, or mark the section with a `<!-- translate -->` note for follow-up.
