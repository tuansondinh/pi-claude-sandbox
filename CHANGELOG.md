# Changelog

## [0.5.3] - 2026-04-25

### Documentation
- README: kept the short differentiation paragraph at the top, added the full comparison table back as a collapsible `<details>` section for users who want the breakdown.

## [0.5.2] - 2026-04-25

### Documentation
- README: prominent comparison table at the top showing differences from upstream `pi-sandbox`. Clearer explanation of the pair design with `pi-claude-permissions`.

## [0.5.1] - 2026-04-25

### Features
- Added `/sandbox-init [global|project] [force]` command. Writes the current default config to disk so users can inspect or customize it.

## [0.5.0] - 2026-04-25

### Breaking Changes
- Removed in-process gating of Read/Write/Edit tool calls. Use [pi-claude-permissions](https://www.npmjs.com/package/pi-claude-permissions) for tool-level allow/ask/deny rules. The OS-level bash subprocess sandbox is unchanged.
- Read prompt-retry flow removed (deny regions are now hard-block only). Write prompt-retry flow remains.
- Default `denyRead` no longer includes broad home regions (`/Users`, `/home`). Reads are open by default; only specific secrets (`.env`, `*.pem`, `*.key`, `~/.ssh`, `~/.aws`, `~/.gnupg`) are blocked.

### Features
- New defaults aligned with Claude Code's "open reads, closed writes, hard deny on secrets" model.
- `allowWrite` now pre-includes common tool caches (`~/.npm`, `~/.cargo/registry`, `~/.gradle/caches`, `~/.m2/repository`) so `npm install`, `cargo build`, etc. work without prompt-spam.
- Expanded `denyWrite` defaults to cover shell rc files, `~/.ssh`, `~/.gitconfig`, and macOS LaunchAgents/LaunchDaemons.

### Documentation
- README rewritten for clarity. Explicit explanation of read/write asymmetric semantics (open-by-default reads vs whitelist writes).
- Documented complementary use with `pi-claude-permissions`.

## [0.4.0] - earlier release
- Coexists with `pi-tool-display` and other bash-overriding extensions.
- Cleaner footer status.
- Write-block retry via `tool_result`.
