# Changelog

## [0.6.0] - 2026-04-25

### Features
- **Auto-retry on grant.** When the OS sandbox blocks a bash write, the user grants access, and the extension now re-executes the original command in-place and replaces the tool result content with the retry output. The model sees the final outcome only — no extra LLM turn, no "Please retry" round-trip.
- Pre-check `denyWrite` before prompting. If the blocked path matches a `denyWrite` pattern, the user is no longer asked to grant access (it would be a no-op since `denyWrite` always wins). The tool result returns a clear explanation pointing at the relevant config file instead.
- Toast distinguishes auto-retry success from "sandbox cleared but command still failed" (e.g. underlying Unix permission denial). Success uses `✓ info`, post-grant command failure uses `⚠ warning` with explicit reason.

### Bug Fixes
- `extractBlockedWritePath` now handles relative (`.env`), absolute (`/tmp/.env`), and `~`-prefixed paths from bash redirect errors. Previously the regex required a leading `/`, silently dropping relative paths and skipping the prompt entirely.
- `matchesPattern` now uses a proper glob → regex converter that supports `**` (any depth), `*` (single segment), and `?`. The previous implementation called `resolve()` on every pattern, which mangled `**/.env` into `<cwd>/**/.env` and broke recursive matches — so the `denyWrite` pre-check could never fire on glob rules.
- Final fallback message clarifies that the auto-retry was attempted and gives the user actionable next steps (manual `denyWrite` edit vs rerun).

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
