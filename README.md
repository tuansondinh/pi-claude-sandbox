# pi-claude-sandbox

Claude-style sandbox for [pi](https://pi.dev/). Forked from [carderne/pi-sandbox](https://github.com/carderne/pi-sandbox).

## What's different from `pi-sandbox`?

- **Coexists with `pi-tool-display` and other bash-overriding extensions.** Does not call `pi.registerTool({name: "bash"})`. Instead intercepts agent bash via `tool_call` event and mutates `event.input.command` with `SandboxManager.wrapWithSandbox()`. Other extensions keep ownership of bash rendering/execution.
- **Cleaner footer status** — just `🔒 Sandbox` (green), no domain/path counts.
- **Write-block retry via `tool_result`** — appends a retry instruction for the LLM rather than re-running in place (since we no longer own `execute`).

## Trade-offs vs upstream

- No live streaming on retry (LLM re-issues bash on next turn)
- Wrapped command may be visible in some UIs that re-snapshot args after `tool_call`
- `shellCommandPrefix` is applied by the active bash tool outside the sandbox wrap

## Install

```bash
pi install npm:pi-claude-sandbox
```

## Configure

Add a config to `~/.pi/agent/sandbox.json` (global) or `.pi/sandbox.json` (project-local). Local takes precedence.

```json
{
  "enabled": true,
  "allowBrowserProcess": true,
  "network": {
    "allowLocalBinding": true,
    "allowAllUnixSockets": true,
    "allowedDomains": ["github.com", "*.github.com"],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["/Users", "/home"],
    "allowRead": [".", "~/.config", "~/.local", "Library"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env", ".env.*", "*.pem", "*.key"]
  }
}
```

## Usage

```
pi --no-sandbox          disable sandboxing for the session
/sandbox                 show current configuration and session allowances
/sandbox-enable          enable sandbox mid-session
/sandbox-disable         disable sandbox mid-session
```

## Architecture

**Bash commands** are wrapped with `sandbox-exec` (macOS) or `bubblewrap` (Linux) at the `tool_call` event layer. The active bash tool (built-in or pi-tool-display's wrapper) executes the wrapped command.

**Read, write, and edit tool calls** are intercepted in `tool_call` and checked against the filesystem policy. The OS-level sandbox cannot cover these tools because they run directly in the Node.js process.

When a block is triggered, a prompt appears with four options:
- Abort (keep blocked)
- Allow for this session only
- Allow for this project — written to `.pi/sandbox.json`
- Allow for all projects — written to `~/.pi/agent/sandbox.json`

**Session allowances** are held in memory only. They are reset when the extension reloads or pi restarts.

### What is prompted vs. hard-blocked

| Rule | Behaviour |
|------|-----------|
| Domain not in `allowedDomains` | Prompted (bash and `!cmd`) |
| Path not in `allowRead` | Prompted (read tool); granting adds to `allowRead` |
| Path not in `allowWrite` | Prompted (write/edit tools and bash write failures) |
| Path in `denyWrite` | Hard-blocked, no prompt |
| Domain in `deniedDomains` | Hard-blocked at OS level, no prompt |

> **⚠️ Read and write have different precedence rules:**
>
> - **Read:** Every read is prompted unless the path is already in `allowRead`. `denyRead` is not a hard-block — it marks regions as denied by default, but granting a prompt adds the path to `allowRead`, overriding `denyRead`.
> - **Write:** `denyWrite` takes precedence over `allowWrite` and is never prompted.

## Acknowledgements

- [carderne/pi-sandbox](https://github.com/carderne/pi-sandbox) by Chris Arderne — direct upstream
- [badlogic/pi-mono sandbox example](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/examples/extensions/sandbox/index.ts) by Mario Zechner — original code, [MIT License](https://github.com/badlogic/pi-mono/blob/main/LICENSE)

[Upstream PR](https://github.com/carderne/pi-sandbox/pull/15) tracks merging the no-registerTool change back to `pi-sandbox`. If/when merged, this fork may be deprecated in favour of upstream.
