/**
 * Based on https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/examples/extensions/sandbox/index.ts
 * by Mario Zechner, used under the MIT License.
 *
 * Sandbox Extension - OS-level sandboxing for bash commands and their
 * subprocesses. Uses @carderne/sandbox-runtime with sandbox-exec (macOS) or
 * bubblewrap (Linux) to enforce filesystem and network restrictions at the
 * kernel level.
 *
 * Scope:
 *   - Bash subprocesses: kernel-enforced filesystem + network rules
 *   - Domain pre-check: prompt before network egress to non-allowed domains
 *   - Bash OS-write block recovery: when sandbox blocks a bash write, prompt
 *     the user to grant access and retry on next turn
 *
 * NOT scoped here:
 *   - Read/Write/Edit tool gating. Those run in-process in Node.js, not in a
 *     subprocess, so OS sandboxing cannot cover them. Use a permission rules
 *     extension (e.g. pi-claude-permissions) for tool-level allow/ask/deny.
 *
 * When a block is triggered, the user is prompted to:
 *   (a) Abort (keep blocked)
 *   (b) Allow for this session only  — stored in memory, agent cannot access
 *   (c) Allow for this project       — written to .pi/sandbox.json
 *   (d) Allow for all projects       — written to ~/.pi/agent/sandbox.json
 *
 * Filesystem rule semantics (applied to bash subprocesses via OS sandbox):
 *   Read:  allowRead OVERRIDES denyRead
 *   Write: denyWrite OVERRIDES allowWrite (most-specific deny wins)
 *
 * Config files (merged, project takes precedence):
 * - ~/.pi/agent/sandbox.json (global)
 * - <cwd>/.pi/sandbox.json  (project-local)
 *
 * Example .pi/sandbox.json:
 * ```json
 * {
 *   "enabled": true,
 *   "network": {
 *     "allowedDomains": ["github.com", "*.github.com"],
 *     "deniedDomains": []
 *   },
 *   "filesystem": {
 *     "denyRead":  [".env", "*.pem", "~/.ssh", "~/.aws"],
 *     "allowRead": [],
 *     "allowWrite": [".", "/tmp", "~/.npm", "~/.cache"],
 *     "denyWrite": [".env", "~/.bashrc", "~/.ssh"]
 *   }
 * }
 * ```
 *
 * Usage:
 * - `pi -e ./sandbox` - sandbox enabled with default/config settings
 * - `pi -e ./sandbox --no-sandbox` - disable sandboxing
 * - `/sandbox` - show current sandbox configuration
 *
 * Setup:
 * 1. Copy sandbox/ directory to ~/.pi/agent/extensions/
 * 2. Run `npm install` in ~/.pi/agent/extensions/sandbox/
 *
 * Linux also requires: bubblewrap, socat, ripgrep
 */

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { SandboxManager, type SandboxRuntimeConfig } from "@carderne/sandbox-runtime";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import {
  type BashOperations,
  getAgentDir,
  isBashToolResult,
  isToolCallEventType,
} from "@mariozechner/pi-coding-agent";

interface SandboxConfig extends SandboxRuntimeConfig {
  enabled?: boolean;
}

const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  network: {
    allowedDomains: [
      "npmjs.org",
      "*.npmjs.org",
      "registry.npmjs.org",
      "registry.yarnpkg.com",
      "pypi.org",
      "*.pypi.org",
      "github.com",
      "*.github.com",
      "api.github.com",
      "raw.githubusercontent.com",
    ],
    deniedDomains: [],
  },
  filesystem: {
    // Open reads: subprocess can read anything by default. Only secrets are
    // hard-denied. No broad home-dir deny — tools need to read tons of files,
    // and a subprocess reading ~/Documents isn't a real threat (network egress
    // is already constrained by the proxy).
    denyRead: [
      ".env",
      ".env.*",
      "*.pem",
      "*.key",
      "~/.ssh",
      "~/.aws",
      "~/.gnupg",
    ],
    // Empty allowRead: nothing to punch holes through. denyRead entries are
    // hard (no grant flow for reads). User can still add specific paths here
    // to override denyRead if truly needed.
    allowRead: [],
    allowWrite: [
      ".",
      "/tmp",
      // Tool caches — without these, npm/cargo/gradle/maven fail or prompt-spam.
      "~/.npm",
      "~/.cache",
      "~/.cargo/registry",
      "~/.gradle/caches",
      "~/.m2/repository",
    ],
    denyWrite: [
      // Secrets — hard block.
      ".env",
      ".env.*",
      "*.pem",
      "*.key",
      // Shell rc — persistence vector.
      "~/.bashrc",
      "~/.zshrc",
      "~/.profile",
      "~/.bash_profile",
      // Credentials / auth.
      "~/.ssh",
      "~/.gitconfig",
      // macOS auto-launch.
      "~/Library/LaunchAgents",
      "~/Library/LaunchDaemons",
    ],
  },
};

function loadConfig(cwd: string): SandboxConfig {
  const projectConfigPath = join(cwd, ".pi", "sandbox.json");
  const globalConfigPath = join(getAgentDir(), "sandbox.json");

  let globalConfig: Partial<SandboxConfig> = {};
  let projectConfig: Partial<SandboxConfig> = {};

  if (existsSync(globalConfigPath)) {
    try {
      globalConfig = JSON.parse(readFileSync(globalConfigPath, "utf-8"));
    } catch (e) {
      console.error(`Warning: Could not parse ${globalConfigPath}: ${e}`);
    }
  }

  if (existsSync(projectConfigPath)) {
    try {
      projectConfig = JSON.parse(readFileSync(projectConfigPath, "utf-8"));
    } catch (e) {
      console.error(`Warning: Could not parse ${projectConfigPath}: ${e}`);
    }
  }

  return deepMerge(deepMerge(DEFAULT_CONFIG, globalConfig), projectConfig);
}

function deepMerge(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
  const result: SandboxConfig = { ...base };

  if (overrides.enabled !== undefined) result.enabled = overrides.enabled;
  if (overrides.network) {
    result.network = { ...base.network, ...overrides.network };
  }
  if (overrides.filesystem) {
    result.filesystem = { ...base.filesystem, ...overrides.filesystem };
  }

  const extOverrides = overrides as {
    ignoreViolations?: Record<string, string[]>;
    enableWeakerNestedSandbox?: boolean;
    allowBrowserProcess?: boolean;
  };
  const extResult = result as {
    ignoreViolations?: Record<string, string[]>;
    enableWeakerNestedSandbox?: boolean;
    allowBrowserProcess?: boolean;
  };

  if (extOverrides.ignoreViolations) {
    extResult.ignoreViolations = extOverrides.ignoreViolations;
  }
  if (extOverrides.enableWeakerNestedSandbox !== undefined) {
    extResult.enableWeakerNestedSandbox = extOverrides.enableWeakerNestedSandbox;
  }
  if (extOverrides.allowBrowserProcess !== undefined) {
    extResult.allowBrowserProcess = extOverrides.allowBrowserProcess;
  }

  return result;
}

// ── Domain helpers ────────────────────────────────────────────────────────────

function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  const domains = new Set<string>();
  let match;
  while ((match = urlRegex.exec(command)) !== null) {
    domains.add(match[1]);
  }
  return [...domains];
}

function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }
  return domain === pattern;
}

function domainIsAllowed(domain: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((p) => domainMatchesPattern(domain, p));
}

// ── Output analysis ───────────────────────────────────────────────────────────

/**
 * Extract a path from a bash "Operation not permitted" OS sandbox error.
 *
 * Bash reports the path exactly as written in the redirect, which can be
 * absolute (`/tmp/.env`), relative (`.env`), or ~-prefixed (`~/.bashrc`).
 * The original regex required a leading slash and missed relative paths,
 * causing the auto-retry/permission flow to silently no-op for those cases.
 */
function extractBlockedWritePath(output: string, cwd: string): string | null {
  const match = output.match(/(?:\/bin\/bash|bash|sh): ([^\s:][^:]*): Operation not permitted/);
  if (!match) return null;
  const raw = match[1].replace(/^["'`]|["'`]$/g, "").trim();
  if (!raw) return null;
  if (raw.startsWith("/")) return raw;
  if (raw.startsWith("~")) return raw.replace(/^~/, homedir());
  return resolve(cwd, raw);
}

// ── Path pattern matching ─────────────────────────────────────────────────────

/**
 * Convert a glob pattern to a RegExp.
 *   **  matches any number of path segments (including /)
 *   *   matches a single segment  (no /)
 *   ?   matches one char          (no /)
 * Other regex metacharacters are escaped.
 */
function globToRegex(pattern: string): RegExp {
  let out = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        out += ".*";
        i++;
      } else {
        out += "[^/]*";
      }
    } else if (c === "?") {
      out += "[^/]";
    } else if (/[.+^${}()|[\]\\]/.test(c)) {
      out += "\\" + c;
    } else {
      out += c;
    }
  }
  return new RegExp(`^${out}$`);
}

/**
 * Match a filesystem path against a list of patterns. Patterns can be:
 *   - Literal paths (optionally ~-prefixed) — prefix match.
 *   - Absolute or ~-rooted globs like `/Users/x/*.pem` — anchored full match.
 *   - Relative globs like `**\/.env` or `*.key` — match the path tail at any
 *     depth (so `**\/.env` matches `/tmp/.env`).
 *
 * The original implementation called `resolve()` on every pattern, which
 * mangled glob segments like `**\/.env` into `<cwd>/**\/.env` and broke
 * recursive matches.
 */
function matchesPattern(filePath: string, patterns: string[]): boolean {
  const expanded = filePath.replace(/^~/, homedir());
  const abs = resolve(expanded);

  return patterns.some((p) => {
    const hasGlob = p.includes("*") || p.includes("?");
    const expandedP = p.replace(/^~/, homedir());

    if (!hasGlob) {
      const absP = resolve(expandedP);
      return abs === absP || abs.startsWith(absP + "/");
    }

    if (expandedP.startsWith("/")) {
      return globToRegex(expandedP).test(abs);
    }

    const anchored = expandedP.startsWith("**") ? expandedP : `**/${expandedP}`;
    return globToRegex(anchored).test(abs);
  });
}

// ── Config file updaters (Node.js process — not OS-sandboxed) ─────────────────

function getConfigPaths(cwd: string): {
  globalPath: string;
  projectPath: string;
} {
  return {
    globalPath: join(homedir(), ".pi", "agent", "sandbox.json"),
    projectPath: join(cwd, ".pi", "sandbox.json"),
  };
}

function readOrEmptyConfig(configPath: string): Partial<SandboxConfig> {
  if (!existsSync(configPath)) return {};
  try {
    return JSON.parse(readFileSync(configPath, "utf-8"));
  } catch {
    return {};
  }
}

function writeConfigFile(configPath: string, config: Partial<SandboxConfig>): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

function addDomainToConfig(configPath: string, domain: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.network?.allowedDomains ?? [];
  if (!existing.includes(domain)) {
    config.network = {
      ...config.network,
      allowedDomains: [...existing, domain],
      deniedDomains: config.network?.deniedDomains ?? [],
    };
    writeConfigFile(configPath, config);
  }
}

function addWritePathToConfig(configPath: string, pathToAdd: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.filesystem?.allowWrite ?? [];
  if (!existing.includes(pathToAdd)) {
    config.filesystem = {
      ...config.filesystem,
      allowWrite: [...existing, pathToAdd],
      denyRead: config.filesystem?.denyRead ?? [],
      denyWrite: config.filesystem?.denyWrite ?? [],
    };
    writeConfigFile(configPath, config);
  }
}

// ── Sandboxed bash ops ────────────────────────────────────────────────────────

function createSandboxedBashOps(): BashOperations {
  return {
    async exec(command, cwd, { onData, signal, timeout, env }) {
      if (!existsSync(cwd)) {
        throw new Error(`Working directory does not exist: ${cwd}`);
      }

      const wrappedCommand = await SandboxManager.wrapWithSandbox(command);

      return new Promise((resolve, reject) => {
        const child = spawn("bash", ["-c", wrappedCommand], {
          cwd,
          env,
          detached: true,
          stdio: ["ignore", "pipe", "pipe"],
        });

        let timedOut = false;
        let timeoutHandle: NodeJS.Timeout | undefined;

        if (timeout !== undefined && timeout > 0) {
          timeoutHandle = setTimeout(() => {
            timedOut = true;
            if (child.pid) {
              try {
                process.kill(-child.pid, "SIGKILL");
              } catch {
                child.kill("SIGKILL");
              }
            }
          }, timeout * 1000);
        }

        child.stdout?.on("data", onData);
        child.stderr?.on("data", onData);

        child.on("error", (err) => {
          if (timeoutHandle) clearTimeout(timeoutHandle);
          reject(err);
        });

        const onAbort = () => {
          if (child.pid) {
            try {
              process.kill(-child.pid, "SIGKILL");
            } catch {
              child.kill("SIGKILL");
            }
          }
        };

        signal?.addEventListener("abort", onAbort, { once: true });

        child.on("close", (code) => {
          if (timeoutHandle) clearTimeout(timeoutHandle);
          signal?.removeEventListener("abort", onAbort);

          if (signal?.aborted) {
            reject(new Error("aborted"));
          } else if (timedOut) {
            reject(new Error(`timeout:${timeout}`));
          } else {
            resolve({ exitCode: code });
          }
        });
      });
    },
  };
}

// ── Extension ─────────────────────────────────────────────────────────────────

// Re-execute a single bash command for auto-retry after grant.
//
// Used by the tool_result handler. Wraps the (already unwrapped) original
// command with the CURRENT sandbox policy and runs it, accumulating stdout
// and stderr into a single string. Returns the combined output and exit code.
// Honours signal so the user can Esc the retry just like the original.
async function retryBashCommand(
  command: string,
  cwd: string,
  signal?: AbortSignal,
): Promise<{ output: string; exitCode: number | null }> {
  if (!existsSync(cwd)) {
    throw new Error(`Working directory does not exist: ${cwd}`);
  }

  const wrappedCommand = await SandboxManager.wrapWithSandbox(command);

  return new Promise((resolveExec, rejectExec) => {
    const child = spawn("bash", ["-c", wrappedCommand], {
      cwd,
      env: process.env,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const chunks: Buffer[] = [];
    child.stdout?.on("data", (d: Buffer) => chunks.push(d));
    child.stderr?.on("data", (d: Buffer) => chunks.push(d));

    const onAbort = () => {
      if (child.pid) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          child.kill("SIGKILL");
        }
      }
    };
    signal?.addEventListener("abort", onAbort, { once: true });

    child.on("error", (err) => {
      signal?.removeEventListener("abort", onAbort);
      rejectExec(err);
    });

    child.on("close", (code) => {
      signal?.removeEventListener("abort", onAbort);
      const output = Buffer.concat(chunks).toString("utf8");
      if (signal?.aborted) {
        rejectExec(new Error("aborted"));
      } else {
        resolveExec({ output, exitCode: code });
      }
    });
  });
}

export default function (pi: ExtensionAPI) {
  pi.registerFlag("no-sandbox", {
    description: "Disable OS-level sandboxing for bash commands",
    type: "boolean",
    default: false,
  });

  let sandboxEnabled = false;
  let sandboxInitialized = false;

  // Session-temporary allowances — held in JS memory, not accessible by the agent.
  // These are added on top of whatever is in the config files.
  const sessionAllowedDomains: string[] = [];
  const sessionAllowedWritePaths: string[] = [];

  // Original (unwrapped) bash commands keyed by toolCallId.
  // Stashed in tool_call before we mutate event.input.command, so tool_result
  // can re-execute the original command after the user grants access.
  const originalCommandsByToolCallId = new Map<string, string>();

  // Tool call IDs we've already auto-retried. Prevents infinite recursion if
  // the retry hits another block (we fall through to the LLM-retry path then).
  const autoRetriedToolCallIds = new Set<string>();

  // ── Effective config helpers ────────────────────────────────────────────────

  function getEffectiveAllowedDomains(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...(config.network?.allowedDomains ?? []), ...sessionAllowedDomains];
  }

  function getEffectiveAllowWrite(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...(config.filesystem?.allowWrite ?? []), ...sessionAllowedWritePaths];
  }

  // ── Sandbox reinitialize ────────────────────────────────────────────────────
  // Called after granting a session/permanent allowance so the OS-level sandbox
  // picks up the new rules before the next bash subprocess starts.

  async function reinitializeSandbox(cwd: string): Promise<void> {
    if (!sandboxInitialized) return;
    const config = loadConfig(cwd);
    const configExt = config as unknown as { allowBrowserProcess?: boolean };
    try {
      await SandboxManager.reset();
      await SandboxManager.initialize({
        network: {
          ...config.network,
          allowedDomains: [...(config.network?.allowedDomains ?? []), ...sessionAllowedDomains],
          deniedDomains: config.network?.deniedDomains ?? [],
        },
        filesystem: {
          ...config.filesystem,
          denyRead: config.filesystem?.denyRead ?? [],
          allowRead: config.filesystem?.allowRead ?? [],
          allowWrite: [...(config.filesystem?.allowWrite ?? []), ...sessionAllowedWritePaths],
          denyWrite: config.filesystem?.denyWrite ?? [],
        },
        allowBrowserProcess: configExt.allowBrowserProcess,
        enableWeakerNetworkIsolation: true,
      });
    } catch (e) {
      console.error(`Warning: Failed to reinitialize sandbox: ${e}`);
    }
  }

  // ── UI prompts ──────────────────────────────────────────────────────────────

  async function promptDomainBlock(
    ctx: ExtensionContext,
    domain: string,
  ): Promise<"abort" | "session" | "project" | "global"> {
    if (!ctx.hasUI) return "abort";
    const choice = await ctx.ui.select(`🌐 Network blocked: "${domain}" is not in allowedDomains`, [
      "Abort (keep blocked)",
      "Allow for this session only",
      "Allow for this project  →  .pi/sandbox.json",
      "Allow for all projects  →  ~/.pi/agent/sandbox.json",
    ]);
    if (!choice || choice.startsWith("Abort")) return "abort";
    if (choice.startsWith("Allow for this session")) return "session";
    if (choice.startsWith("Allow for this project")) return "project";
    return "global";
  }

  async function promptWriteBlock(
    ctx: ExtensionContext,
    filePath: string,
  ): Promise<"abort" | "session" | "project" | "global"> {
    if (!ctx.hasUI) return "abort";
    const choice = await ctx.ui.select(`📝 Write blocked: "${filePath}" is not in allowWrite`, [
      "Abort (keep blocked)",
      "Allow for this session only",
      "Allow for this project  →  .pi/sandbox.json",
      "Allow for all projects  →  ~/.pi/agent/sandbox.json",
    ]);
    if (!choice || choice.startsWith("Abort")) return "abort";
    if (choice.startsWith("Allow for this session")) return "session";
    if (choice.startsWith("Allow for this project")) return "project";
    return "global";
  }

  // ── Apply allowance choices ─────────────────────────────────────────────────

  async function applyDomainChoice(
    choice: "session" | "project" | "global",
    domain: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedDomains.includes(domain)) sessionAllowedDomains.push(domain);
    if (choice === "project") addDomainToConfig(projectPath, domain);
    if (choice === "global") addDomainToConfig(globalPath, domain);
    await reinitializeSandbox(cwd);
  }

  async function applyWriteChoice(
    choice: "session" | "project" | "global",
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedWritePaths.includes(filePath)) sessionAllowedWritePaths.push(filePath);
    if (choice === "project") addWritePathToConfig(projectPath, filePath);
    if (choice === "global") addWritePathToConfig(globalPath, filePath);
    await reinitializeSandbox(cwd);
  }

  // ── user_bash — network pre-check ──────────────────────────────────────────

  pi.on("user_bash", async (event, ctx) => {
    if (!sandboxEnabled || !sandboxInitialized) return;

    const domains = extractDomainsFromCommand(event.command);
    const effectiveDomains = getEffectiveAllowedDomains(ctx.cwd);

    for (const domain of domains) {
      if (!domainIsAllowed(domain, effectiveDomains)) {
        const choice = await promptDomainBlock(ctx, domain);
        if (choice === "abort") {
          return {
            result: {
              output: `Blocked: "${domain}" is not in allowedDomains. Use /sandbox to review your config.`,
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }
        await applyDomainChoice(choice, domain, ctx.cwd);
      }
    }

    return { operations: createSandboxedBashOps() };
  });

  // ── tool_call — network pre-check for bash + wrap with OS sandbox

  pi.on("tool_call", async (event, ctx) => {
    const config = loadConfig(ctx.cwd);
    if (!config.enabled) return;

    // Bash: network pre-check + wrap command with sandbox.
    // We don't own the bash tool (avoids conflict with pi-tool-display);
    // instead we mutate event.input.command so the active bash tool runs the
    // OS-sandboxed command. ToolCallEvent input is mutable per pi docs.
    if (sandboxEnabled && sandboxInitialized && isToolCallEventType("bash", event)) {
      const originalCommand = event.input.command;
      const domains = extractDomainsFromCommand(originalCommand);
      const effectiveDomains = getEffectiveAllowedDomains(ctx.cwd);
      for (const domain of domains) {
        if (!domainIsAllowed(domain, effectiveDomains)) {
          const choice = await promptDomainBlock(ctx, domain);
          if (choice === "abort") {
            return {
              block: true,
              reason: `Network access to "${domain}" is blocked (not in allowedDomains).`,
            };
          }
          await applyDomainChoice(choice, domain, ctx.cwd);
        }
      }

      // Wrap with OS sandbox (sandbox-exec / bwrap).
      try {
        event.input.command = await SandboxManager.wrapWithSandbox(originalCommand);
        // Stash unwrapped command so tool_result can re-execute on grant.
        originalCommandsByToolCallId.set(event.toolCallId, originalCommand);
      } catch (err) {
        ctx.ui.notify(
          `Sandbox wrap failed: ${err instanceof Error ? err.message : err}. Running unsandboxed.`,
          "warning",
        );
      }
    }

    // Note: in-process read/write/edit tool gating is intentionally NOT
    // handled here — use a permission rules extension (pi-claude-permissions)
    // for that. The filesystem rules in config apply to bash subprocesses via
    // the OS sandbox only.
  });

  // ── tool_result — detect OS-level write block in bash output ───────────────────
  //
  // We don't own bash.execute (avoids conflict with pi-tool-display). Instead,
  // after the active bash tool runs the wrapped command, inspect output: if
  // sandbox blocked a write, prompt user, update config, then re-execute the
  // ORIGINAL command directly (with the new policy) and return the combined
  // output. This keeps everything within a single LLM turn — the model never
  // sees the failure, only the final retry result.
  //
  // Fallback: if the retry itself hits another block, we surface a
  // "please retry" hint so the LLM can do another round next turn.

  pi.on("tool_result", async (event, ctx) => {
    if (!sandboxEnabled || !sandboxInitialized) return;
    if (!isBashToolResult(event)) return;
    if (!ctx.hasUI) return;

    const outputText = event.content
      .filter((c): c is { type: "text"; text: string } => c.type === "text")
      .map((c) => c.text)
      .join("\n");

    const blockedPath = extractBlockedWritePath(outputText, ctx.cwd);
    if (!blockedPath) {
      // No block detected — release the stash so we don't leak memory.
      originalCommandsByToolCallId.delete(event.toolCallId);
      return;
    }

    // Pre-check denyWrite BEFORE prompting. denyWrite always wins over
    // allowWrite, so granting allowWrite would be misleading: the OS sandbox
    // would still block the write. Tell the user (and the LLM) up-front so
    // they can either edit the sandbox.json by hand or skip the operation.
    const initialConfig = loadConfig(ctx.cwd);
    const { projectPath, globalPath } = getConfigPaths(ctx.cwd);
    if (matchesPattern(blockedPath, initialConfig.filesystem?.denyWrite ?? [])) {
      ctx.ui.notify(
        `⚠️ "${blockedPath}" matches a denyWrite rule. denyWrite always wins over allowWrite — grant cannot help here. Edit denyWrite manually if needed.`,
        "warning",
      );
      return {
        content: [
          {
            type: "text" as const,
            text:
              outputText +
              `\n\n[Sandbox] Cannot grant write to "${blockedPath}": it matches a denyWrite rule (denyWrite always wins over allowWrite).\n` +
              `To allow this path, manually remove the matching pattern from denyWrite in:\n  ${projectPath}\n  ${globalPath}\n` +
              `Otherwise, choose a different path or skip this operation.`,
          },
        ],
        isError: true,
      };
    }

    const choice = await promptWriteBlock(ctx, blockedPath);
    if (choice === "abort") return;

    await applyWriteChoice(choice, blockedPath, ctx.cwd);

    // Auto-retry: re-execute the original command with the new policy. We do
    // this only once per tool call (autoRetriedToolCallIds) to avoid recursion
    // if the retry triggers another block.
    const originalCommand = originalCommandsByToolCallId.get(event.toolCallId);
    const alreadyRetried = autoRetriedToolCallIds.has(event.toolCallId);
    if (originalCommand && !alreadyRetried) {
      autoRetriedToolCallIds.add(event.toolCallId);
      try {
        // ctx.signal is available in pi-coding-agent >= 0.62 but our peerDep
        // pins ^0.61, so we can't depend on it. Pass undefined for now — the
        // blocked-write retry is typically a single fast syscall.
        const ctxSignal = (ctx as { signal?: AbortSignal }).signal;
        const retry = await retryBashCommand(originalCommand, ctx.cwd, ctxSignal);
        // If retry STILL produced a sandbox block, fall through to the
        // LLM-retry hint path so the user can keep granting.
        const retryStillBlocked = extractBlockedWritePath(retry.output, ctx.cwd) !== null;
        if (!retryStillBlocked) {
          ctx.ui.notify(
            `✓ Auto-retried "${blockedPath}" after grant (exit ${retry.exitCode ?? "?"})`,
            "info",
          );
          return {
            content: [
              {
                type: "text" as const,
                text: retry.output,
              },
            ],
            isError: retry.exitCode !== 0,
          };
        }
      } catch (err) {
        ctx.ui.notify(
          `Auto-retry failed: ${err instanceof Error ? err.message : err}. Falling back to LLM retry.`,
          "warning",
        );
      } finally {
        originalCommandsByToolCallId.delete(event.toolCallId);
      }
    }

    // Final fallback: we tried the auto-retry but it still hit a block we
    // can't auto-handle (e.g. a different blocked path on the same command).
    // Surface the granted path AND the latest output so the LLM can decide
    // whether to retry, narrow the command, or ask the user.
    return {
      content: [
        {
          type: "text" as const,
          text:
            outputText +
            `\n\n[Sandbox] Granted write access for "${blockedPath}", but the auto-retry still hit a block. ` +
            `If the same path is blocked, denyWrite is overriding allowWrite — inspect ${projectPath} or ${globalPath}. ` +
            `Otherwise rerun the command and grant the next blocked path when prompted.`,
        },
      ],
      isError: true,
    };
  });

  // ── session_start ───────────────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    const noSandbox = pi.getFlag("no-sandbox") as boolean;

    if (noSandbox) {
      sandboxEnabled = false;
      ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
      return;
    }

    const config = loadConfig(ctx.cwd);

    if (!config.enabled) {
      sandboxEnabled = false;
      ctx.ui.notify("Sandbox disabled via config", "info");
      return;
    }

    const platform = process.platform;
    if (platform !== "darwin" && platform !== "linux") {
      sandboxEnabled = false;
      ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
      return;
    }

    try {
      const configExt = config as unknown as {
        ignoreViolations?: Record<string, string[]>;
        enableWeakerNestedSandbox?: boolean;
        allowBrowserProcess?: boolean;
      };

      await SandboxManager.initialize({
        network: config.network,
        filesystem: config.filesystem,
        ignoreViolations: configExt.ignoreViolations,
        enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
        allowBrowserProcess: configExt.allowBrowserProcess,
        enableWeakerNetworkIsolation: true,
      });

      // Make Node's built-in fetch() honour HTTP_PROXY / HTTPS_PROXY in this
      // process and any child processes that inherit the environment.
      // NODE_USE_ENV_PROXY avoids NODE_OPTIONS allowlisting issues on older Node
      // versions while still propagating naturally to child `node` processes.
      // fetch() supports this on Node 22.21.0+ and 24.0.0+.
      const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
      const supportsEnvProxy = (nodeMajor === 22 && nodeMinor >= 21) || nodeMajor >= 24;
      if (supportsEnvProxy) {
        process.env.NODE_USE_ENV_PROXY ??= "1";
      }

      sandboxEnabled = true;
      sandboxInitialized = true;

      ctx.ui.setStatus(
        "sandbox",
        ctx.ui.theme.fg("success", "🔒 Sandbox"),
      );
    } catch (err) {
      sandboxEnabled = false;
      ctx.ui.notify(
        `Sandbox initialization failed: ${err instanceof Error ? err.message : err}`,
        "error",
      );
    }
  });

  // ── session_shutdown ────────────────────────────────────────────────────────

  pi.on("session_shutdown", async () => {
    if (sandboxInitialized) {
      try {
        await SandboxManager.reset();
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  // ── /sandbox command ────────────────────────────────────────────────────────

  pi.registerCommand("sandbox-enable", {
    description: "Enable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (sandboxEnabled) {
        ctx.ui.notify("Sandbox is already enabled", "info");
        return;
      }

      const config = loadConfig(ctx.cwd);
      const platform = process.platform;
      if (platform !== "darwin" && platform !== "linux") {
        ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
        return;
      }

      try {
        const configExt = config as unknown as {
          ignoreViolations?: Record<string, string[]>;
          enableWeakerNestedSandbox?: boolean;
          allowBrowserProcess?: boolean;
        };

        await SandboxManager.initialize({
          network: config.network,
          filesystem: config.filesystem,
          ignoreViolations: configExt.ignoreViolations,
          enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
          allowBrowserProcess: configExt.allowBrowserProcess,
          enableWeakerNetworkIsolation: true,
        });

        sandboxEnabled = true;
        sandboxInitialized = true;

        ctx.ui.setStatus(
          "sandbox",
          ctx.ui.theme.fg("success", "🔒 Sandbox"),
        );
        ctx.ui.notify("Sandbox enabled", "info");
      } catch (err) {
        ctx.ui.notify(
          `Sandbox initialization failed: ${err instanceof Error ? err.message : err}`,
          "error",
        );
      }
    },
  });

  pi.registerCommand("sandbox-disable", {
    description: "Disable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is already disabled", "info");
        return;
      }

      if (sandboxInitialized) {
        try {
          await SandboxManager.reset();
        } catch {
          // Ignore cleanup errors
        }
      }

      sandboxEnabled = false;
      sandboxInitialized = false;
      ctx.ui.setStatus("sandbox", "");
      ctx.ui.notify("Sandbox disabled", "info");
    },
  });

  pi.registerCommand("sandbox-init", {
    description:
      "Write the default sandbox config to disk so you can inspect or customize it. " +
      "Usage: /sandbox-init [global|project] [force]",
    handler: async (args, ctx) => {
      const argList = (args ?? "").trim().split(/\s+/).filter(Boolean);
      const scope = argList.includes("global") ? "global" : "project";
      const force = argList.includes("force");

      const { globalPath, projectPath } = getConfigPaths(ctx.cwd);
      const targetPath = scope === "global" ? globalPath : projectPath;

      if (existsSync(targetPath) && !force) {
        ctx.ui.notify(
          `Config already exists at ${targetPath}.\n` +
            `Use \`/sandbox-init ${scope} force\` to overwrite.`,
          "warning",
        );
        return;
      }

      try {
        writeConfigFile(targetPath, DEFAULT_CONFIG);
        ctx.ui.notify(
          `Wrote default sandbox config to ${targetPath}.\n` +
            `Edit it to customize, then run /sandbox-disable + /sandbox-enable to reload.`,
          "info",
        );
      } catch (e) {
        ctx.ui.notify(
          `Failed to write ${targetPath}: ${e instanceof Error ? e.message : e}`,
          "error",
        );
      }
    },
  });

  pi.registerCommand("sandbox", {
    description: "Show sandbox configuration",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is disabled", "info");
        return;
      }

      const config = loadConfig(ctx.cwd);
      const { globalPath, projectPath } = getConfigPaths(ctx.cwd);

      const lines = [
        "Sandbox Configuration",
        `  Project config: ${projectPath}`,
        `  Global config:  ${globalPath}`,
        "",
        "Network (bash + !cmd):",
        `  Allowed domains: ${config.network?.allowedDomains?.join(", ") || "(none)"}`,
        `  Denied domains:  ${config.network?.deniedDomains?.join(", ") || "(none)"}`,
        ...(sessionAllowedDomains.length > 0
          ? [`  Session allowed: ${sessionAllowedDomains.join(", ")}`]
          : []),
        "",
        "Filesystem (bash subprocesses — OS-enforced):",
        `  Deny Read:   ${config.filesystem?.denyRead?.join(", ") || "(none)"}`,
        `  Allow Read:  ${config.filesystem?.allowRead?.join(", ") || "(none)"}`,
        `  Allow Write: ${config.filesystem?.allowWrite?.join(", ") || "(none)"}`,
        `  Deny Write:  ${config.filesystem?.denyWrite?.join(", ") || "(none)"}`,
        ...(sessionAllowedWritePaths.length > 0
          ? [`  Session write: ${sessionAllowedWritePaths.join(", ")}`]
          : []),
        "",
        "Note: filesystem rules above apply to bash subprocesses only.",
        "Note: allowRead OVERRIDES denyRead. denyWrite OVERRIDES allowWrite.",
        "Note: read/write/edit tool gating is NOT handled here — use pi-claude-permissions.",
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
