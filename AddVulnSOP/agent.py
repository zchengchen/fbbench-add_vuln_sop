#!/usr/bin/env python3
"""Thin wrapper around the `claude` CLI's headless print mode (`claude -p`).

This is the ONLY place in the AddVulnSOP pipeline that talks to an LLM. Every
other module in this directory is plain deterministic Python/subprocess code
(git, docker, curl, regex/YAML text edits). pipeline.py calls call_agent()
whenever a stage needs judgment a script can't safely hardcode: picking a fix
commit, bisecting vuln_commit against a regression window, writing prose
(description.txt/PROVENANCE.md), reviewing a changelog-scrub candidate list,
deciding curated ASan categories, etc.

This deliberately does NOT use the Workflow tool / agent()/pipeline() JS
orchestration -- it is a plain subprocess call to the `claude` binary, so the
whole pipeline can run as an ordinary standalone Python script outside of any
Claude Code session.

Verified empirically against the installed CLI (2026-07-27):
  - `claude -p "<prompt>" --output-format json` prints exactly one JSON object
    as the last line of stdout. Top-level fields used here: "result" (final
    assistant text), "structured_output" (only present when --json-schema was
    given -- the schema-validated object), "total_cost_usd", "is_error",
    "session_id".
  - `--permission-mode acceptEdits --allowedTools <scoped list>` runs fully
    unattended: no hang, empty permission_denials, as long as every tool the
    turn actually needs is in the allow-list. This is the default here.
    `bypassPermissions` / `--dangerously-skip-permissions` exist but are NOT
    the default -- callers opt in explicitly via `permission_mode=`.
  - `--max-turns` does not exist on this CLI; turn-count is not capped here.
    Use `max_budget_usd` (maps to `--max-budget-usd`) to bound runaway cost
    on an autonomous multi-tool-call stage (e.g. a bisection loop).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


class AgentError(RuntimeError):
    """Raised when the `claude` CLI itself fails, or the agent's own turn
    errored (is_error=true, e.g. it hit --max-budget-usd or a fatal tool
    failure). `.raw` holds whatever diagnostic payload is available."""

    def __init__(self, message: str, raw=None):
        super().__init__(message)
        self.raw = raw


DEFAULT_ALLOWED_TOOLS = ["Bash", "Read", "Grep", "Glob"]

# Failures that say nothing about whether the TASK is doable -- re-issuing the
# identical prompt can plausibly succeed. Retried with backoff rather than
# killing a stage (and, with it, a pipeline run that may already be an hour
# and many dollars deep).
#
# The safeguard one is the motivating case: this pipeline's prompts are
# necessarily about crashes, UAFs, exploit reproduction and patch analysis, so
# the classifier flags a legitimate turn now and then. It is non-deterministic
# -- the same prompt usually sails through on a retry -- and pipeline.py
# already attaches AUTHORIZATION_CONTEXT to every call explaining this is
# authorized benchmark work on already-disclosed, already-fixed bugs.
TRANSIENT_ERROR_PATTERNS = (
    "safeguards flagged",
    "api error",
    "overloaded",
    "rate limit",
    "rate_limit",
    "internal server error",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "connection reset",
    "connection error",
    "timed out",
    " 429",
    " 500",
    " 502",
    " 503",
    " 529",
)


def is_transient_error(message: str) -> bool:
    low = (message or "").lower()
    return any(p in low for p in TRANSIENT_ERROR_PATTERNS)


def call_agent(
    prompt: str,
    cwd: str | Path,
    *,
    allowed_tools: list[str] | None = None,
    permission_mode: str = "acceptEdits",
    model: str | None = None,
    json_schema: dict | None = None,
    max_budget_usd: float | None = None,
    timeout_s: int = 1800,
    append_system_prompt: str | None = None,
    extra_args: list[str] | None = None,
    max_retries: int = 3,
    retry_backoff_s: float = 10.0,
) -> dict:
    """Run one headless claude turn scoped to `cwd` and return:

        {"result": str, "structured_output": dict | None, "cost_usd": float,
         "session_id": str, "raw": dict}

    `structured_output` is populated (and schema-validated by the CLI itself)
    only when `json_schema` is given; otherwise it is None and callers should
    parse `result` as free text.

    Raises AgentError if the CLI produced no parseable JSON, or if the agent's
    own turn errored. Never silently returns a guessed/partial result.

    Failures matching TRANSIENT_ERROR_PATTERNS (safeguard flags, 429/5xx,
    network blips) are retried up to `max_retries` times with exponential
    backoff, since they say nothing about whether the task is doable and
    would otherwise kill a stage — and with it a pipeline run that may
    already be hours and many dollars in. Every other failure raises
    immediately; retrying a genuinely-impossible task just burns money.
    """
    cmd = ["claude", "-p", prompt, "--output-format", "json", "--no-session-persistence"]

    tools = allowed_tools if allowed_tools is not None else DEFAULT_ALLOWED_TOOLS
    if tools:
        cmd += ["--allowedTools", " ".join(tools)]
    if permission_mode:
        cmd += ["--permission-mode", permission_mode]
    if model:
        cmd += ["--model", model]
    if json_schema is not None:
        cmd += ["--json-schema", json.dumps(json_schema)]
    if max_budget_usd is not None:
        cmd += ["--max-budget-usd", str(max_budget_usd)]
    if append_system_prompt:
        cmd += ["--append-system-prompt", append_system_prompt]
    if extra_args:
        cmd += extra_args

    last_error: AgentError | None = None
    for attempt in range(max_retries + 1):
        try:
            return _call_once(cmd, cwd, timeout_s, prompt)
        except AgentError as e:
            last_error = e
            if attempt >= max_retries or not is_transient_error(str(e)):
                raise
            delay = retry_backoff_s * (2 ** attempt)
            # stderr, so it lands in the stage's run.log without polluting the
            # last-line-JSON stdout contract.
            print(f"[agent] transient failure on attempt {attempt + 1}/{max_retries + 1}, "
                  f"retrying in {delay:.0f}s: {e}", file=sys.stderr, flush=True)
            time.sleep(delay)
    raise last_error  # unreachable; for the type checker


def _call_once(cmd: list[str], cwd: str | Path, timeout_s: int, prompt: str) -> dict:
    """One `claude -p` invocation, no retry. Raises AgentError on any failure."""
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        raise AgentError(
            f"agent call timed out after {timeout_s}s (prompt: {prompt[:120]!r}...)",
            raw={"stdout": stdout, "stderr": stderr},
        )

    stdout = (p.stdout or "").strip()
    if not stdout:
        raise AgentError(
            f"agent call produced no stdout (rc={p.returncode}): {(p.stderr or '')[-2000:]}",
            raw={"returncode": p.returncode, "stderr": p.stderr},
        )

    # --output-format json prints one JSON object; be defensive and take the
    # last non-blank line in case anything else was written to stdout first.
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    try:
        obj = json.loads(lines[-1])
    except json.JSONDecodeError as e:
        raise AgentError(
            f"could not parse agent JSON output: {e}",
            raw={"stdout": stdout, "stderr": p.stderr},
        ) from e

    if obj.get("is_error"):
        raise AgentError(f"agent turn errored: {obj.get('result')!r}", raw=obj)

    return {
        "result": obj.get("result"),
        "structured_output": obj.get("structured_output"),
        "cost_usd": obj.get("total_cost_usd"),
        "session_id": obj.get("session_id"),
        "raw": obj,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Standalone test/debug entrypoint for call_agent() -- not used by pipeline.py "
                    "directly (it imports call_agent), but handy for poking at the wrapper."
    )
    ap.add_argument("prompt")
    ap.add_argument("--cwd", default=".")
    ap.add_argument("--allowed-tools", nargs="*", default=None)
    ap.add_argument("--permission-mode", default="acceptEdits")
    ap.add_argument("--model", default=None)
    ap.add_argument("--json-schema", default=None, help="inline JSON schema string")
    ap.add_argument("--max-budget-usd", type=float, default=None)
    ap.add_argument("--timeout-s", type=int, default=1800)
    args = ap.parse_args()

    schema = json.loads(args.json_schema) if args.json_schema else None
    try:
        out = call_agent(
            args.prompt,
            args.cwd,
            allowed_tools=args.allowed_tools,
            permission_mode=args.permission_mode,
            model=args.model,
            json_schema=schema,
            max_budget_usd=args.max_budget_usd,
            timeout_s=args.timeout_s,
        )
    except AgentError as e:
        print(json.dumps({"error": str(e), "raw": e.raw}))
        return 1

    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
