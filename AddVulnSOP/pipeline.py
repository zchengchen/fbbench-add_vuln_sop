#!/usr/bin/env python3
"""Standalone orchestrator for the fbbench-add-bug SOP.

Plain Python, no Claude Code Workflow tool involved. Deterministic work
(git/docker/curl/YAML/regex edits) is delegated to the sibling AddVulnSOP/*.py
CLI modules (each already contracts "JSON as the last line of stdout",
originally written for a Workflow's executor agent to shell out to -- here
*this* script plays that role instead, via subprocess). Judgment work an
agent is genuinely needed for (finding the real fix commit, bisecting
vuln_commit against a noisy regression window, writing prose, reviewing
changelog-scrub candidates, adapting a harness build script) is delegated to
agent.call_agent(), a thin wrapper around headless `claude -p`.

State is persisted to a JSON file next to the report dir (default
<report-dir>/.pipeline_state.json) so a multi-hour run (many docker builds)
can be killed and resumed without redoing finished stages.

Usage:
    python3 pipeline.py run --report-dir /path/to/report
    python3 pipeline.py run --report-dir ... --from-stage corpus_scan
    python3 pipeline.py run --report-dir ... --only-stage find_fix_commit
    python3 pipeline.py list-stages
    python3 pipeline.py show --report-dir /path/to/report

Never pushes to any git remote or Docker Hub -- the final stage commits
locally in both repos and stops.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

SOP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SOP_DIR))

import onboarding_lib as lib  # noqa: E402
import agent as agentlib  # noqa: E402
from agent import call_agent as _call_agent_raw, AgentError  # noqa: E402

# ---------------------------------------------------------------------------
# Authorization context, prepended to every agent call via --append-system-
# prompt (not folded into the task prompt itself). Every stage prompt below
# is written in plain, precise technical language (crash, UAF, patch, exploit
# reproduction) because vague euphemisms would both hurt the agent's ability
# to do the task correctly AND read as evasive. What a cold-started headless
# call genuinely lacks -- and what this supplies -- is the surrounding
# context this whole conversation already has: this is a disclosed, already-
# fixed bug being cataloged for a defensive benchmark, not a live/undisclosed
# vulnerability being discovered or weaponized.

AUTHORIZATION_CONTEXT = (
    "Context for this task: you are assisting with FuzzingBrain-Bench, an authorized benchmark used "
    "to evaluate automated bug-finding/patching tools. The bug in question was already publicly "
    "reported via OSS-Fuzz/ClusterFuzz and is already fixed upstream -- you are cataloging a "
    "resolved, disclosed issue (root cause, reproduction, regression testing) for defensive "
    "evaluation purposes, not discovering or weaponizing a new/undisclosed vulnerability. Any file "
    "deletions or edits you're asked to make are ordinary benchmark test-set hygiene (e.g. removing "
    "already-published changelog entries so a benchmark solver can't just grep the answer out of the "
    "changelog -- comparable to scrubbing answer keys out of training data), not concealment of a "
    "live security issue."
)


def call_agent(prompt, cwd, **kwargs):
    """Wraps agent.call_agent, always injecting AUTHORIZATION_CONTEXT as the
    system-prompt addition unless a caller explicitly overrides it."""
    kwargs.setdefault("append_system_prompt", AUTHORIZATION_CONTEXT)
    return _call_agent_raw(prompt, cwd, **kwargs)


# ---------------------------------------------------------------------------
# subprocess helpers


def run_tool(script: str, args: list[str], timeout_s: int = 600) -> dict:
    """Shell out to an AddVulnSOP/<script>.py CLI, parse its last-line JSON."""
    cmd = [sys.executable, str(SOP_DIR / script)] + [str(a) for a in args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"{script} timed out after {timeout_s}s") from e
    lines = [ln for ln in (p.stdout or "").strip().splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError(f"{script} produced no stdout (rc={p.returncode}): {(p.stderr or '')[-2000:]}")
    try:
        obj = json.loads(lines[-1])
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"{script} did not emit parseable JSON: {e}\n"
            f"stdout tail: {p.stdout[-1500:]}\nstderr tail: {p.stderr[-1500:]}"
        ) from e
    obj["_returncode"] = p.returncode
    return obj


def _answers_python(answers_repo: Path) -> tuple[str, dict]:
    venv_python = answers_repo / ".venv" / "bin" / "python3"
    if venv_python.is_file():
        return str(venv_python), {}
    import os
    env = {"PYTHONPATH": str(answers_repo)}
    return sys.executable, env


def run_answers_tool(answers_repo: Path, relpath: str, args: list[str], timeout_s: int = 1200) -> dict:
    """Run a tool inside the answers repo (needs its own venv/fbbench package)."""
    import os
    python_exe, extra_env = _answers_python(answers_repo)
    env = dict(os.environ)
    env.update(extra_env)
    cmd = [python_exe, str(answers_repo / relpath)] + [str(a) for a in args]
    p = subprocess.run(cmd, cwd=str(answers_repo), env=env, capture_output=True, text=True, timeout=timeout_s)
    return {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}


def git(cwd: Path, *args: str, timeout_s: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, timeout=timeout_s)


# ---------------------------------------------------------------------------
# state persistence


def load_state(state_file: Path) -> dict:
    if state_file.is_file():
        return json.loads(state_file.read_text())
    return {"stages": {}, "created_at": None}


def save_state(state_file: Path, state: dict) -> None:
    state_file.write_text(json.dumps(state, indent=2, sort_keys=False))


def stage_data(state: dict, name: str):
    entry = state["stages"].get(name)
    return entry["data"] if entry and entry.get("status") == "done" else None


def mark_done(state: dict, name: str, data: dict, cost_usd: float = 0.0) -> None:
    state["stages"][name] = {"status": "done", "data": data, "cost_usd": cost_usd, "ts": time.time()}


# ---------------------------------------------------------------------------
# pipeline context


class Ctx:
    def __init__(self, args):
        self.report_dir = Path(args.report_dir).resolve()
        paths = lib.find_repo_paths(
            answers_repo=args.answers_repo, public_repo=args.public_repo, oss_fuzz_repo=args.oss_fuzz_repo
        )
        self.answers_repo = paths.answers
        self.public_repo = paths.public
        self.oss_fuzz_repo = paths.oss_fuzz
        self.model = args.model
        self.state_file = Path(args.state_file).resolve() if args.state_file else self.report_dir / ".pipeline_state.json"
        self.corpus_workers = args.corpus_workers
        self.grade_url = args.grade_url


# ---------------------------------------------------------------------------
# STAGE 1: parse_report (agent) -- read report.txt/poc/upstream.txt, extract
# structured facts. Deliberately agent-driven rather than fixed regexes: OSS-
# Fuzz report formatting varies enough across projects/years that a rigid
# parser silently breaks on the next bug; the agent just reads the files.

PARSE_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "project": {"type": "string"},
        "fuzz_target": {"type": "string"},
        "language": {"type": ["string", "null"]},
        "sanitizer": {"type": "string"},
        "crash_type": {"type": "string", "description": "e.g. 'Heap-use-after-free'"},
        "operation": {"type": ["string", "null"], "enum": ["READ", "WRITE", None]},
        "crash_state_functions": {
            "type": "array", "items": {"type": "string"},
            "description": "innermost-first function names from the report's Crash State block",
        },
        "regression_window_start": {"type": ["string", "null"]},
        "regression_window_end": {"type": ["string", "null"]},
        "testcase_url": {"type": ["string", "null"]},
        "issue_url": {"type": ["string", "null"]},
        "report_filed_at": {
            "type": ["string", "null"],
            "description": "the report/issue filing timestamp if stated anywhere in the files (e.g. a "
                            "'date:' header line). Normalize to ISO 8601 (UTC) if a timezone/offset is "
                            "determinable, otherwise pass through as written. This is a strong proxy for "
                            "'a commit at/around this time reproduces' when the bug is still unfixed at "
                            "filing time -- do not discard it.",
        },
        "poc_filename": {"type": ["string", "null"], "description": "filename of the PoC in the report dir"},
        "short_title": {"type": "string", "description": "one-line human title (used in description.txt prose; "
                        "the neutral bug id is <project>-NN, assigned by compute_alias, NOT authored here)"},
    },
    "required": ["project", "fuzz_target", "crash_type", "crash_state_functions",
                 "short_title", "sanitizer"],
}


def stage_parse_report(ctx: Ctx, state: dict) -> dict:
    prompt = (
        "Read every file in the current directory (a dropped OSS-Fuzz bug report bundle -- typically "
        "just report.txt plus a PoC blob; report.txt itself may carry 'upstream: <url>' / 'date: "
        "<timestamp>' header lines ahead of the raw OSS-Fuzz report text, or those may be absent). "
        "Extract the structured facts below. Do not guess fields that aren't present -- use null. "
        "crash_state_functions must be taken verbatim from the report's 'Crash State:' block, innermost "
        "frame first. report_filed_at should come from a 'date:' header line if present."
    )
    out = call_agent(
        prompt, cwd=ctx.report_dir,
        allowed_tools=["Read", "Glob", "Grep"],
        model=ctx.model,
        json_schema=PARSE_REPORT_SCHEMA,
        timeout_s=300,
    )
    data = out["structured_output"]
    if not data:
        raise RuntimeError(f"parse_report: agent returned no structured_output: {out['result']!r}")
    poc_filename = data.get("poc_filename")
    if not poc_filename or not (ctx.report_dir / poc_filename).is_file():
        candidates = [p.name for p in ctx.report_dir.iterdir()
                      if p.is_file() and p.name not in ("report.txt", "upstream.txt")
                      and not p.name.startswith(".")]
        if len(candidates) == 1:
            data["poc_filename"] = candidates[0]
        else:
            raise RuntimeError(f"parse_report: could not resolve poc filename; candidates={candidates}")
    return {"data": data, "cost_usd": out["cost_usd"]}


# ---------------------------------------------------------------------------
# STAGE 2: clone_upstream (deterministic) -- resolve repo_url from oss-fuzz's
# project.yaml, full-clone it (no --depth).

def stage_clone_upstream(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    project = report["project"]
    out = run_tool("resolve_vuln_fix_commits.py", [
        "--project", project,
        "--oss-fuzz-repo", str(ctx.oss_fuzz_repo),
    ], timeout_s=1800)
    if "error" in out:
        raise RuntimeError(f"clone_upstream failed: {out['error']}")
    return {"data": out}


# ---------------------------------------------------------------------------
# STAGE 3: find_fix_commit (agent, Bash-enabled autonomous git-log search).
# Per SOP: search for the FIX, never the introducing commit.

FIND_FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "branch": {"type": "string", "enum": ["clean_fix", "unusable_fix", "unfixed"]},
        "fix_commit": {"type": ["string", "null"]},
        "fix_commit_subject": {"type": ["string", "null"]},
        "rationale": {"type": "string"},
        "unusable_reason": {
            "type": ["string", "null"],
            "description": "why the upstream fix can't anchor differential (release rollup / other "
                            "branch / vendored dep / large refactor) -- required if branch=unusable_fix",
        },
    },
    "required": ["branch", "rationale"],
}


def stage_find_fix_commit(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    clone = stage_data(state, "clone_upstream")
    clone_dir = clone["clone_dir"]

    crash_fns = ", ".join(report["crash_state_functions"])
    prompt = f"""You are searching a full git clone (cwd) of the upstream project '{report['project']}' \
for the commit that FIXES a specific bug -- never the commit that introduced it.

Bug facts:
  crash_type: {report['crash_type']} ({report.get('operation') or 'n/a'})
  crash_state (innermost-first): {crash_fns}
  regression_window: {report.get('regression_window_start')} .. {report.get('regression_window_end')}

Use `git log --all --format="%H %ad %s" --date=iso -i --grep=<keyword>` and \
`git log --format="%H %ad %s" --date=iso -- <file>` to search, then `git show <sha>` to read candidate \
diffs. Decide which of three situations applies:
  - clean_fix: a single clean upstream commit fixes this bug and can anchor a differential build.
  - unusable_fix: it WAS fixed upstream, but the fix can't anchor differential as-is (landed as a \
release rollup, on a different branch, inside a vendored dependency, or buried in an unrelated large \
refactor) -- explain unusable_reason.
  - unfixed: still unfixed upstream.

Return the fix_commit sha (full 40-char) when branch is clean_fix or unusable_fix. Do NOT go hunting \
for the introducing commit under any branch."""

    out = call_agent(
        prompt, cwd=clone_dir,
        allowed_tools=["Bash", "Read", "Grep", "Glob"],
        model=ctx.model,
        json_schema=FIND_FIX_SCHEMA,
        timeout_s=900,
        max_budget_usd=3.0,
    )
    data = out["structured_output"]
    if not data:
        raise RuntimeError(f"find_fix_commit: no structured_output: {out['result']!r}")
    if data["branch"] in ("clean_fix", "unusable_fix") and not data.get("fix_commit"):
        raise RuntimeError(f"find_fix_commit: branch={data['branch']} but no fix_commit given")
    return {"data": data, "cost_usd": out["cost_usd"]}


# ---------------------------------------------------------------------------
# STAGE 4: resolve_vuln_commit.
#   - unfixed branch: deterministic, vuln_commit = HEAD (already resolved by
#     clone_upstream when fix_commit is absent -- but clone_upstream ran
#     BEFORE fix_commit was known, so re-resolve here with the real fix_commit
#     wired in for clean_fix/unusable_fix).
#   - clean_fix/unusable_fix: agent-driven bisection against the regression
#     window, using reproduce_at_commit.py as its verification tool. Startup
#     hypothesis (fix_commit^) is NOT trusted blindly -- known failure mode,
#     see resolve_vuln_fix_commits.py's docstring: OSS-Fuzz's reported fix
#     range is a coarse periodic-build checkpoint, not necessarily adjacent
#     git commits.

RESOLVE_VULN_SCHEMA = {
    "type": "object",
    "properties": {
        "vuln_commit": {"type": "string"},
        "confirmed_signature_match": {"type": "boolean"},
        "fix_confirmed_clean": {"type": ["boolean", "null"]},
        "asan_summary": {"type": ["string", "null"]},
        "candidates_tried": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "string"},
    },
    "required": ["vuln_commit", "confirmed_signature_match", "notes"],
}


def stage_resolve_vuln_commit(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    clone = stage_data(state, "clone_upstream")
    fix = stage_data(state, "find_fix_commit")
    clone_dir = clone["clone_dir"]
    project = report["project"]
    fuzzer = report["fuzz_target"]
    poc_path = str((ctx.report_dir / report["poc_filename"]).resolve())

    if fix["branch"] == "unfixed":
        rc = run_tool("resolve_vuln_fix_commits.py", [
            "--repo-url", clone["repo_url"], "--clone-dir", clone_dir,
        ], timeout_s=600)
        return {"data": {
            # resolve_vuln_fix_commits.py now emits the resolved commit as
            # `vuln_version` (its vuln.yaml home); we keep the pipeline-internal
            # key `vuln_commit` and only rename it at the vuln.yaml write site.
            "vuln_commit": rc["vuln_version"], "fix_commit": None,
            "confirmed_signature_match": None, "notes": "unfixed upstream; vuln_commit=HEAD",
        }}

    fix_commit = fix["fix_commit"]
    report_filed_at = report.get("report_filed_at")
    prompt = f"""You must determine the correct `vuln_commit` for a bug in '{project}', fuzz target \
'{fuzzer}', whose upstream fix is commit {fix_commit} ({fix.get('fix_commit_subject') or ''}).

Repo clone (full history, no --depth) is at: {clone_dir}
PoC file (crashes at vuln_commit, must NOT crash at fix_commit): {poc_path}
Report was filed/discovered at: {report_filed_at or 'unknown -- not stated in the report'}
Reported regression window (coarse, see gotcha below): {report.get('regression_window_start')} .. {report.get('regression_window_end')}
Expected crash signature: {report['crash_type']} in {', '.join(report['crash_state_functions'])}

`vuln_commit` just needs to be SOME commit that empirically reproduces this exact crash signature -- \
it does NOT need to be the oldest possible reproducing commit, and it is explicitly NOT your job to \
find the commit that introduced the bug (that's a deliberate benchmark-design rule, not a shortcut you \
should try to correct for). Stop as soon as you have one confirmed-reproducing commit.

KNOWN GOTCHA -- do not assume `{fix_commit}^` (the fix's immediate git parent) reproduces the bug, and \
do not assume the reported regression window brackets when the vulnerable code was actually written. \
OSS-Fuzz's regression window only reflects when the FUZZER started triggering the crash (e.g. because \
a harness/coverage change made an already-old code path newly reachable) -- it is not reliable evidence \
of when the bug was introduced, and a commit picked by date from that window alone can land on a \
completely unrelated commit. Verify every hypothesis empirically; never accept a candidate on \
date/message reasoning alone.

STRONGEST HYPOTHESIS FIRST: if a report-filed/discovered date is given above, that is much stronger \
signal than the regression window -- if the bug was already unfixed at that moment (which it was, \
since OSS-Fuzz found it by fuzzing), then whatever commit was at the tip of this project's default \
branch at that time is very likely to reproduce, regardless of when the bug was actually introduced. \
Resolve it with e.g. `git log --before="<report_filed_at>" -1 --format=%H <default-branch>` (adjust \
format to whatever `git log` accepts for the given date string) and test THAT candidate before trying \
anything else.

Tool available: `python3 {SOP_DIR / 'reproduce_at_commit.py'} --oss-fuzz-repo {ctx.oss_fuzz_repo} \
--project {project} --fuzzer {fuzzer} --sha <candidate-sha> --testcase {poc_path}` -- this patches the \
oss-fuzz Dockerfile to check out <candidate-sha>, builds with ASan, reproduces the PoC, restores the \
Dockerfile, and prints one JSON line with build/reproduce results including the ASan summary and top \
frames. Each call takes several minutes (a real docker build) -- budget your candidate tries wisely.

Procedure:
  1. If report_filed_at is known, resolve and try the commit at that date first (see above).
  2. Otherwise (or if that doesn't reproduce), try `{fix_commit}^` as the next-cheapest hypothesis.
  3. If neither reproduces with the expected signature, use `git log` (informed by whichever dates you \
do have) to pick better candidates -- do not scan every commit one by one.
  4. The MOMENT any candidate reproduces with a matching signature, stop searching further back -- that \
is your vuln_commit. Also verify {fix_commit} itself does NOT crash on the same PoC (fix_confirmed_clean).
  5. Report every sha you tried in candidates_tried.

Do not stop at a plausible-looking commit without actually running the tool against it."""

    out = call_agent(
        prompt, cwd=clone_dir,
        allowed_tools=["Bash", "Read", "Grep", "Glob"],
        model=ctx.model,
        json_schema=RESOLVE_VULN_SCHEMA,
        timeout_s=7200,
        max_budget_usd=15.0,
    )
    data = out["structured_output"]
    if not data or not data.get("confirmed_signature_match"):
        raise RuntimeError(f"resolve_vuln_commit: bisection did not confirm a matching signature: {out['result']!r}")
    data["fix_commit"] = fix_commit
    return {"data": data, "cost_usd": out["cost_usd"]}


# ---------------------------------------------------------------------------
# STAGE 5: compute_alias (deterministic) + create the answers-repo bug dir.

def stage_compute_alias(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    project = report["project"]
    # Unified identity: dir name == bug_id == public alias == <project>-NN.
    # compute_alias.py returns the next sequential id; there is no separate
    # descriptive id to feed in.
    out = run_tool("compute_alias.py", [
        "--project", project, "--answers-repo", str(ctx.answers_repo),
    ])
    bug_id = out["bug_id"]
    bug_dir = ctx.answers_repo / "bugs" / project / bug_id
    bug_dir.mkdir(parents=True, exist_ok=True)
    # New per-bug layout: build/ (Dockerfile + build.sh), harness/ (source),
    # poc/ (poc.bin only), grader/ (expected.yaml), utils/ (generators).
    for sub in ("build", "harness", "poc", "grader", "utils"):
        (bug_dir / sub).mkdir(exist_ok=True)
    out["bug_dir"] = str(bug_dir)
    return {"data": out}


# ---------------------------------------------------------------------------
# STAGE 6: scaffold_harness (find_sibling_bundle.py reuse, else
# derive_dockerfile.py fallback, agent finalizes/adapts for this bug's own
# fuzz target and writes build/Dockerfile + build/build.sh + harness/ source).

SCAFFOLD_HARNESS_SCHEMA = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean"},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "harness_meta": {
            "type": "object",
            "description": "the harness/build facts you just encoded -- used verbatim to generate the "
                           "answers bench.yaml (minimal), vuln.yaml, and the public bench.yaml. Report "
                           "what you actually wrote, not a guess.",
            "properties": {
                "language": {"type": "string", "description": "c | cpp | jvm"},
                "build_system": {"type": "string", "description": "autoconf|cmake|meson|maven|make|handrolled|..."},
                "harness_type": {"type": "string", "description": "libfuzzer | java"},
                "entrypoint": {"type": "string", "description": "LLVMFuzzerTestOneInput, or <Class>.fuzzerTestOneInput for jvm"},
                "engine": {"type": "string", "description": "libfuzzer | jazzer"},
                "sanitizer": {"type": "string", "description": "the crash ORACLE that captures the bug: asan|ubsan|libfuzzer|jazzer"},
                "invocation": {"type": "array", "items": {"type": "string"}, "description": 'e.g. ["-rss_limit_mb=256","@@"] or ["@@"]'},
                "rss_limit_mb": {"type": ["integer", "null"]},
                "timeout_s": {"type": ["integer", "null"]},
                "provenance": {"type": "string", "description": "oss-fuzz if the fuzz target is upstream's own; fuzzingbrain if hand-authored"},
                "is_oss_fuzz": {"type": "boolean", "description": "true if this bug's fuzz target is an official OSS-Fuzz target"},
            },
            "required": ["language", "build_system", "harness_type", "entrypoint", "engine",
                         "sanitizer", "invocation", "provenance", "is_oss_fuzz"],
        },
    },
    "required": ["ok", "harness_meta"],
}


def stage_scaffold_harness(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    clone = stage_data(state, "clone_upstream")
    vuln = stage_data(state, "resolve_vuln_commit")
    alias = stage_data(state, "compute_alias")
    project = report["project"]
    bug_dir = Path(alias["bug_dir"])
    vuln_commit = vuln["vuln_commit"]

    sibling = run_tool("find_sibling_bundle.py", ["--project", project, "--answers-repo", str(ctx.answers_repo)])

    if sibling.get("found"):
        reference = (
            f"An existing sibling bug bundle for this project was found (bug_id={sibling['sibling_bug_id']}). "
            f"Its build/Dockerfile:\n```\n{sibling['dockerfile']}\n```\n"
            f"Its build/build.sh:\n```\n{sibling.get('build_sh') or ''}\n```\n"
            f"Its harness/ source files: {json.dumps(sorted((sibling.get('harness_files') or {}).keys()))}\n"
            f"Sibling bench.yaml/vuln.yaml metadata: {json.dumps(sibling['sibling_bench'])}\n"
            f"This new bug's fuzz target is '{report['fuzz_target']}', which may DIFFER from the "
            f"sibling's fuzz target -- adapt build/build.sh to build and link the correct "
            f"OSS-Fuzz fuzz-target source for '{report['fuzz_target']}' (inspect the cloned repo at "
            f"{clone['clone_dir']} -- likely under fuzz/ -- and how the project's own "
            f"fuzz/oss-fuzz-build.sh or build.sh compiles/links that specific target) rather than "
            f"reusing the sibling's fuzz target verbatim."
        )
    else:
        derived = run_tool("derive_dockerfile.py", [
            "--project", project, "--vuln-commit", vuln_commit,
            "--oss-fuzz-repo", str(ctx.oss_fuzz_repo),
        ])
        reference = (
            f"No existing sibling bundle for this project. A mechanically-derived best-effort draft "
            f"(may contain TODO placeholders -- see warnings) is:\nbuild/Dockerfile:\n```\n{derived['dockerfile']}\n```\n"
            f"build/build.sh:\n```\n{derived['harness_build_sh']}\n```\n"
            f"Generator warnings: {derived.get('warnings')}\n"
            f"Resolve every TODO by inspecting the cloned repo at {clone['clone_dir']} and the "
            f"oss-fuzz project files at {ctx.oss_fuzz_repo / 'projects' / project}."
        )

    prompt = f"""Write build/Dockerfile and build/build.sh (relative to your cwd, which IS that bug \
directory {bug_dir.name}) for a new challenge bundle, and place any harness SOURCE files under harness/. \
VULN_COMMIT must be {vuln_commit}. SOURCE_DATE_EPOCH must be 1735689600. Fuzz target: \
'{report['fuzz_target']}'. Build system: mirror whatever this project actually uses.

Per-bug layout (post-refactor): build/Dockerfile + build/build.sh hold the build recipe; harness/ holds \
ONLY the harness source (e.g. harness.c / Harness.java), never build.sh.

{reference}

The build/Dockerfile must clone the project's real upstream URL ({clone['repo_url']}) at ${{VULN_COMMIT}}, \
then `COPY harness/ /src/harness/` and `COPY build/build.sh /src/build/build.sh`, then RUN build-libs and \
RUN harness for debug, debug-asan, release-asan, coverage configs (all invoked as /src/build/build.sh ...) \
-- mirror the exact shape/flags of the reference above unless this project's build system genuinely \
differs. build/build.sh must implement the `build-libs` / `harness <config>` subcommand contract (see \
reference). You have Bash access to explore the cloned repo at {clone['clone_dir']} (read-only exploration \
is fine; do not modify it) to confirm the real fuzz-target source path and its exact compile/link flags \
before writing the build script -- do not guess.

Finally, report `harness_meta` describing exactly what you encoded (language, build_system, harness_type, \
entrypoint, engine, sanitizer, invocation, rss_limit_mb, timeout_s, provenance, is_oss_fuzz). These drive \
the generated bench.yaml/vuln.yaml, so they must match the build/Dockerfile + build/build.sh you wrote."""

    out = call_agent(
        prompt, cwd=bug_dir,
        allowed_tools=["Bash", "Read", "Write", "Grep", "Glob"],
        model=ctx.model,
        json_schema=SCAFFOLD_HARNESS_SCHEMA,
        timeout_s=1800,
        max_budget_usd=5.0,
        extra_args=["--add-dir", clone["clone_dir"]],
    )
    data = out["structured_output"] or {"ok": False, "warnings": ["no structured_output returned"]}
    if not (bug_dir / "build" / "Dockerfile").is_file() or not (bug_dir / "build" / "build.sh").is_file():
        raise RuntimeError(f"scaffold_harness: agent did not write build/Dockerfile + build/build.sh: {out['result']!r}")
    return {"data": data, "cost_usd": out["cost_usd"]}


# ---------------------------------------------------------------------------
# STAGE 7: build_release_asan + verify PoC crash signature matches report.

def stage_build_release_asan(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    vuln = stage_data(state, "resolve_vuln_commit")
    report = stage_data(state, "parse_report")
    bug_dir = Path(alias["bug_dir"])

    build = run_tool("build_binaries.py", [
        "--bug-dir", str(bug_dir), "--config", "release-asan", "--vuln-commit", vuln["vuln_commit"],
    ], timeout_s=2400)
    if not build.get("built"):
        raise RuntimeError(f"build_release_asan failed: {build.get('log_tail', '')[-2000:]}")

    harness = bug_dir / "binaries" / "release-asan" / "harness"
    poc_path = (ctx.report_dir / report["poc_filename"]).resolve()
    result = lib.run_harness_once(harness, ["@@"], poc_path, timeout_s=30)
    if not result["fault"]:
        raise RuntimeError(f"release-asan build did not crash on the PoC: {result}")
    return {"data": {"build": build, "harness_result": result}}


# ---------------------------------------------------------------------------
# STAGE 8: build_fixed_asan (+ optional local patch) + verify PoC does NOT
# crash.

def stage_build_fixed_asan(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    vuln = stage_data(state, "resolve_vuln_commit")
    report = stage_data(state, "parse_report")
    bug_dir = Path(alias["bug_dir"])
    fix_commit = vuln.get("fix_commit")
    if not fix_commit:
        raise RuntimeError("build_fixed_asan: no fix_commit resolved (unfixed-upstream bugs need a "
                            "fix_patch and don't reach this stage the same way -- not yet automated)")

    build = run_tool("build_binaries.py", [
        "--bug-dir", str(bug_dir), "--config", "fixed-asan", "--fix-commit", fix_commit,
    ], timeout_s=2400)
    if not build.get("built"):
        raise RuntimeError(f"build_fixed_asan failed: {build.get('log_tail', '')[-2000:]}")

    harness = bug_dir / "binaries" / "fixed-asan" / "harness"
    poc_path = (ctx.report_dir / report["poc_filename"]).resolve()
    result = lib.run_harness_once(harness, ["@@"], poc_path, timeout_s=30)
    if result["fault"]:
        raise RuntimeError(
            f"fixed-asan STILL crashes on the PoC at fix_commit={fix_commit} -- wrong fix_commit or "
            f"differential doesn't hold: {result}"
        )
    return {"data": {"build": build, "harness_result": result}}


# ---------------------------------------------------------------------------
# STAGE 9: corpus_scan against both binaries; loop with an agent-diagnosed
# local patch if fixed-asan shows any unrelated crash.

def stage_corpus_scan(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    alias = stage_data(state, "compute_alias")
    bug_dir = Path(alias["bug_dir"])
    project = report["project"]
    target = report["fuzz_target"]

    vuln_scan = run_tool("corpus_scan.py", [
        "--project", project, "--target", target,
        "--harness", str(bug_dir / "binaries" / "release-asan" / "harness"),
        "--download-corpus", "--workers", str(ctx.corpus_workers),
    ], timeout_s=3600)

    fixed_scan = run_tool("corpus_scan.py", [
        "--project", project, "--target", target,
        "--harness", str(bug_dir / "binaries" / "fixed-asan" / "harness"),
        "--download-corpus", "--workers", str(ctx.corpus_workers),
    ], timeout_s=3600)

    return {"data": {"vuln_scan": vuln_scan, "fixed_scan": fixed_scan}}


HANDLE_ANOMALY_SCHEMA = {
    "type": "object",
    "properties": {
        "needs_patch": {"type": "boolean", "description": "true only for scenario (a): a local "
                        "patch/patch.diff applied to the fixed-asan build only"},
        "patch_relpath": {"type": ["string", "null"], "description": "path to the written patch, relative "
                          "to the bug dir -- always 'patch/patch.diff'"},
        "harness_build_modified": {"type": "boolean", "description": "true if you directly edited "
                                   "build/build.sh (scenario (b)) -- both release-asan and fixed-asan "
                                   "will be rebuilt from it and rescanned"},
        "root_cause": {"type": ["string", "null"]},
        "notes": {"type": "string"},
    },
    "required": ["needs_patch", "harness_build_modified", "notes"],
}


def stage_handle_corpus_anomaly(ctx: Ctx, state: dict) -> dict:
    scan = stage_data(state, "corpus_scan")
    fixed_summaries = scan["fixed_scan"].get("summaries", [])
    if not fixed_summaries:
        return {"data": {"needs_patch": False, "notes": "fixed-asan corpus scan is clean, nothing to do"}}

    alias = stage_data(state, "compute_alias")
    vuln = stage_data(state, "resolve_vuln_commit")
    bug_dir = Path(alias["bug_dir"])
    prompt = f"""The differential oracle build (fixed-asan, at fix_commit={vuln.get('fix_commit')}) is \
NOT clean against the real historical fuzzing corpus -- it still crashes on some inputs:

{json.dumps(fixed_summaries, indent=2)}

Diagnose the root cause. You have Bash/Read access to the fixed-asan harness at \
{bug_dir / 'binaries' / 'fixed-asan' / 'harness'}, to build/build.sh, and to a scratch clone -- feel \
free to `git clone` the upstream repo yourself if you need to read source at fix_commit or vuln_commit.

IMPORTANT -- calibrate the fix to what this benchmark actually needs, nothing more:
  - This is NOT a real upstream contribution. The fix does not need to be "maintainer-acceptable", \
preserve full functionality, or handle every edge case correctly. Its ONLY job is to stop the fixed-\
asan oracle from crashing on inputs that are NOT this bug -- so an evaluated agent can't stumble onto \
an unrelated crash and have it misread as solving (or interfering with) this challenge. A blunt, even \
slightly hacky suppression (disabling a code path, adding an arbitrary limit, short-circuiting a \
check) is perfectly fine as long as it doesn't touch or mask the target bug's own crash/fix behavior.
  - First figure out WHERE the bug actually lives, since that changes where the fix belongs:
    (a) If it's a real defect in the library SOURCE that the fix commit itself introduced or left \
standing (unrelated to vuln_commit/fix_commit's own diff), a local source patch applied ONLY to the \
fixed-asan build is correct -- write a plain `git diff`-format patch and save it as patch/patch.diff \
inside this bug dir (report patch_relpath="patch/patch.diff"). This is local-only: never applied to \
vuln_commit, only when building this bug's own fixed-asan oracle.
    (b) If it's a gap in THIS bug's own build/build.sh (e.g. missing a build flag/macro that real \
OSS-Fuzz always sets, missing a resource limit) that affects vuln-asan and fixed-asan EQUALLY, do NOT \
patch fixed-asan only -- that leaves vuln-asan (the public-shipped build) still crash-prone on the \
same unrelated inputs while fixed-asan is clean, which creates a spurious differential-positive risk \
(crash-on-vuln/no-crash-on-fixed for something that isn't a real bug). Instead edit build/build.sh \
directly (you have Write access) so BOTH binaries build the same corrected way, set needs_patch=false \
and harness_build_modified=true, and explain the harness fix you made in root_cause/notes. Both \
release-asan and fixed-asan will automatically be rebuilt from your corrected script and rescanned."""

    out = call_agent(
        prompt, cwd=bug_dir,
        allowed_tools=["Bash", "Read", "Write", "Grep", "Glob"],
        model=ctx.model,
        json_schema=HANDLE_ANOMALY_SCHEMA,
        timeout_s=3600,
        max_budget_usd=8.0,
    )
    data = out["structured_output"] or {"needs_patch": False, "notes": "no structured_output"}
    return {"data": data, "cost_usd": out["cost_usd"]}


def stage_rebuild_fixed_asan_with_patch(ctx: Ctx, state: dict) -> dict:
    """Handles both anomaly-fix scenarios from stage_handle_corpus_anomaly:
      (a) needs_patch: a local patch/patch.diff, applied to fixed-asan only.
      (b) harness_build_modified: the agent edited build/build.sh directly,
          which affects BOTH binaries -- rebuild and rescan both, not just
          fixed-asan, or vuln-asan is left crash-prone on the same class
          while fixed-asan alone gets cleaned (a spurious-differential risk).
    """
    anomaly = stage_data(state, "handle_corpus_anomaly")
    needs_patch = anomaly.get("needs_patch")
    harness_modified = anomaly.get("harness_build_modified")
    if not needs_patch and not harness_modified:
        return {"data": {"skipped": True}}

    alias = stage_data(state, "compute_alias")
    vuln = stage_data(state, "resolve_vuln_commit")
    report = stage_data(state, "parse_report")
    bug_dir = Path(alias["bug_dir"])
    result = {}

    if needs_patch:
        # patch_relpath is now bug-dir-relative ("patch/patch.diff"), the same
        # file tools/build_fixed.py reads in the answers repo.
        patch_path = bug_dir / anomaly["patch_relpath"]
        build = run_tool("build_binaries.py", [
            "--bug-dir", str(bug_dir), "--config", "fixed-asan",
            "--fix-commit", vuln["fix_commit"], "--patch", str(patch_path),
        ], timeout_s=2400)
        if not build.get("built"):
            raise RuntimeError(f"rebuild fixed-asan with patch failed: {build.get('log_tail', '')[-2000:]}")
        rescan = run_tool("corpus_scan.py", [
            "--project", report["project"], "--target", report["fuzz_target"],
            "--harness", str(bug_dir / "binaries" / "fixed-asan" / "harness"),
            "--download-corpus", "--workers", str(ctx.corpus_workers),
        ], timeout_s=3600)
        if rescan.get("summaries"):
            raise RuntimeError(f"fixed-asan still not clean after patch: {rescan['summaries']}")
        result["fixed_asan_patch"] = {"build": build, "rescan": rescan}

    if harness_modified:
        poc_path = (ctx.report_dir / report["poc_filename"]).resolve()

        vuln_build = run_tool("build_binaries.py", [
            "--bug-dir", str(bug_dir), "--config", "release-asan", "--vuln-commit", vuln["vuln_commit"],
        ], timeout_s=2400)
        if not vuln_build.get("built"):
            raise RuntimeError(f"rebuild release-asan from corrected harness failed: {vuln_build.get('log_tail', '')[-2000:]}")
        vuln_check = lib.run_harness_once(bug_dir / "binaries" / "release-asan" / "harness", ["@@"], poc_path, timeout_s=30)
        if not vuln_check["fault"]:
            raise RuntimeError(f"release-asan no longer reproduces the target bug after harness fix: {vuln_check}")

        fix_commit = vuln.get("fix_commit")
        if fix_commit:
            fixed_build = run_tool("build_binaries.py", [
                "--bug-dir", str(bug_dir), "--config", "fixed-asan", "--fix-commit", fix_commit,
            ], timeout_s=2400)
            if not fixed_build.get("built"):
                raise RuntimeError(f"rebuild fixed-asan from corrected harness failed: {fixed_build.get('log_tail', '')[-2000:]}")
            fixed_check = lib.run_harness_once(bug_dir / "binaries" / "fixed-asan" / "harness", ["@@"], poc_path, timeout_s=30)
            if fixed_check["fault"]:
                raise RuntimeError(f"fixed-asan still crashes on the PoC after harness fix: {fixed_check}")
        else:
            fixed_build = fixed_check = None

        vuln_rescan = run_tool("corpus_scan.py", [
            "--project", report["project"], "--target", report["fuzz_target"],
            "--harness", str(bug_dir / "binaries" / "release-asan" / "harness"),
            "--download-corpus", "--workers", str(ctx.corpus_workers),
        ], timeout_s=3600)
        fixed_rescan = None
        if fix_commit:
            fixed_rescan = run_tool("corpus_scan.py", [
                "--project", report["project"], "--target", report["fuzz_target"],
                "--harness", str(bug_dir / "binaries" / "fixed-asan" / "harness"),
                "--download-corpus", "--workers", str(ctx.corpus_workers),
            ], timeout_s=3600)
            if fixed_rescan.get("summaries"):
                raise RuntimeError(f"fixed-asan still not clean after harness fix: {fixed_rescan['summaries']}")

        result["harness_rebuild"] = {
            "vuln_build": vuln_build, "vuln_check": vuln_check, "vuln_rescan": vuln_rescan,
            "fixed_build": fixed_build, "fixed_check": fixed_check, "fixed_rescan": fixed_rescan,
        }
        # coverage also needs rebuilding from the corrected script -- build_coverage
        # stage runs later in STAGE_ORDER and will pick this up unconditionally.

    return {"data": result}


# ---------------------------------------------------------------------------
# STAGE 10: build_coverage.

def stage_build_coverage(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    vuln = stage_data(state, "resolve_vuln_commit")
    bug_dir = Path(alias["bug_dir"])
    build = run_tool("build_binaries.py", [
        "--bug-dir", str(bug_dir), "--config", "coverage", "--vuln-commit", vuln["vuln_commit"],
    ], timeout_s=2400)
    if not build.get("built"):
        raise RuntimeError(f"build_coverage failed: {build.get('log_tail', '')[-2000:]}")
    return {"data": build}


# ---------------------------------------------------------------------------
# STAGE 11: gen_expected_yaml draft, then agent trims/finalizes it (never
# fabricates new values -- only reviews the real derived draft).

def stage_gen_expected_yaml(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    report = stage_data(state, "parse_report")
    clone = stage_data(state, "clone_upstream")
    bug_dir = Path(alias["bug_dir"])
    poc_path = (ctx.report_dir / report["poc_filename"]).resolve()

    draft = run_tool("gen_expected_yaml.py", [
        "--harness", str(bug_dir / "binaries" / "release-asan" / "harness"),
        "--poc", str(poc_path),
        "--src-dir", clone["clone_dir"],
        "--bug-id", alias["alias"],
    ], timeout_s=120)
    return {"data": draft}


FINALIZE_EXPECTED_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}


def stage_finalize_expected_yaml(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    draft = stage_data(state, "gen_expected_yaml")
    bug_dir = Path(alias["bug_dir"])

    prompt = f"""Write grader/expected.yaml (relative to your cwd, the bug directory) from this REAL, \
already-derived ASan-trace data -- do not invent or adjust any file/function/line value yourself, only \
copy them through (you may fix formatting/YAML syntax and trim the sanitizer/class strings to their \
canonical bare form):

reach: {json.dumps(draft['reach'])}
class: {json.dumps(draft['class'])}
site: {json.dumps(draft['site'])}
warnings from the generator: {draft.get('warnings')}

If warnings indicate missing file/line/function data, you may re-derive by reading the raw_trace below \
and the source at {{clone_dir}}, but never fabricate a plausible-sounding line number.
raw_trace: {json.dumps(draft.get('raw_trace'))}"""

    out = call_agent(
        prompt, cwd=bug_dir,
        allowed_tools=["Read", "Write"],
        model=ctx.model,
        json_schema=FINALIZE_EXPECTED_SCHEMA,
        timeout_s=300,
    )
    if not (bug_dir / "grader" / "expected.yaml").is_file():
        raise RuntimeError(f"finalize_expected_yaml: expected.yaml not written: {out['result']!r}")
    return {"data": out["structured_output"] or {"ok": True}, "cost_usd": out["cost_usd"]}


# ---------------------------------------------------------------------------
# STAGE 12: write the MINIMAL answers bench.yaml (public-facing 5 fields) +
# description.txt + optional NOTES.md + poc/poc.bin. All answer metadata now
# lives in vuln.yaml, written by the next stage (STAGE 13). PROVENANCE.md is
# gone (deleted repo-wide); NOTES.md is an optional human-only provenance note.

WRITE_DOCS_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}


def stage_write_answers_docs(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    clone = stage_data(state, "clone_upstream")
    fix = stage_data(state, "find_fix_commit")
    vuln = stage_data(state, "resolve_vuln_commit")
    alias = stage_data(state, "compute_alias")
    scan = stage_data(state, "corpus_scan")
    anomaly = state["stages"].get("handle_corpus_anomaly", {}).get("data")
    draft = stage_data(state, "gen_expected_yaml")
    hm = stage_data(state, "scaffold_harness").get("harness_meta") or {}
    bug_dir = Path(alias["bug_dir"])

    import shutil
    poc_src = ctx.report_dir / report["poc_filename"]
    shutil.copy2(poc_src, bug_dir / "poc" / "poc.bin")

    language = hm.get("language") or report.get("language") or "c"
    # Minimal, public-facing answers bench.yaml (5 fields). Everything else
    # (repo / vuln_version / fix_commit / capability_set / status / ...) moved
    # to the hidden vuln.yaml (STAGE 13). `language` is top-level now.
    bench = {
        "bug_id": bug_dir.name,
        "project": report["project"],
        "is_oss_fuzz": bool(hm.get("is_oss_fuzz", True)),
        "language": language,
        "harness": {
            "sanitizer": hm.get("sanitizer") or report.get("sanitizer") or "asan",
            "engine": hm.get("engine") or ("jazzer" if language == "jvm" else "libfuzzer"),
            "invocation": hm.get("invocation") or ["@@"],
        },
    }
    lib.write_yaml(bug_dir / "bench.yaml", bench)

    prompt = f"""Write description.txt (and, if there is provenance worth keeping, an optional NOTES.md) in \
the current directory (the bug's answers-repo bundle) for a new benchmark challenge. Full context:

bug_id / public alias (unified -- same string): {bug_dir.name}
project: {report['project']}
title: {report['short_title']}
crash_type: {report['crash_type']} ({report.get('operation')})
crash_state (from original report): {report['crash_state_functions']}
upstream repo: {clone['repo_url']}
vuln_commit (-> vuln.yaml metadata.vuln_version): {vuln['vuln_commit']}
fix_commit: {vuln.get('fix_commit')}  (branch classification: {fix['branch']}, rationale: {fix['rationale']})
vuln_commit resolution notes (bisection agent): {vuln.get('notes')}
real ASan trace derived from the actual harness run:
  reach: {json.dumps(draft['reach'])}
  class: {json.dumps(draft['class'])}
  site: {json.dumps(draft['site'])}
corpus differential-cleanliness scan: vuln-asan crashed={scan['vuln_scan']['crashed']}/{scan['vuln_scan']['total_files']} \
(summaries: {scan['vuln_scan']['summaries']}), fixed-asan crashed={scan['fixed_scan']['crashed']}/{scan['fixed_scan']['total_files']} \
(summaries: {scan['fixed_scan']['summaries']})
unrelated-bug local patch (if any): {anomaly}

description.txt: root-cause writeup -- summary, exact buggy line(s) with file:line, call chain from the \
confirmed ASan trace, harness explanation, upstream fix reference.

NOTES.md (OPTIONAL, human-only -- machines never read it; it REPLACES the old PROVENANCE.md): the \
bisection trail (regression window, how vuln_commit/fix_commit were verified, not just guessed), \
discovery method, and the unrelated-bug/local-patch writeup if applicable. Only write it if there is \
real provenance worth recording; skip it otherwise."""

    out = call_agent(
        prompt, cwd=bug_dir,
        allowed_tools=["Read", "Write"],
        model=ctx.model,
        json_schema=WRITE_DOCS_SCHEMA,
        timeout_s=600,
        max_budget_usd=4.0,
    )
    # description.txt is required; NOTES.md is optional (do not hard-require it).
    if not (bug_dir / "description.txt").is_file():
        raise RuntimeError(f"write_answers_docs: description.txt not written: {out['result']!r}")
    return {"data": {"bench_yaml_written": True, "language": language,
                     **(out["structured_output"] or {})}, "cost_usd": out["cost_usd"]}


# ---------------------------------------------------------------------------
# STAGE 13: write the hidden vuln.yaml (T2 answer metadata) DIRECTLY, in the
# current on-disk format. The answers repo's own tools/gen_vuln_yaml.py is
# STALE w.r.t. this format (last functional change 06-11; the 07-27 vuln.yaml
# restructure edited the data files by hand and deferred the generator code --
# see that commit's "代码触点留 §6"), and per-bug diffscan.yaml was removed
# repo-wide, so we no longer call gen_vuln_yaml.py / diffscan_freeze.py. The
# category (T2 class answer) is derived inline from the real ASan class.

_CATEGORY_MAP = {
    "heap-use-after-free": "use-after-free", "use-after-free": "use-after-free",
    "oob-read": "out-of-bounds-read", "memory-leak": "memory-leak",
    "oom": "memory-exhaustion", "allocation-size-too-big": "memory-exhaustion",
    "timeout": "excessive-computation", "stack-overflow": "stack-exhaustion",
    "undefined-behavior": "undefined-behavior", "misaligned-access": "undefined-behavior",
    "class-cast": "type-confusion",
}


def _derive_category(cls_text: str) -> str:
    """Mirror tools/gen_vuln_yaml.py's mapping: a self-describing crash class
    maps to its category; ASan spatial classes (buffer-overflow / out-of-bounds)
    are read/write-ambiguous and resolve by the READ/WRITE in the class text;
    everything else is 'unclassified' (left for the human #12 code-reading pass)."""
    c = (cls_text or "").strip().lower()
    if c in _CATEGORY_MAP:
        return _CATEGORY_MAP[c]
    if "buffer-overflow" in c or "out-of-bounds" in c:
        if "read" in c:
            return "out-of-bounds-read"
        if "write" in c:
            return "out-of-bounds-write"
    return "unclassified"


_VULN_HEADER = (
    "# vuln.yaml — HIDDEN ground-truth metadata. NOT in SANDBOX_ENTRIES, so it is\n"
    "# never staged into the agent's view. `category` is the T2 class answer — do\n"
    "# not move it into an agent-visible file. Written by the add_vuln pipeline in\n"
    "# the current vuln.yaml format (tools/gen_vuln_yaml.py is stale w.r.t. this\n"
    "# layout). `difficulty`/`category` refinement are the human passes.\n"
)


def stage_curate_and_generate(ctx: Ctx, state: dict) -> dict:
    import yaml
    report = stage_data(state, "parse_report")
    clone = stage_data(state, "clone_upstream")
    fix = stage_data(state, "find_fix_commit")
    vuln = stage_data(state, "resolve_vuln_commit")
    alias = stage_data(state, "compute_alias")
    draft = stage_data(state, "gen_expected_yaml")
    hm = stage_data(state, "scaffold_harness").get("harness_meta") or {}
    anomaly = state["stages"].get("handle_corpus_anomaly", {}).get("data")
    bug_dir = Path(alias["bug_dir"])
    bug_id = bug_dir.name

    # Read the FINALIZED class from grader/expected.yaml. finalize_expected_yaml
    # (stage 13) cleaned the raw ASan SUMMARY line into a bare crash class like
    # "heap-use-after-free"; the gen_expected_yaml DRAFT still holds the whole
    # raw SUMMARY string, which the category map can't exact-match. This mirrors
    # the real tools/gen_vuln_yaml.py, which also derives category from
    # grader/expected.yaml's class.expected.
    exp = {}
    exp_path = bug_dir / "grader" / "expected.yaml"
    if exp_path.is_file():
        try:
            exp = yaml.safe_load(exp_path.read_text()) or {}
        except Exception:
            exp = {}
    exp_cls = exp.get("class") or {}
    cls = exp_cls.get("expected", "") or (draft.get("class") or {}).get("expected", "") or ""
    category = _derive_category(cls)   # 'unclassified' -> flags a human #12 pass
    sanitizer = exp_cls.get("sanitizer") or (draft.get("class") or {}).get("sanitizer") or hm.get("sanitizer") or None
    language = hm.get("language") or report.get("language") or "c"

    # self_fix (intent per commits 3a49af3 + 1b0040c, and the operative
    # tools/build_fixed.py + tools/fix_commits.yaml model): the fixed-asan oracle
    # is built from OUR OWN patch (patch/patch.diff) applied on the vuln tree,
    # rather than a clean upstream fix_commit. That happens whenever there is no
    # usable upstream fix (branches unfixed / unusable_fix), and also when a
    # corpus-anomaly suppression patch is the differential source. build_fixed.py
    # keys on self_fix to apply patch/patch.diff; it NEVER reads a `fix_patch`
    # field, so the old `fix_patch: tools/fixes/<id>.patch` pointer is dropped
    # (deprecated leftover; it would dangle -- this pipeline writes patch/patch.diff).
    branch = fix.get("branch")
    self_fix = branch in ("unfixed", "unusable_fix") or bool(anomaly and anomaly.get("needs_patch"))
    fix_commit = vuln.get("fix_commit") if branch == "clean_fix" else None
    metadata = {
        "arch": "x86_64",
        "sanitizer": sanitizer,
        "vuln_version": vuln["vuln_commit"],   # renamed field home (was vuln_commit)
        "fix_commit": fix_commit,              # null when self_fix (no clean upstream anchor)
        "repo": clone["repo_url"],
        "timeout_s": hm.get("timeout_s") or 30,
    }

    payload = {
        "bug_id": bug_id,
        "project": report["project"],
        "language": language,
        "category": category,
        "scope": {"type": "single-library"},   # cross-library scope is curated by hand
        "metadata": metadata,
        "active": True,
        "upstream_report": report.get("testcase_url") or report.get("issue_url") or "",
        "capability_set": ["class", "crash", "differential", "reach", "site"],
        "status": "fixed",
        "cve": None,
        "disclosed": None,
    }
    if self_fix:
        payload["self_fix"] = True

    text = _VULN_HEADER + yaml.safe_dump(payload, sort_keys=False, default_flow_style=False, allow_unicode=True)
    (bug_dir / "vuln.yaml").write_text(text)

    # Register the fix in tools/fix_commits.yaml -- the OPERATIVE registry the
    # answers repo's batch differential builder (tools/build_fixed.py) reads,
    # keyed by bug_id (commit 3e3bee1). vuln.yaml.metadata.fix_commit is
    # documentation; THIS is what drives the fixed-asan build for `differential`.
    # SELF_FIX => build_fixed.py applies patch/patch.diff on the vuln tree.
    registered = False
    reg = ctx.answers_repo / "tools" / "fix_commits.yaml"
    if reg.is_file():
        reg_text = reg.read_text()
        if not re.search(rf"(?m)^{re.escape(bug_id)}\s*:", reg_text):
            sha = "SELF_FIX" if self_fix else (fix_commit or "NOT_FOUND")
            conf = "self" if self_fix else "med"
            note = (fix.get("rationale") or "added by add_vuln pipeline").replace('"', "'")[:120]
            with reg.open("a") as fp:
                if not reg_text.endswith("\n"):
                    fp.write("\n")
                fp.write(f'{bug_id}: {{sha: {sha}, conf: {conf}, note: "{note}"}}\n')
            registered = True

    return {"data": {"category": category, "self_fix": self_fix,
                     "unclassified": category == "unclassified",
                     "fix_commits_registered": registered}}


# ---------------------------------------------------------------------------
# STAGE 14: scaffold the public repo bug dir -- the SCRUBBED, runner-facing
# bench.yaml (still the stable "fat" shape: target + full harness + repro; it
# predates and was untouched by the answers-repo refactor) plus a copy of the
# harness source + build.sh for reference. NO image field (the runner resolves
# the challenge image via its --image-prefix default) and NO answer fields.

def stage_scaffold_public_repo(ctx: Ctx, state: dict) -> dict:
    import shutil
    report = stage_data(state, "parse_report")
    alias_data = stage_data(state, "compute_alias")
    hm = stage_data(state, "scaffold_harness").get("harness_meta") or {}
    project = report["project"]
    alias = alias_data["bug_id"]                 # dir == bug_id == public alias
    answers_bug_dir = Path(alias_data["bug_dir"])

    pub_dir = ctx.public_repo / "bugs" / project / alias
    pub_dir.mkdir(parents=True, exist_ok=True)
    (pub_dir / "harness").mkdir(exist_ok=True)

    language = hm.get("language") or report.get("language") or "c"
    # Derived from the harness descriptor the scaffold agent reported.
    # build_system/entrypoint/rss are best-effort -- verify them in review.
    pub_bench = {
        "bug_id": alias,
        "project": project,
        "target": {
            "language": language,
            "build_system": hm.get("build_system") or "unknown",
        },
        "harness": {
            "type": hm.get("harness_type") or ("java" if language == "jvm" else "libfuzzer"),
            "entrypoint": hm.get("entrypoint") or "LLVMFuzzerTestOneInput",
            "invocation": hm.get("invocation") or ["@@"],
            "rss_limit_mb": hm.get("rss_limit_mb") or 256,
            "timeout_s": hm.get("timeout_s") or 30,
            "provenance": hm.get("provenance") or "oss-fuzz",
            "sanitizer": hm.get("sanitizer") or report.get("sanitizer") or "asan",
        },
        "reproducibility": {
            "base_image_digest": "",
            "snapshot_debian_date": "20260101T000000Z",
            "source_date_epoch": 1735689600,
        },
    }
    lib.write_yaml(pub_dir / "bench.yaml", pub_bench)

    # Public bug dir carries the harness SOURCE (harness/) plus build.sh (the
    # answers build/build.sh copied to the public harness/build.sh, matching the
    # existing public repo layout).
    ans_harness = answers_bug_dir / "harness"
    if ans_harness.is_dir():
        for f in ans_harness.rglob("*"):
            if f.is_file():
                dst = pub_dir / "harness" / f.relative_to(ans_harness)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dst)
    build_sh_src = answers_bug_dir / "build" / "build.sh"
    if build_sh_src.is_file():
        (pub_dir / "harness" / "build.sh").write_text(build_sh_src.read_text())

    return {"data": {"pub_dir": str(pub_dir), "alias": alias}}


# ---------------------------------------------------------------------------
# NOTE: README.md and tools/sealed/CHALLENGES.md in the public repo are
# intentionally never touched by this pipeline -- both are shared, cross-bug
# documentation the user updates by hand. There used to be an
# update_public_docs stage here (first an agent+Edit version, then a read-
# only preview version); both were removed per explicit instruction to just
# ignore these two files entirely.

# ---------------------------------------------------------------------------
# STAGE 15: regrade_verify against the real mcp-server oracle.

def stage_regrade_verify(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    bug_id = Path(alias["bug_dir"]).name
    poc_path = str(Path(alias["bug_dir"]) / "poc" / "poc.bin")

    out = run_tool("regrade_verify.py", [
        "--bug-id", bug_id, "--poc", poc_path, "--answers-repo", str(ctx.answers_repo),
    ], timeout_s=600)
    if not out.get("solved"):
        llvm14 = run_tool("ensure_llvm14.py", [])
        if llvm14.get("path"):
            out = run_tool("regrade_verify.py", [
                "--bug-id", bug_id, "--poc", poc_path, "--answers-repo", str(ctx.answers_repo),
                "--llvm14-path", llvm14["path"],
            ], timeout_s=600)
    if not out.get("solved"):
        raise RuntimeError(f"regrade_verify: not solved, missing={out.get('missing')}, raw={out.get('raw_stdout', '')[-1500:]}")
    return {"data": out}


# ---------------------------------------------------------------------------
# STAGE 16: build public challenge image, scrub changelog files, verify.

SCRUB_DECISION_SCHEMA = {
    "type": "object",
    "properties": {
        "delete": {"type": "array", "items": {"type": "string"}},
        "keep_reasoning": {"type": "string"},
    },
    "required": ["delete", "keep_reasoning"],
}


def stage_build_challenge_image(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    report = stage_data(state, "parse_report")
    bug_id = Path(alias["bug_dir"]).name
    public_alias = stage_data(state, "scaffold_public_repo")["alias"]

    staged = run_answers_tool(ctx.answers_repo, "tools/sealed/build_challenge.py", [
        bug_id, "--grade-url", ctx.grade_url, "--no-build",
    ], timeout_s=600)
    if staged["returncode"] != 0:
        raise RuntimeError(f"build_challenge.py --no-build failed: {staged['stderr'][-2000:]}")
    m = re.search(r"context ready at (\S+)", staged["stdout"])
    if not m:
        raise RuntimeError(f"could not find staged context path in build_challenge.py output: {staged['stdout'][-1000:]}")
    ctx_dir = Path(m.group(1))
    src_dir = ctx_dir / "bundle" / "src"

    sweep = run_tool("scrub_changelog.py", ["--context-dir", str(src_dir)])

    if sweep["name_sweep"] or sweep["content_sweep"]:
        prompt = f"""This is a benchmark test-set decontamination task, analogous to stripping an \
answer key out of a training set: a staged public-challenge source tree at {src_dir} (an upstream \
open-source library, already fixed at this bug's fix_commit, being packaged as a benchmark task where \
a solver must independently find an already-publicly-disclosed bug) was swept for changelog/history \
files whose CONTENT would hand the solver the answer for free (function/file names, CVE numbers, \
"fixed in version X" notes) -- the equivalent of a textbook shipping with the answer key stapled to \
the exam. Candidates found:

name_sweep (filename-matched, e.g. NEWS/CHANGELOG/SECURITY/HISTORY): {sweep['name_sweep']}
content_sweep (README/*.md/*.txt containing CVE-/vulnerability/security-advisory phrases): {sweep['content_sweep']}
excerpts: {json.dumps(sweep['excerpts'], indent=2)[:4000]}

This bug's own crash function(s): {report['crash_state_functions']}

Judgement rule: delete files that are a RECORD OF PAST BUGS (changelogs, release notes, security \
advisories) -- especially any entry naming this bug's own function/file (a direct answer leak) or any \
entry for some OTHER old, already-fixed bug that could read as a decoy lead for the solver. Do NOT \
delete: inline code comments, generic security-policy sections in a README, maintainer/build/fuzzing \
guides, CI configs -- anything that is documentation rather than a history of specific past defects. \
You have Read access to inspect any file before deciding. Return the exact relative paths (from \
{src_dir}) to delete."""

        out = call_agent(
            prompt, cwd=src_dir,
            allowed_tools=["Read", "Glob", "Grep"],
            model=ctx.model,
            json_schema=SCRUB_DECISION_SCHEMA,
            timeout_s=600,
            max_budget_usd=3.0,
        )
        decision = out["structured_output"] or {"delete": [], "keep_reasoning": "no structured_output"}
        if decision["delete"]:
            applied = run_tool("scrub_changelog.py", [
                "--context-dir", str(src_dir), "--apply", ",".join(decision["delete"]),
            ])
        else:
            applied = {"deleted": [], "not_found": []}
    else:
        decision = {"delete": [], "keep_reasoning": "sweep found nothing"}
        applied = {"deleted": [], "not_found": []}

    tag = f"fbbench-challenge/{public_alias}:latest"
    build = lib.docker_build(ctx_dir, tag=tag, timeout_s=2400)
    if not build["ok"]:
        raise RuntimeError(f"docker build of challenge image failed: {build['log_tail']}")

    final_tag = f"docker.io/chenzc2001/fbbench-challenge-{public_alias}:latest"
    subprocess.run(["docker", "tag", tag, final_tag], check=True)

    return {"data": {"ctx_dir": str(ctx_dir), "sweep": sweep, "scrub_decision": decision,
                      "applied": applied, "build": build, "tag": final_tag}}


def stage_verify_challenge_image(ctx: Ctx, state: dict) -> dict:
    built = stage_data(state, "build_challenge_image")
    draft = stage_data(state, "gen_expected_yaml")
    verify = run_tool("verify_public_image.py", [
        "--image", built["tag"], "--expected-function", draft["reach"]["expected_function"] or "",
    ], timeout_s=300)
    if not verify.get("ok"):
        raise RuntimeError(f"verify_public_image failed: {verify}")
    return {"data": verify}


# ---------------------------------------------------------------------------
# STAGE 17: commit locally in both repos. NEVER push.

def stage_commit_locally(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    report = stage_data(state, "parse_report")
    project = report["project"]
    public_alias = stage_data(state, "scaffold_public_repo")["alias"]
    bug_id = Path(alias["bug_dir"]).name

    ans_msg = f"Add {bug_id} bug bundle ({report['short_title']})"
    pub_msg = f"Add {public_alias} challenge ({report['short_title']})"

    results = {}
    for repo, rel_paths, msg, key, force_paths in (
        # answers: also commit the fix_commits.yaml registration (STAGE 13 adds a
        # line), and FORCE-add the bug's build/ dir -- the answers repo .gitignore
        # has a generic `build/` rule (for Python build artifacts) that shadows
        # every bug's build/Dockerfile + build/build.sh, so a plain `git add`
        # silently drops them. The existing 68 bugs' build/ dirs are tracked via
        # the same force-add, so this matches the established convention.
        (ctx.answers_repo, [f"bugs/{project}", "tools/fix_commits.yaml"], ans_msg, "answers",
         [f"bugs/{project}/{bug_id}/build"]),
        (ctx.public_repo, [f"bugs/{project}", "tools/sealed/CHALLENGES.md", "README.md"], pub_msg, "public", []),
    ):
        add = git(repo, "add", *rel_paths)
        if add.returncode != 0:
            raise RuntimeError(f"git add failed in {repo}: {add.stderr}")
        for fp in force_paths:
            if (Path(repo) / fp).exists():
                fadd = git(repo, "add", "-f", fp)
                if fadd.returncode != 0:
                    raise RuntimeError(f"git add -f {fp} failed in {repo}: {fadd.stderr}")
        status = git(repo, "status", "--porcelain")
        if not status.stdout.strip():
            results[key] = {"committed": False, "reason": "nothing staged"}
            continue
        commit = git(repo, "commit", "-m", msg)
        results[key] = {"committed": commit.returncode == 0, "stdout": commit.stdout, "stderr": commit.stderr}
        if commit.returncode != 0:
            raise RuntimeError(f"git commit failed in {repo}: {commit.stderr}")

    return {"data": results}


# ---------------------------------------------------------------------------

STAGES: list[tuple[str, callable]] = [
    ("parse_report", stage_parse_report),
    ("clone_upstream", stage_clone_upstream),
    ("find_fix_commit", stage_find_fix_commit),
    ("resolve_vuln_commit", stage_resolve_vuln_commit),
    ("compute_alias", stage_compute_alias),
    ("scaffold_harness", stage_scaffold_harness),
    ("build_release_asan", stage_build_release_asan),
    ("build_fixed_asan", stage_build_fixed_asan),
    ("corpus_scan", stage_corpus_scan),
    ("handle_corpus_anomaly", stage_handle_corpus_anomaly),
    ("rebuild_fixed_asan_with_patch", stage_rebuild_fixed_asan_with_patch),
    ("build_coverage", stage_build_coverage),
    ("gen_expected_yaml", stage_gen_expected_yaml),
    ("finalize_expected_yaml", stage_finalize_expected_yaml),
    ("write_answers_docs", stage_write_answers_docs),
    ("curate_and_generate", stage_curate_and_generate),
    ("scaffold_public_repo", stage_scaffold_public_repo),
    ("regrade_verify", stage_regrade_verify),
    ("build_challenge_image", stage_build_challenge_image),
    ("verify_challenge_image", stage_verify_challenge_image),
    ("commit_locally", stage_commit_locally),
]
STAGE_NAMES = [n for n, _ in STAGES]


# ---------------------------------------------------------------------------
# CLI


def cmd_run(args) -> int:
    ctx = Ctx(args)
    state = load_state(ctx.state_file)
    state.setdefault("created_at", time.time())

    if args.only_stage:
        to_run = [(n, f) for n, f in STAGES if n == args.only_stage]
        if not to_run:
            print(f"unknown stage: {args.only_stage}", file=sys.stderr)
            return 2
    else:
        start_idx = STAGE_NAMES.index(args.from_stage) if args.from_stage else 0
        to_run = STAGES[start_idx:]

    for name, func in to_run:
        already = state["stages"].get(name)
        if already and already.get("status") == "done" and not args.force:
            print(f"[skip]  {name} (already done)")
            continue
        print(f"[run]   {name} ...")
        t0 = time.time()
        try:
            result = func(ctx, state)
        except Exception as e:
            print(f"[FAIL]  {name}: {e}", file=sys.stderr)
            state["stages"][name] = {"status": "failed", "error": str(e), "ts": time.time()}
            save_state(ctx.state_file, state)
            return 1
        mark_done(state, name, result["data"], cost_usd=result.get("cost_usd", 0.0))
        save_state(ctx.state_file, state)
        dt = time.time() - t0
        print(f"[done]  {name} ({dt:.0f}s)")

    print("\nAll requested stages complete. Nothing was pushed to any git remote or Docker Hub.")
    return 0


def cmd_list_stages(args) -> int:
    for i, name in enumerate(STAGE_NAMES):
        print(f"{i:2d}  {name}")
    return 0


def cmd_show(args) -> int:
    ctx = Ctx(args)
    state = load_state(ctx.state_file)
    for name in STAGE_NAMES:
        entry = state["stages"].get(name)
        status = entry["status"] if entry else "pending"
        print(f"{status:8s} {name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p):
        p.add_argument("--report-dir", required=True)
        p.add_argument("--answers-repo", default=None)
        p.add_argument("--public-repo", default=None)
        p.add_argument("--oss-fuzz-repo", default=None)
        p.add_argument("--state-file", default=None)
        p.add_argument("--model", default=None, help="override model for all agent calls")
        p.add_argument("--corpus-workers", type=int, default=8)
        # Live grading backend baked into the public challenge image as
        # BENCH_GRADE_URL. This ngrok endpoint fronts the fbbench-grader FastAPI
        # (verified: GET / -> {"service":"fbbench-grader"}, /v1/health healthy) and
        # is the ONLY publicly reachable route -- the FastAPI itself binds
        # 127.0.0.1:8078 on the oracle host with no direct public route. It exposes
        # the /grade?bug=<alias> compat endpoint the challenge client uses, so the
        # image only needs this base URL. (Confirmed grading libxml2-02 -> solved.)
        p.add_argument("--grade-url", default="https://nonretinal-arletha-arduous.ngrok-free.dev")

    p_run = sub.add_parser("run")
    add_common(p_run)
    p_run.add_argument("--from-stage", default=None, choices=STAGE_NAMES)
    p_run.add_argument("--only-stage", default=None, choices=STAGE_NAMES)
    p_run.add_argument("--force", action="store_true", help="rerun a stage even if already marked done")
    p_run.set_defaults(func=cmd_run)

    p_list = sub.add_parser("list-stages")
    p_list.set_defaults(func=cmd_list_stages)

    p_show = sub.add_parser("show")
    add_common(p_show)
    p_show.set_defaults(func=cmd_show)

    return ap


def main() -> int:
    ap = build_parser()
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
