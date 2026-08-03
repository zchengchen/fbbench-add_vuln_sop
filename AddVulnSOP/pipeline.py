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
from agent import call_agent as _call_agent_raw, AgentError, DEFAULT_MODEL  # noqa: E402
from ensure_mcp_server import ensure_mcp_server  # noqa: E402

# On-disk layout for built harness binaries under a bug's `binaries/` dir.
# Matches the answers repo's grading-oracle convention (tools/mcp-server/grade.go,
# commit f0fb0b7 "move oracle bundle to binaries/vuln/{asan,cov} and fixed/{asan}") --
# grade.go reads these exact paths directly (never through this pipeline), so
# build_binaries.py's extraction destination must match them exactly.
BIN_VULN_ASAN = Path("binaries/vuln/asan/harness")
BIN_VULN_COV = Path("binaries/vuln/cov/harness")
BIN_FIXED_ASAN = Path("binaries/fixed/asan/harness")

# The Go grading oracle (tools/mcp-server/setup.go's benchYAML struct) reads
# `capability_set` from the ANSWERS bench.yaml, not vuln.yaml -- if it's absent
# there, grade.go silently falls back to ["reach","crash","class","site"],
# which excludes "differential" from both scoring and SOLVED, even when the
# underlying round data shows it fired. Real bugs (e.g. skia-01) carry this
# same list in bench.yaml AND vuln.yaml; keep both in lockstep from one constant.
CAPABILITY_SET = ["class", "crash", "differential", "reach", "site"]

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


def bench_yaml_text(bug_id: str, project: str, is_oss_fuzz: bool, language: str,
                     sanitizer: str, engine: str, invocation: list[str]) -> str:
    """Serialize a bench.yaml BY HAND, for both repos' copies.

    Not through lib.write_yaml, and the difference is not cosmetic. Both repos
    read `capability_set` through fbbench/grading/bench_yaml.py's deliberately
    tiny reader (the public repo's own tooling, plus the answers repo's
    tools/regrade.py and tools/diffscan_report.py), and that reader recognizes a
    list ONLY when it is written on one line as `[a, b]`. PyYAML's default block
    style parses to '' -- falsy -- and capability_set() then silently
    substitutes the full default ladder, scoring a bug on capabilities it was
    never meant to be scored on. It also skips every indented line, so anything
    nested beyond `harness:` is invisible to it. Verified against the real
    reader both ways.
    """
    return "\n".join([
        f"bug_id: {bug_id}",
        f"project: {project}",
        f"is_oss_fuzz: {'true' if is_oss_fuzz else 'false'}",
        f"language: {language}",
        "harness:",
        f"  sanitizer: {sanitizer}",
        f"  engine: {engine}",
        "  invocation: [" + ", ".join(f'"{a}"' for a in invocation) + "]",
        "",
        "capability_set: [" + ", ".join(CAPABILITY_SET) + "]",
        "",
    ])


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


def run_answers_tool(answers_repo: Path, relpath: str, args: list[str], timeout_s: int = 1200,
                      extra_env: dict | None = None) -> dict:
    """Run a tool inside the answers repo (needs its own venv/fbbench package)."""
    import os
    python_exe, venv_env = _answers_python(answers_repo)
    env = dict(os.environ)
    env.update(venv_env)
    if extra_env:
        env.update(extra_env)
    cmd = [python_exe, str(answers_repo / relpath)] + [str(a) for a in args]
    p = subprocess.run(cmd, cwd=str(answers_repo), env=env, capture_output=True, text=True, timeout=timeout_s)
    return {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}


def git(cwd: Path, *args: str, timeout_s: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, timeout=timeout_s)


def default_branch(repo: Path) -> str:
    """Best-effort detection of the repo's primary branch (main/master), so
    a new bug's newbug/<bug_id> branch is always cut from ITS latest HEAD,
    not from whatever remote-tracking guess we can't otherwise resolve."""
    symref = git(repo, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
    if symref.returncode == 0 and symref.stdout.strip():
        return symref.stdout.strip().rsplit("/", 1)[-1]
    for candidate in ("main", "master"):
        if git(repo, "show-ref", "--verify", "--quiet", f"refs/heads/{candidate}").returncode == 0:
            return candidate
    return git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()


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
        self.bug_id = getattr(args, "bug_id", None)


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
        "upstream_url": {
            "type": ["string", "null"],
            "description": "the report/issue tracker URL from report.txt's own 'upstream: <url>' header "
                            "line, verbatim -- this is the canonical source for vuln.yaml's "
                            "upstream_report field. Only fall back to testcase_url/issue_url below if no "
                            "'upstream:' header line is present.",
        },
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
    # Per-run clone dir, keyed on report_dir's own name -- NOT bug_id, which
    # isn't assigned until STAGE 4 (compute_alias), after this stage. Without
    # this, resolve_vuln_fix_commits.py's default (/tmp/fbbench-src-<project>,
    # shared by PROJECT NAME ALONE) would be shared by every concurrent
    # onboarding run for the same project: a race on `git fetch`, and a risk
    # that find_fix_commit's agent (has raw Bash access to this clone) checks
    # out something and yanks the HEAD out from under a sibling run reading
    # the same directory.
    clone_dir = Path("/tmp") / f"fbbench-src-{project}-{ctx.report_dir.name}"
    out = run_tool("resolve_vuln_fix_commits.py", [
        "--project", project,
        "--oss-fuzz-repo", str(ctx.oss_fuzz_repo),
        "--clone-dir", str(clone_dir),
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


def _pin_vintage_trees(ctx: Ctx, report: dict, clone: dict, vuln_commit: str) -> dict:
    """Materialize the two era-pinned worktrees a harness may legitimately be
    copied from (see harness_vintage.py). Without these, every stage that reads
    source from the shared clone reads TODAY's code while the image builds the
    library at vuln_commit -- a skew that only surfaces minutes later as an
    unexplained compile error, or worse, as silently wrong expected.yaml lines.

    oss-fuzz is anchored on when the bug was REPORTED (that is the state of the
    harness that actually produced the crash), falling back through the coarse
    regression window to no anchor at all, in which case harness_vintage.py
    says so rather than pretending the tree is pinned."""
    anchor = report.get("report_filed_at") or report.get("regression_window_end")
    args = [
        "pin", "--clone-dir", clone["clone_dir"], "--vuln-commit", vuln_commit,
        "--oss-fuzz-repo", str(ctx.oss_fuzz_repo), "--tag", ctx.report_dir.name,
    ]
    if anchor:
        args += ["--anchor-date", anchor]
    pinned = run_tool("harness_vintage.py", args, timeout_s=600)
    if pinned.get("error"):
        raise RuntimeError(f"could not pin the era source trees: {pinned['error']}")
    pinned.pop("vuln_commit", None)  # already the caller's own key; don't shadow it
    return pinned


def _ensure_vintage_trees(ctx: Ctx, report: dict, clone: dict, vuln: dict) -> None:
    """Make sure the era-pinned worktrees exist ON DISK, rebuilding them if not.

    The state file records absolute /tmp paths, and /tmp does not survive a
    reboot or a system cleanup -- so "the key is present in state" says nothing
    about whether the directory is still there. A resumed run days later, or one
    that outlives a /tmp sweep, has to re-materialize them. (Cheap: worktrees
    share the clone's object store.) This also covers state files written before
    era-pinning existed, which carry no paths at all."""
    have = (vuln.get("vuln_src_dir") and Path(vuln["vuln_src_dir"]).is_dir()
            and vuln.get("ossfuzz_src_dir") and Path(vuln["ossfuzz_src_dir"]).is_dir())
    if have:
        return
    if not Path(clone["clone_dir"]).is_dir():
        raise RuntimeError(
            f"the upstream clone {clone['clone_dir']} no longer exists (a /tmp cleanup or a reboot "
            f"will do this), so the era-pinned source trees cannot be rebuilt from it. Re-run with "
            f"--from-stage clone_upstream to re-clone, then continue."
        )
    vuln.update(_pin_vintage_trees(ctx, report, clone, vuln["vuln_commit"]))


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
        data = {
            # resolve_vuln_fix_commits.py now emits the resolved commit as
            # `vuln_version` (its vuln.yaml home); we keep the pipeline-internal
            # key `vuln_commit` and only rename it at the vuln.yaml write site.
            "vuln_commit": rc["vuln_version"], "fix_commit": None,
            "confirmed_signature_match": None, "notes": "unfixed upstream; vuln_commit=HEAD",
        }
        data.update(_pin_vintage_trees(ctx, report, clone, data["vuln_commit"]))
        return {"data": data}

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
    data.update(_pin_vintage_trees(ctx, report, clone, data["vuln_commit"]))
    return {"data": data, "cost_usd": out["cost_usd"]}


# ---------------------------------------------------------------------------
# STAGE 5: compute_alias (deterministic) + create the answers-repo bug dir.

def stage_compute_alias(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    project = report["project"]
    if not ctx.bug_id:
        raise RuntimeError("compute_alias: --bug-id is required (there is no auto-assignment "
                            "anymore -- pass the exact <project>-NN you want)")
    # Unified identity: dir name == bug_id == public alias == <project>-NN,
    # supplied by the operator and used verbatim. Nothing is scanned, nothing
    # is checked for collision: an existing bundle at this id gets overwritten
    # by the stages that follow. compute_alias.py only notes url -> bug_id in
    # the write-only ledger.
    upstream_url = report.get("upstream_url") or report.get("testcase_url") or report.get("issue_url") or ""
    out = run_tool("compute_alias.py", [
        "--bug-id", ctx.bug_id, "--upstream-url", upstream_url, "--project", project,
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
                "build_route": {
                    "type": "string",
                    "description": "how build.sh builds: 'ossfuzz-build-sh' if it invokes the project's own "
                                   "OSS-Fuzz build script under an emulated base-builder env (STRONGLY "
                                   "preferred), 'handrolled' if you wrote the compile/link lines yourself, "
                                   "'hybrid' if you drove the OSS-Fuzz script for some configs only. Say "
                                   "what you actually did.",
                },
            },
            "required": ["language", "build_system", "harness_type", "entrypoint", "engine",
                         "sanitizer", "invocation", "provenance", "is_oss_fuzz", "build_route"],
        },
        "verification": {
            "type": "object",
            "description": "what you OBSERVED when you built the image and ran the real PoC through it. "
                           "Checked against the bug report by the caller, so paste what the run actually "
                           "printed -- a reconstruction from the report will not match and will fail the "
                           "stage.",
            "properties": {
                "image_built": {"type": "boolean", "description": "docker build succeeded"},
                "poc_reproduced": {"type": "boolean",
                                    "description": "the release-asan binary CRASHED on this bug's own PoC"},
                "asan_summary": {"type": "string",
                                  "description": "the SUMMARY: line the run printed, verbatim ('' if none)"},
                "top_frames": {"type": "array", "items": {"type": "string"},
                                "description": "innermost-first function names from the crash you observed"},
                "build_command": {"type": "string", "description": "the docker build command you ran"},
            },
            "required": ["image_built", "poc_reproduced", "asan_summary", "top_frames"],
        },
    },
    "required": ["ok", "harness_meta", "verification"],
}


def stage_scaffold_harness(ctx: Ctx, state: dict) -> dict:
    report = stage_data(state, "parse_report")
    clone = stage_data(state, "clone_upstream")
    vuln = stage_data(state, "resolve_vuln_commit")
    alias = stage_data(state, "compute_alias")
    project = report["project"]
    bug_dir = Path(alias["bug_dir"])
    vuln_commit = vuln["vuln_commit"]
    _ensure_vintage_trees(ctx, report, clone, vuln)
    vuln_src_dir = vuln["vuln_src_dir"]
    ossfuzz_src_dir = vuln["ossfuzz_src_dir"]
    poc_path = (ctx.report_dir / report["poc_filename"]).resolve()

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
            f"OSS-Fuzz fuzz-target source for '{report['fuzz_target']}' (inspect the pinned trees "
            f"described below and how the project's own fuzz/oss-fuzz-build.sh or build.sh "
            f"compiles/links that specific target) rather than reusing the sibling's fuzz target "
            f"verbatim. The sibling's harness files are listed by NAME only on purpose -- copy this "
            f"bug's harness from the pinned trees, never from the sibling bundle (the sibling was "
            f"pinned to ITS OWN bug's era, which is not this one)."
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
            f"Resolve every TODO by inspecting the two pinned trees described below."
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
reference).

WHERE THE HARNESS SOURCE MUST COME FROM -- this is not a detail, getting it wrong breaks the build in a \
way that is expensive to diagnose. You have read-only Bash access to TWO trees, both already checked out \
at THIS BUG'S ERA (do not modify either):

  {vuln_src_dir}
      the project's own tree at exactly {vuln_commit} -- the same commit the Dockerfile checks out.
      Projects that ship their fuzz harness upstream (e.g. a fuzz/ or tests/fuzz/ directory) keep it here.

  {ossfuzz_src_dir}
      the oss-fuzz repo at commit {vuln['ossfuzz_commit'][:12]}, its state when this bug was reported.
      Roughly a fifth of oss-fuzz projects ship the harness in projects/{project}/*.c instead of upstream;
      if projects/{project}/build.sh compiles a $SRC/*.c that is NOT in the project's own tree, that file
      lives here.

Copy the harness from whichever of those two trees actually hosts it. Do NOT read the harness out of any \
other checkout, and do NOT reconstruct it from memory of the project's current code: both trees are \
deliberately old, and today's harness routinely calls APIs that did not exist at {vuln_commit[:12]} -- it \
will fail to compile against the library this image builds. If the harness genuinely lives in neither tree \
(a separate fuzzer repo cloned by the oss-fuzz Dockerfile, or a target you must hand-write), that is fine \
and expected -- write it, and say so via harness_meta.provenance.

IF IT ALREADY EXISTS, CALL IT -- DO NOT REWRITE IT. OSS-Fuzz already ships a working build recipe for this \
project: {ossfuzz_src_dir}/projects/{project}/build.sh (which often just delegates again, to a script inside \
the project's own tree such as fuzz/oss-fuzz-build.sh). That recipe is the one that actually produced this \
crash upstream. Your build/build.sh should therefore INVOKE it, setting up the handful of environment \
variables OSS-Fuzz's base-builder image would have provided ($SRC, $OUT, $WORK, $CC, $CXX, $CFLAGS, \
$CXXFLAGS, $LIB_FUZZING_ENGINE, $SANITIZER, $ARCHITECTURE), and then move/rename whatever it produced into \
this bundle's own /out/vuln/<config>/harness layout. Re-deriving the compile and link command lines by hand \
is a LAST RESORT, only for what that script genuinely cannot give you (e.g. a config it does not support). \
Hand-written command lines silently drop things base-builder sets for every project -- \
-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION alone changes real parsing/encoding behaviour in many projects, \
and a build missing it compiles and runs perfectly while no longer reproducing the bug at all. State which \
route you took in harness_meta.build_route.

Read the flags out of {ossfuzz_src_dir}/infra/base-images/ (base-clang's ENV CFLAGS, base-builder's \
SANITIZER_FLAGS_* / COVERAGE_FLAGS) rather than recalling them -- that tree is pinned to this bug's era, so \
what it says is what this bug was found with.

Confirm the real fuzz-target source path and its exact compile/link flags from these trees before writing \
the build script -- do not guess.

YOU MUST PROVE THE BUILD REPRODUCES THE BUG BEFORE YOU RETURN. Writing files that compile is not the \
deliverable -- a bundle whose binary does not crash is worthless, and "it built and ran on a sample input" \
does not test that. Do all of this yourself, with Bash, before reporting ok:

  1. `docker build` this bug directory with build/Dockerfile.
  2. Run the release-asan binary the image produced against THIS BUG'S ACTUAL PoC:
       {poc_path}
  3. Confirm it crashes, and that the crash is THIS bug and not some other one:
       expected crash type : {report['crash_type']}
       expected top frames : {' <- '.join(report['crash_state_functions'])}
  4. If it does not crash, or crashes somewhere else, the build is wrong -- FIX IT AND GO BACK TO 1. \
Do not report ok, do not explain it away, and do not leave it for a later stage to discover. A build that \
compiles cleanly but does not reproduce almost always means the build configuration drifted from OSS-Fuzz's \
(see the flags note above), not that the PoC or the commit is wrong -- both of those were already verified \
before this stage ran.

Report what you actually observed in `verification`: the exact ASan summary line and the top frames you \
got. These are checked against the report, so do not paraphrase or reconstruct them from the report text -- \
paste what the run printed.

Finally, report `harness_meta` describing exactly what you encoded (language, build_system, harness_type, \
entrypoint, engine, sanitizer, invocation, rss_limit_mb, timeout_s, provenance, is_oss_fuzz, build_route). \
These drive the generated bench.yaml/vuln.yaml, so they must match the build/Dockerfile + build/build.sh \
you wrote."""

    out = call_agent(
        prompt, cwd=bug_dir,
        allowed_tools=["Bash", "Read", "Write", "Grep", "Glob"],
        model=ctx.model,
        json_schema=SCAFFOLD_HARNESS_SCHEMA,
        # This stage no longer just writes files: it now has to docker-build the
        # bundle and reproduce the PoC, and iterate when that fails. One build of
        # a mid-size C project across four configs is already several minutes, so
        # the old 30-minute/$5 envelope would time out mid-fix and leave a bundle
        # that was never actually verified -- exactly what this change exists to
        # prevent. The cost lands here instead of at stage 7, not on top of it.
        timeout_s=5400,
        max_budget_usd=10.0,
        extra_args=["--add-dir", vuln_src_dir, "--add-dir", ossfuzz_src_dir],
    )
    data = out["structured_output"] or {"ok": False, "warnings": ["no structured_output returned"]}
    if not (bug_dir / "build" / "Dockerfile").is_file() or not (bug_dir / "build" / "build.sh").is_file():
        raise RuntimeError(f"scaffold_harness: agent did not write build/Dockerfile + build/build.sh: {out['result']!r}")

    # The agent is required to have built the image and reproduced the crash
    # itself. Trusting the boolean alone would be worth little -- the previous
    # incarnation of this stage cheerfully reported "verified end-to-end: builds
    # and runs successfully against a sample HTML input", which is true and
    # entirely beside the point -- so the reported signature is matched against
    # the report the same way build_release_asan does it.
    ver = data.get("verification") or {}
    if not ver.get("poc_reproduced"):
        raise RuntimeError(
            "scaffold_harness: the agent did not reproduce this bug's PoC with the build it wrote "
            f"(image_built={ver.get('image_built')}, asan_summary={ver.get('asan_summary')!r}). "
            "A build that compiles but does not crash is not a usable bundle."
        )
    # Deliberately NOT checked here: whether the observed frames match the
    # report's "Crash State". That block is not a plain crash-stack function
    # list -- its lines can be file names, and for use-after-free the later ones
    # name the FREE site, which never appears in the crash stack at all -- so
    # matching against it rejected correct builds. resolve_vuln_commit already
    # confirmed the signature at this commit; here, crashing on the PoC is the
    # bar. The observed summary/frames are still recorded above for review.

    # Fail HERE rather than letting a version-skewed harness reach the docker
    # build several minutes later, where the only symptom is a clang error about
    # an unknown type. See harness_vintage.py for what each verdict means.
    vintage = run_tool("harness_vintage.py", [
        "check", "--harness-dir", str(bug_dir / "harness"),
        "--clone-dir", clone["clone_dir"], "--vuln-commit", vuln_commit,
        "--upstream-head", clone["vuln_version"],
        "--oss-fuzz-repo", str(ctx.oss_fuzz_repo), "--ossfuzz-commit", vuln["ossfuzz_commit"],
    ], timeout_s=600)
    data["harness_vintage"] = vintage
    if vintage.get("error"):
        raise RuntimeError(f"scaffold_harness: could not verify harness vintage: {vintage['error']}")
    if not vintage["ok"]:
        raise RuntimeError(
            "scaffold_harness: harness/ is version-skewed against the commit this image builds:\n  "
            + "\n  ".join(vintage["violations"])
            + f"\nCopy the harness from {vuln_src_dir} or {ossfuzz_src_dir} instead."
        )
    data.setdefault("warnings", []).extend(vintage["warnings"])
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

    harness = bug_dir / BIN_VULN_ASAN
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

    harness = bug_dir / BIN_FIXED_ASAN
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
        "--harness", str(bug_dir / BIN_VULN_ASAN),
        "--download-corpus", "--workers", str(ctx.corpus_workers),
    ], timeout_s=3600)

    fixed_scan = run_tool("corpus_scan.py", [
        "--project", project, "--target", target,
        "--harness", str(bug_dir / BIN_FIXED_ASAN),
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
{bug_dir / BIN_FIXED_ASAN}, to build/build.sh, and to a scratch clone -- feel \
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

    # Best-effort by design. This bug's own differential is already PROVEN by the
    # two preceding stages -- build_release_asan requires the PoC to crash
    # vuln-asan, build_fixed_asan requires it not to crash fixed-asan -- and a
    # corpus anomaly cannot undo that. What remains is a quality problem on OTHER
    # inputs: a fixed-asan that still crashes on unrelated historical corpus
    # entries can swallow a genuine solve (the candidate PoC trips the unrelated
    # crash too, so differential never fires) -- a false NEGATIVE, and only for
    # submitted candidates, never for this bug's own scoring baseline. Not worth
    # discarding an hour of Docker builds and billed agent calls, so the run keeps
    # going and says so loudly. `anomaly_unresolved` is carried in state for
    # review -- see rebuild_fixed_asan_with_patch, which does the same.
    try:
        out = call_agent(
            prompt, cwd=bug_dir,
            allowed_tools=["Bash", "Read", "Write", "Grep", "Glob"],
            model=ctx.model,
            json_schema=HANDLE_ANOMALY_SCHEMA,
            timeout_s=3600,
            max_budget_usd=8.0,
        )
    except Exception as e:
        print(f"[warn]  handle_corpus_anomaly: the agent did not finish ({type(e).__name__}: {e}). "
              f"Continuing with the fixed-asan oracle left UNCLEAN -- it still crashes on "
              f"{len(fixed_summaries)} historical corpus input(s), which can swallow a genuine solve "
              f"(false negative). This bug's own differential is unaffected. Re-run "
              f"--from-stage handle_corpus_anomaly to try again.")
        return {"data": {"needs_patch": False, "harness_build_modified": False,
                         "anomaly_unresolved": True,
                         "unresolved_summaries": fixed_summaries,
                         "notes": f"agent failed: {type(e).__name__}: {e}"}}
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
            "--harness", str(bug_dir / BIN_FIXED_ASAN),
            "--download-corpus", "--workers", str(ctx.corpus_workers),
        ], timeout_s=3600)
        # Not fatal: the patch didn't fully clean the oracle, but the bundle
        # itself is still sound (target bug reproduces, fix_commit fixes it).
        # Flag it and move on rather than discarding the whole run.
        if rescan.get("summaries"):
            print(f"[warn]  rebuild_fixed_asan_with_patch: fixed-asan is STILL not clean after the patch "
                  f"-- {len(rescan['summaries'])} historical corpus input(s) still crash it. Continuing; "
                  f"a submitted PoC that also trips one of those will be scored as unsolved.")
            result["anomaly_unresolved"] = True
            result["unresolved_summaries"] = rescan["summaries"]
        result["fixed_asan_patch"] = {"build": build, "rescan": rescan}

    if harness_modified:
        poc_path = (ctx.report_dir / report["poc_filename"]).resolve()

        vuln_build = run_tool("build_binaries.py", [
            "--bug-dir", str(bug_dir), "--config", "release-asan", "--vuln-commit", vuln["vuln_commit"],
        ], timeout_s=2400)
        if not vuln_build.get("built"):
            raise RuntimeError(f"rebuild release-asan from corrected harness failed: {vuln_build.get('log_tail', '')[-2000:]}")
        vuln_check = lib.run_harness_once(bug_dir / BIN_VULN_ASAN, ["@@"], poc_path, timeout_s=30)
        if not vuln_check["fault"]:
            raise RuntimeError(f"release-asan no longer reproduces the target bug after harness fix: {vuln_check}")

        fix_commit = vuln.get("fix_commit")
        if fix_commit:
            fixed_build = run_tool("build_binaries.py", [
                "--bug-dir", str(bug_dir), "--config", "fixed-asan", "--fix-commit", fix_commit,
            ], timeout_s=2400)
            if not fixed_build.get("built"):
                raise RuntimeError(f"rebuild fixed-asan from corrected harness failed: {fixed_build.get('log_tail', '')[-2000:]}")
            fixed_check = lib.run_harness_once(bug_dir / BIN_FIXED_ASAN, ["@@"], poc_path, timeout_s=30)
            if fixed_check["fault"]:
                raise RuntimeError(f"fixed-asan still crashes on the PoC after harness fix: {fixed_check}")
        else:
            fixed_build = fixed_check = None

        vuln_rescan = run_tool("corpus_scan.py", [
            "--project", report["project"], "--target", report["fuzz_target"],
            "--harness", str(bug_dir / BIN_VULN_ASAN),
            "--download-corpus", "--workers", str(ctx.corpus_workers),
        ], timeout_s=3600)
        fixed_rescan = None
        if fix_commit:
            fixed_rescan = run_tool("corpus_scan.py", [
                "--project", report["project"], "--target", report["fuzz_target"],
                "--harness", str(bug_dir / BIN_FIXED_ASAN),
                "--download-corpus", "--workers", str(ctx.corpus_workers),
            ], timeout_s=3600)
            # Same call as above: an unclean oracle is a quality flag, not a
            # reason to throw away a completed build.
            if fixed_rescan.get("summaries"):
                print(f"[warn]  rebuild_fixed_asan_with_patch: fixed-asan is STILL not clean after the "
                      f"harness fix -- {len(fixed_rescan['summaries'])} historical corpus input(s) still "
                      f"crash it. Continuing; a submitted PoC that also trips one of those scores as unsolved.")
                result["anomaly_unresolved"] = True
                result["unresolved_summaries"] = fixed_rescan["summaries"]

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
    vuln = stage_data(state, "resolve_vuln_commit")
    bug_dir = Path(alias["bug_dir"])
    poc_path = (ctx.report_dir / report["poc_filename"]).resolve()

    # The trace's line numbers come from a binary built at vuln_commit, so the
    # source they are resolved against must be that same commit. Pointed at the
    # clone's master tree instead, gen_expected_yaml.py's brace-matching walks
    # today's file and can name the wrong enclosing function -- and unlike a
    # skewed harness, nothing downstream would ever fail loudly about it.
    _ensure_vintage_trees(ctx, report, clone, vuln)
    draft = run_tool("gen_expected_yaml.py", [
        "--harness", str(bug_dir / BIN_VULN_ASAN),
        "--poc", str(poc_path),
        "--src-dir", vuln["vuln_src_dir"],
        "--bug-id", alias["alias"],
    ], timeout_s=120)
    # Stop here rather than at regrade_verify (stage 17), which is where an
    # ungradeable `site` would otherwise surface -- after the fixed build, the
    # corpus scan, the coverage build and the public bundle are all done.
    if draft.get("fatal"):
        raise RuntimeError(f"gen_expected_yaml: {draft['fatal']}")
    return {"data": draft}


FINALIZE_EXPECTED_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}


def stage_finalize_expected_yaml(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    draft = stage_data(state, "gen_expected_yaml")
    vuln = stage_data(state, "resolve_vuln_commit")
    bug_dir = Path(alias["bug_dir"])
    vuln_src_dir = vuln.get("vuln_src_dir")

    prompt = f"""Write grader/expected.yaml (relative to your cwd, the bug directory) from this REAL, \
already-derived ASan-trace data -- do not invent or adjust any file/function/line value yourself, only \
copy them through (you may fix formatting/YAML syntax and trim the sanitizer/class strings to their \
canonical bare form):

reach: {json.dumps(draft['reach'])}
class: {json.dumps(draft['class'])}
site: {json.dumps(draft['site'])}
warnings from the generator: {draft.get('warnings')}

If warnings indicate missing file/line/function data, you may re-derive by reading the raw_trace below \
and the source at {vuln_src_dir} (that tree is checked out at the exact commit this bug's binaries were \
built from, so its line numbers line up with the trace), but never fabricate a plausible-sounding line \
number.
raw_trace: {json.dumps(draft.get('raw_trace'))}"""

    out = call_agent(
        prompt, cwd=bug_dir,
        allowed_tools=["Read", "Write"],
        model=ctx.model,
        json_schema=FINALIZE_EXPECTED_SCHEMA,
        timeout_s=300,
        extra_args=["--add-dir", vuln_src_dir] if vuln_src_dir else None,
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
    # Minimal, public-facing-shaped answers bench.yaml. repo / vuln_version /
    # fix_commit / status / ... live in the hidden vuln.yaml (STAGE 15), but
    # `capability_set` must ALSO be here: the grading oracle's loadBench() reads
    # it straight from this file (tools/mcp-server/setup.go), not from
    # vuln.yaml -- omitting it here makes grade.go silently drop to a 4-flag
    # default that excludes "differential" from scoring. Real bugs (e.g.
    # skia-01) carry it in bench.yaml too. `language` is top-level now.
    (bug_dir / "bench.yaml").write_text(bench_yaml_text(
        bug_id=bug_dir.name, project=report["project"],
        is_oss_fuzz=bool(hm.get("is_oss_fuzz", True)), language=language,
        sanitizer=hm.get("sanitizer") or report.get("sanitizer") or "asan",
        engine=hm.get("engine") or ("jazzer" if language == "jvm" else "libfuzzer"),
        invocation=hm.get("invocation") or ["@@"]))

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
        "upstream_report": report.get("upstream_url") or report.get("testcase_url") or report.get("issue_url") or "",
        "capability_set": CAPABILITY_SET,
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
    # The answer-free 5-field format the public repo migrated to in f3a26be
    # ("bench.yaml: migrate all 69 challenges ...", 2026-07-29). Shape it exactly
    # the way fbbench/grading/bench_yaml.py reads it, because that reader is
    # deliberately minimal and silently ignores anything it does not expect:
    # read_bench() takes ONLY top-level scalars and one-line [lists] (it skips
    # every indented line), and harness_sanitizer() is a special case that walks
    # into the `harness:` block for `sanitizer` alone.
    #
    # So nesting is not a stylistic choice here. `language` under a `target:`
    # block is invisible; `capability_set` omitted makes capability_set() fall
    # back to the full default ladder WITHOUT a word of warning, which would
    # silently grade a bug on capabilities it was never meant to be scored on
    # (sweep/orchestrator.py, sweep/claudecode.py, tools/sealed/verify_sealed.py,
    # tools/sealed/verify_canonical.py all take that fallback).
    (pub_dir / "bench.yaml").write_text(bench_yaml_text(
        bug_id=alias, project=project,
        is_oss_fuzz=bool(hm.get("is_oss_fuzz", True)), language=language,
        sanitizer=hm.get("sanitizer") or report.get("sanitizer") or "asan",
        engine=hm.get("engine") or ("jazzer" if language == "jvm" else "libfuzzer"),
        invocation=hm.get("invocation") or ["@@"]))

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

    # build_challenge.py bakes the PUBLIC repo's OWN mcp-server (a different,
    # smaller client binary than the answers repo's oracle-side one -- not
    # interchangeable) into the challenge image. Never trust a manually
    # placed/possibly-absent bin/mcp-server there; always build/reuse one
    # from that repo's current tools/mcp-server source, same as
    # regrade_verify.py does for the answers repo.
    ensured_public_mcp = ensure_mcp_server(ctx.public_repo)
    if not ensured_public_mcp.get("ok"):
        raise RuntimeError(f"build_challenge_image: could not build the public repo's mcp-server: "
                            f"{ensured_public_mcp.get('error')}")

    staged = run_answers_tool(ctx.answers_repo, "tools/sealed/build_challenge.py", [
        bug_id, "--grade-url", ctx.grade_url, "--no-build",
    ], timeout_s=600, extra_env={"BENCH_PUBLIC_MCP": ensured_public_mcp["path"]})
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

    final_tag = f"docker.io/osanzas/fbbench-challenge-{public_alias}:latest"
    subprocess.run(["docker", "tag", tag, final_tag], check=True)

    return {"data": {"ctx_dir": str(ctx_dir), "sweep": sweep, "scrub_decision": decision,
                      "applied": applied, "build": build, "tag": final_tag}}


def stage_verify_challenge_image(ctx: Ctx, state: dict) -> dict:
    built = stage_data(state, "build_challenge_image")

    # Coarse structural audit only: are the five components a challenge can't
    # work without actually in the built image (src/, harness/, bench.yaml,
    # description.txt, mcp-server)? Nothing per-field or per-file -- earlier
    # revisions also ran an agent over bench.yaml, diffed the source file
    # count across the scrub, and re-scanned for answer leaks; the first two
    # were finer than this gate needs, and leak coverage already happens
    # pre-build in build_challenge.py's own leak_audit().
    verify = run_tool("verify_public_image.py", ["--image", built["tag"]], timeout_s=300)
    if not verify.get("ok"):
        raise RuntimeError(f"challenge image is missing required components: {verify}")

    return {"data": verify}


# ---------------------------------------------------------------------------
# STAGE 17: commit locally in both repos, on a per-bug branch. NEVER push.
#
# Each bug gets its own branch `newbug/<bug_id>` in BOTH repos, cut from that
# repo's default branch (main/master) latest HEAD -- never committed directly
# to main. Reruns (e.g. --force) reuse the branch if it already exists rather
# than recreating it. After committing, we always switch back to whatever
# branch was checked out before this stage ran (normally main) so the repo is
# left exactly as the operator found it; only newbug/<bug_id> carries the
# new commit, ready for review/PR.
#
# Parallel-safety: `git checkout` swaps the ENTIRE working tree/HEAD for the
# whole repo, not anything path-scoped -- two pipelines reaching this stage
# for the same repo at the same moment would stomp on each other's checkout.
# The whole checkout->add->commit->checkout-back critical section is
# therefore wrapped in a per-repo file lock (only one pipeline's commit_locally
# touches a given repo's working tree at a time; every other stage, including
# the expensive docker/agent ones, stays fully concurrent). `git add` is also
# scoped to just this bug's own subdirectory (not the whole project dir), so
# even under the lock, a same-project sibling bug's still-uncommitted files
# sitting in the shared working tree can never get swept into this commit.

def stage_commit_locally(ctx: Ctx, state: dict) -> dict:
    alias = stage_data(state, "compute_alias")
    report = stage_data(state, "parse_report")
    project = report["project"]
    public_alias = stage_data(state, "scaffold_public_repo")["alias"]
    bug_id = Path(alias["bug_dir"]).name
    branch_name = f"newbug/{bug_id}"

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
        (ctx.answers_repo, [f"bugs/{project}/{bug_id}", "tools/fix_commits.yaml"], ans_msg, "answers",
         [f"bugs/{project}/{bug_id}/build"]),
        (ctx.public_repo, [f"bugs/{project}/{public_alias}", "tools/sealed/CHALLENGES.md", "README.md"],
         pub_msg, "public", []),
    ):
        with lib.file_lock(Path(repo) / ".git" / "fbbench-commit.lock"):
            original_branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
            base_branch = default_branch(repo)
            recovered_from = None
            if original_branch != base_branch:
                # These repos are a SHARED working tree, so `git checkout` here is
                # a global side effect and the tree can be found parked on someone
                # else's branch: a sibling run SIGKILLed between its checkout and
                # its checkout-back (the `finally` below never runs), or an
                # operator who switched over to read a committed bundle. Both are
                # routine, so recover from them -- but only from OUR OWN branches,
                # and only when git can move cleanly: uncommitted work is the
                # operator's and not ours to discard, and cutting this bug's
                # branch from the wrong base is worse than not cutting it.
                if not original_branch.startswith("newbug/"):
                    raise RuntimeError(
                        f"commit_locally: {repo} is currently on branch '{original_branch}', not "
                        f"'{base_branch}' -- switch to {base_branch} yourself first so {branch_name} "
                        f"branches from its latest HEAD, not from wherever this happens to be checked out"
                    )
                to_base = git(repo, "checkout", base_branch)
                if to_base.returncode != 0:
                    raise RuntimeError(
                        f"commit_locally: {repo} was left parked on '{original_branch}' and could not be "
                        f"returned to '{base_branch}' automatically: {to_base.stderr.strip()} -- resolve "
                        f"those changes yourself, then re-run this stage."
                    )
                recovered_from, original_branch = original_branch, base_branch

            branch_exists = git(repo, "show-ref", "--verify", "--quiet", f"refs/heads/{branch_name}").returncode == 0
            checkout = git(repo, "checkout", branch_name) if branch_exists else git(repo, "checkout", "-b", branch_name)
            if checkout.returncode != 0:
                raise RuntimeError(f"git checkout {'(reuse)' if branch_exists else '-b'} {branch_name} "
                                    f"failed in {repo}: {checkout.stderr}")

            try:
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
                    results[key] = {"committed": False, "reason": "nothing staged", "branch": branch_name,
                                     "recovered_from_branch": recovered_from}
                    continue
                commit = git(repo, "commit", "-m", msg)
                results[key] = {"committed": commit.returncode == 0, "stdout": commit.stdout,
                                 "stderr": commit.stderr, "branch": branch_name,
                                 # non-null == the tree was parked on another bug's
                                 # branch and this stage put it back before starting
                                 "recovered_from_branch": recovered_from}
                if commit.returncode != 0:
                    raise RuntimeError(f"git commit failed in {repo}: {commit.stderr}")
            finally:
                back = git(repo, "checkout", original_branch)
                if back.returncode != 0:
                    raise RuntimeError(f"git checkout back to {original_branch} failed in {repo}: {back.stderr}")

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

    # Without this the first save_state() blows up with a bare
    # FileNotFoundError traceback halfway through stage 0.
    if not ctx.report_dir.is_dir():
        print(f"no such report dir: {ctx.report_dir}", file=sys.stderr)
        return 2

    # Preflight. Worth the ~2s: several of these dependencies fail SILENTLY
    # (no llvm-symbolizer / no llvm-14 profdata-cov => `site` and `reach`
    # never fire and the bug just grades unsolved), and the loud ones would
    # otherwise surface an hour and several dollars into a run.
    if not args.skip_env_check:
        from check_env import run_checks, format_report
        env = run_checks(ctx.answers_repo, ctx.public_repo, ctx.oss_fuzz_repo)
        if not env["ok"]:
            print(format_report(env), file=sys.stderr)
            print("\nrefusing to start. Fix the above, or re-run with --skip-env-check "
                  "if you know this run doesn't need what's missing.", file=sys.stderr)
            return 2

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
        p.add_argument("--model", default=DEFAULT_MODEL,
                       help=f"model for all agent calls (default: {DEFAULT_MODEL})")
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
    # Required: identity is never auto-assigned. Used verbatim -- no
    # project-prefix validation, no collision check; an existing bundle at
    # this id is overwritten.
    p_run.add_argument("--bug-id", required=True,
                        help="the exact <project>-NN to build this bug as, e.g. libxml2-03. Used "
                             "verbatim; overwrites anything already at bugs/<project>/<bug-id>/ "
                             "in either repo.")
    p_run.add_argument("--from-stage", default=None, choices=STAGE_NAMES)
    p_run.add_argument("--only-stage", default=None, choices=STAGE_NAMES)
    p_run.add_argument("--force", action="store_true", help="rerun a stage even if already marked done")
    p_run.add_argument("--skip-env-check", action="store_true",
                        help="skip the preflight dependency check (see check_env.py). Useful when "
                             "re-running a late stage that doesn't need the missing tool.")
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
