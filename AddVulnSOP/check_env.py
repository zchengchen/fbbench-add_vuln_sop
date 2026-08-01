#!/usr/bin/env python3
"""Preflight check for everything an onboarding run needs.

Two tiers:

  REQUIRED -- the run is blocked without it. This covers both the loud
    dependencies (no git/docker/claude/curl and stage 1 dies immediately) AND
    the quiet ones, which matter more: without llvm-symbolizer the ASan
    backtrace carries no file:line, so `site` and `reach` simply never fire;
    without the llvm-14-matched profdata/cov the coverage profile fails to
    merge and `reach` never fires. Neither prints an error -- you just get a
    bug that grades as unsolved for no visible reason, hours in. Cheap to
    check up front, expensive to debug later.

  ADVISORY -- reported, never blocks: things that only bite some runs
    (a dirty repo working tree, low disk, Flask for the webapp).

Probes RUN each tool rather than just `which`-ing it. llvm-profdata-14 in
particular is typically a wrapper script that exports LD_LIBRARY_PATH before
exec'ing the real binary (that's what ensure_llvm14.py installs) -- `which`
finds the wrapper even when the binary underneath is gone. It also rejects
`--version` outright ("Unknown command!"), so the probe uses a subcommand.

Usage:
    check_env.py [--json] [--answers-repo P] [--public-repo P] [--oss-fuzz-repo P]
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

import onboarding_lib as lib

REQUIRED = "required"
ADVISORY = "advisory"


def _probe(cmd: list[str], timeout: int = 20) -> tuple[bool, str]:
    """Run cmd; True if it executed and exited 0."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, "not found on PATH"
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    except OSError as e:
        return False, str(e)
    if p.returncode != 0:
        tail = (p.stderr or p.stdout or "").strip().splitlines()
        return False, _clip(tail[-1] if tail else f"exit {p.returncode}")
    first = (p.stdout or p.stderr or "").strip().splitlines()
    return True, _clip(first[0] if first else "ok")


def _clip(s: str, n: int = 60) -> str:
    """Version banners can be a full paragraph (curl lists every library it
    links); the report only needs enough to identify the build."""
    s = s.strip()
    return s if len(s) <= n else s[:n - 1] + "…"


def _result(name, level, ok, detail, remedy=None, why=None) -> dict:
    return {"name": name, "level": level, "ok": ok, "detail": detail,
            "remedy": remedy, "why": why}


def _check_tool(name, cmd, level, why, remedy) -> dict:
    where = shutil.which(cmd[0])
    ok, detail = _probe(cmd)
    if ok and where:
        detail = f"{where} — {detail}"
    return _result(name, level, ok, detail, remedy, why)


def run_checks(answers_repo: Path, public_repo: Path, oss_fuzz_repo: Path) -> dict:
    checks: list[dict] = []

    # -- python packages ----------------------------------------------------
    try:
        import yaml  # noqa: F401
        checks.append(_result("PyYAML", REQUIRED, True, "importable"))
    except ImportError as e:
        checks.append(_result("PyYAML", REQUIRED, False, str(e),
                               "pip install -r requirements.txt",
                               "every stage reads/writes yaml"))

    # -- loud external tools ------------------------------------------------
    checks.append(_check_tool(
        "git", ["git", "--version"], REQUIRED,
        "stage 1 clones upstream; stage 20 commits both repos",
        "apt install git"))
    checks.append(_check_tool(
        "curl", ["curl", "--version"], REQUIRED,
        "stage 8 downloads the ClusterFuzz corpus",
        "apt install curl"))
    checks.append(_check_tool(
        "docker", ["docker", "--version"], REQUIRED,
        "every build stage, the image audit, and the llvm-14/mcp-server helpers",
        "install Docker"))
    checks.append(_check_tool(
        "docker daemon", ["docker", "info", "--format", "{{.ServerVersion}}"], REQUIRED,
        "the CLI alone is not enough -- builds need a reachable daemon",
        "start Docker, and make sure this user is in the `docker` group"))
    checks.append(_check_tool(
        "claude CLI", ["claude", "--version"], REQUIRED,
        "the 8 agent-driven stages (parse_report, find_fix_commit, scaffold_harness, …)",
        "install the claude CLI and log in (`claude` once, interactively)"))

    # -- quiet ones: these fail by producing a wrong RESULT, not an error ----
    checks.append(_check_tool(
        "llvm-symbolizer", ["llvm-symbolizer", "--version"], REQUIRED,
        "symbolizes ASan frames. Missing -> frames have no file:line -> `site` and "
        "`reach` silently never fire and the bug grades unsolved",
        "apt install llvm  (or point ASAN_SYMBOLIZER_PATH at one)"))
    # NOT --version: llvm-profdata rejects it outright ("Unknown command!").
    checks.append(_check_tool(
        "llvm-profdata-14", ["llvm-profdata-14", "show", "--help"], REQUIRED,
        "merges the coverage profile for `reach`. The coverage binaries are built "
        "with clang-14 (profile format v8); a newer host llvm cannot read them and "
        "`reach` silently never fires",
        "python3 AddVulnSOP/ensure_llvm14.py   (extracts llvm-14 via docker)"))
    checks.append(_check_tool(
        "llvm-cov-14", ["llvm-cov-14", "--version"], REQUIRED,
        "exports the merged profile for `reach` -- same clang-14 ABI constraint",
        "python3 AddVulnSOP/ensure_llvm14.py"))

    # -- workspace ----------------------------------------------------------
    for label, path, extra in (
        ("answers repo", answers_repo, None),
        ("public repo", public_repo, None),
        ("oss-fuzz repo", oss_fuzz_repo, "projects"),
    ):
        ok = path.is_dir() and (extra is None or (path / extra).is_dir())
        checks.append(_result(
            label, REQUIRED, ok,
            str(path) + ("" if ok else "  (missing)"),
            "clone it next to this repo, or pass --answers-repo/--public-repo/--oss-fuzz-repo",
            "resolved by walking up for the dir holding both bench repos"))

    # -- advisory -----------------------------------------------------------
    # dpkg-deb only matters as the REMEDY path for llvm-14; if the llvm-14
    # tools already work, its absence is irrelevant, so don't block on it.
    llvm14_ok = all(c["ok"] for c in checks if c["name"] in ("llvm-profdata-14", "llvm-cov-14"))
    checks.append(_check_tool(
        "dpkg-deb", ["dpkg-deb", "--version"], ADVISORY if llvm14_ok else REQUIRED,
        "only used by ensure_llvm14.py to unpack the llvm-14 debs"
        + (" — not needed, llvm-14 already works" if llvm14_ok else ""),
        "apt install dpkg  (or install llvm-14 by hand)"))

    for label, repo in (("answers repo", answers_repo), ("public repo", public_repo)):
        if not (repo / ".git").is_dir():
            continue
        branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo,
                                 capture_output=True, text=True).stdout.strip()
        porcelain = subprocess.run(["git", "status", "--porcelain"], cwd=repo,
                                    capture_output=True, text=True).stdout.splitlines()
        # Untracked paths under bugs/ are this tool's own output: a bug's files
        # get committed on its newbug/<id> branch, so on main they read as
        # untracked. Expected, not a problem. MODIFIED TRACKED files are the
        # ones that could get swept into a bug's commit by mistake.
        modified = [ln for ln in porcelain if not ln.startswith("??")]
        untracked = [ln for ln in porcelain if ln.startswith("??")]
        on_main = branch in ("main", "master")
        bits = [f"on `{branch}`"]
        if modified:
            bits.append(f"{len(modified)} modified tracked file(s)")
        if untracked:
            bits.append(f"{len(untracked)} untracked path(s) — normal for per-bug output")
        if not modified and not untracked:
            bits.append("clean")
        checks.append(_result(
            f"{label} tree", ADVISORY, on_main and not modified, ", ".join(bits),
            "switch back to main / commit or stash tracked edits",
            "stage 20 refuses to branch from anything but the default branch, and "
            "tracked edits sitting here can end up in a bug's commit"))

    try:
        free_gb = shutil.disk_usage(str(answers_repo)).free / 2**30
        checks.append(_result("disk space", ADVISORY, free_gb >= 40,
                               f"{free_gb:.0f} GB free",
                               "free up space", "a run pulls sources and builds several ASan/coverage images"))
    except OSError as e:
        checks.append(_result("disk space", ADVISORY, False, str(e)))

    try:
        import flask  # noqa: F401
        checks.append(_result("Flask", ADVISORY, True, "importable (webapp only)"))
    except ImportError:
        checks.append(_result("Flask", ADVISORY, False, "not installed",
                               "pip install -r requirements.txt", "only the webapp needs it"))

    blocking = [c for c in checks if c["level"] == REQUIRED and not c["ok"]]
    return {"ok": not blocking, "checks": checks,
            "blocking": [c["name"] for c in blocking]}


def format_report(res: dict) -> str:
    lines = []
    for level, title in ((REQUIRED, "required"), (ADVISORY, "advisory")):
        group = [c for c in res["checks"] if c["level"] == level]
        if not group:
            continue
        lines.append(f"\n{title}:")
        for c in group:
            mark = "OK  " if c["ok"] else ("FAIL" if level == REQUIRED else "warn")
            lines.append(f"  [{mark}] {c['name']:<18} {c['detail']}")
            if not c["ok"]:
                if c.get("why"):
                    lines.append(f"           why:  {c['why']}")
                if c.get("remedy"):
                    lines.append(f"           fix:  {c['remedy']}")
    lines.append("")
    lines.append("environment OK" if res["ok"]
                 else f"MISSING: {', '.join(res['blocking'])}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="emit JSON as the last stdout line")
    ap.add_argument("--answers-repo", default=None)
    ap.add_argument("--public-repo", default=None)
    ap.add_argument("--oss-fuzz-repo", default=None)
    args = ap.parse_args()

    paths = lib.find_repo_paths(answers_repo=args.answers_repo, public_repo=args.public_repo,
                                 oss_fuzz_repo=args.oss_fuzz_repo)
    res = run_checks(paths.answers, paths.public, paths.oss_fuzz)

    if args.json:
        lib.emit(res)
    else:
        print(format_report(res))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
