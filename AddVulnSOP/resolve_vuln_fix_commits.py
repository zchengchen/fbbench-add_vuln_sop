#!/usr/bin/env python3
"""Resolve repo_url + ensure a full clone + resolve fix_commit's date.

Deliberately does NOT compute vuln_commit when a fix_commit is given -- an
earlier version of this script assumed vuln_commit = fix_commit's immediate
git parent, which is unsafe: OSS-Fuzz's "Fixed commit: A:B" line is a coarse
periodic-build bisection checkpoint, not necessarily adjacent git commits.
Real example that broke this assumption: report said "Fixed commit:
149c04c0:f1e1f13b", but f1e1f13b's actual parent (152fbb60) doesn't reproduce
the bug at all -- the real vuln_commit (00314882) sits THREE commits earlier,
because two unrelated commits (149c04c0, 152fbb60) happened to land in
between the real regression and the eventual fix.

Picking vuln_commit is instead done by an agent, primarily from the report's
regression time window (`git log --before=<timestamp> -1`-style reasoning),
NOT from fix_commit's git-graph position and NOT from keyword/commit-message
search. This script only does the boring, deterministic prep work so that
agent doesn't have to: resolve repo_url, get a full (non-shallow) local
clone ready, and confirm fix_commit exists (with its date, as a sanity
anchor the agent can compare candidate vuln_commit dates against).

  - fix_commit given -> {branch: "clean_fix", fix_commit, fix_commit_date,
    vuln_commit: null (caller must resolve this), clone_dir, repo_url}
  - no fix_commit given -> presumed unfixed upstream -> {branch: "unfixed",
    vuln_commit: <HEAD>, fix_commit: null, ...} (HEAD is unambiguous, no
    time-inference needed for this branch)

Usage:
    python3 resolve_vuln_fix_commits.py --project libxml2 \
        --oss-fuzz-repo <path> [--fix-commit <sha>] [--clone-dir <path>]
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

import onboarding_lib


def _run(cmd, cwd=None, timeout_s=1800):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout_s)
    return p.returncode, p.stdout, p.stderr


def _default_clone_dir(repo_url: str) -> Path:
    name = re.sub(r"\.git$", "", (repo_url or "").rstrip("/").split("/")[-1]) or "repo"
    return Path("/tmp") / f"fbbench-src-{name}"


def resolve_repo_url(oss_fuzz_repo: Path, project: str) -> str:
    """oss-fuzz project.yaml conventionally names the upstream repo in
    `main_repo:` -- deterministic, no need to ask an agent to guess it."""
    project_yaml = oss_fuzz_repo / "projects" / project / "project.yaml"
    if not project_yaml.is_file():
        raise RuntimeError(f"no project.yaml at {project_yaml}")
    data = onboarding_lib.read_yaml(project_yaml)
    repo_url = data.get("main_repo")
    if not repo_url:
        raise RuntimeError(f"project.yaml at {project_yaml} has no main_repo field")
    return repo_url


def ensure_full_clone(repo_url: str, clone_dir: Path) -> dict:
    """Full clone (no --depth), or fetch-update if already cloned."""
    if (clone_dir / ".git").is_dir():
        rc, out, err = _run(["git", "fetch", "--all", "-q"], cwd=str(clone_dir), timeout_s=600)
        return {"reused": True, "fetch_ok": rc == 0, "fetch_stderr": err[-500:] if rc != 0 else ""}
    clone_dir.parent.mkdir(parents=True, exist_ok=True)
    rc, out, err = _run(["git", "clone", repo_url, str(clone_dir)], timeout_s=1800)
    if rc != 0:
        raise RuntimeError(f"git clone {repo_url} -> {clone_dir} failed (rc={rc}): {err[-1500:]}")
    return {"reused": False, "fetch_ok": True, "fetch_stderr": ""}


def commit_date(clone_dir: Path, sha: str) -> str | None:
    rc, out, err = _run(["git", "show", "-s", "--format=%aI", sha], cwd=str(clone_dir))
    return out.strip() if rc == 0 else None


def resolve(repo_url: str, fix_commit: str | None, clone_dir: Path) -> dict:
    clone_info = ensure_full_clone(repo_url, clone_dir)

    if fix_commit:
        rc, out, err = _run(["git", "cat-file", "-e", fix_commit], cwd=str(clone_dir))
        if rc != 0:
            raise RuntimeError(f"fix_commit {fix_commit!r} does not exist in {repo_url} (checked at {clone_dir}): {err.strip()}")
        return {
            "branch": "clean_fix",
            "vuln_commit": None,  # caller (agent, time-based) must resolve this
            "fix_commit": fix_commit,
            "fix_commit_date": commit_date(clone_dir, fix_commit),
            "clone_dir": str(clone_dir),
            "clone_info": clone_info,
        }

    # No fix commit named anywhere -- presumed still unfixed upstream. HEAD
    # is unambiguous, no time-inference needed for this branch.
    rc, out, err = _run(["git", "rev-parse", "origin/HEAD"], cwd=str(clone_dir))
    if rc != 0 or not out.strip():
        rc, out, err = _run(["git", "rev-parse", "HEAD"], cwd=str(clone_dir))
        if rc != 0 or not out.strip():
            raise RuntimeError(f"could not resolve HEAD in {clone_dir}: {err.strip()}")
    head_sha = out.strip()
    return {
        "branch": "unfixed",
        "vuln_commit": head_sha,
        "fix_commit": None,
        "fix_commit_date": None,
        "vuln_commit_date": commit_date(clone_dir, head_sha),
        "clone_dir": str(clone_dir),
        "clone_info": clone_info,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-url", default=None,
                     help="explicit upstream repo git URL; if omitted, resolved from "
                          "--oss-fuzz-repo/projects/--project/project.yaml's main_repo field")
    ap.add_argument("--project", default=None, help="oss-fuzz project name, used to auto-resolve --repo-url")
    ap.add_argument("--oss-fuzz-repo", default=None)
    ap.add_argument("--fix-commit", default=None, help="omit entirely if the report names no fix commit")
    ap.add_argument("--clone-dir", default=None)
    args = ap.parse_args()

    repo_url = args.repo_url
    if not repo_url:
        if not args.project:
            onboarding_lib.emit({"error": "must give either --repo-url or --project (to auto-resolve from project.yaml)"})
            return 2
        oss_fuzz_repo = Path(args.oss_fuzz_repo).resolve() if args.oss_fuzz_repo else onboarding_lib.find_repo_paths().oss_fuzz
        try:
            repo_url = resolve_repo_url(oss_fuzz_repo, args.project)
        except Exception as e:
            onboarding_lib.emit({"error": str(e)})
            return 1

    clone_dir = Path(args.clone_dir).resolve() if args.clone_dir else _default_clone_dir(repo_url)

    try:
        result = resolve(repo_url, args.fix_commit, clone_dir)
    except Exception as e:
        onboarding_lib.emit({"error": str(e), "repo_url": repo_url, "fix_commit": args.fix_commit})
        return 1

    result["repo_url"] = repo_url
    onboarding_lib.emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
