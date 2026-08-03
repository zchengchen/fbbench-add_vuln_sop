#!/usr/bin/env python3
"""Pin the two source trees a harness can legitimately come from to the bug's
own era, and afterwards verify the harness that got written actually came from
them.

WHY THIS EXISTS
---------------
The Dockerfile pins the code UNDER TEST (`ARG VULN_COMMIT` + `git checkout`),
but the trees the scaffolding agent reads to *author* the harness were left at
whatever their default branch points at today. That is a silent version skew:
the agent copies today's fuzz harness, the image compiles it against
year-old library headers, and the failure surfaces several minutes later as a
mystifying clang error (observed: libxml2's `fuzz/fuzz.c` at master calls
`xmlParserInputFlags`, an enum introduced three weeks AFTER the vuln commit).

A harness can live in either of two places, so both have to be pinned:

  - the project's OWN tree (e.g. libxml2's `fuzz/`)         -> pin to vuln_commit
  - the oss-fuzz repo (`projects/<project>/*.c`, ~22% of    -> pin to the oss-fuzz
    projects ship the harness there, not upstream)             commit contemporaneous
                                                                with the report

Both are pinned with `git worktree add --detach`, never `git checkout`:
  - the upstream clone's master working tree is still needed by find_fix_commit
    and reproduce_at_commit.py, which must not have HEAD yanked out from under
    them;
  - the oss-fuzz repo is a SHARED path (BENCHMARK_ROOT/oss-fuzz) that every
    concurrently-running pipeline reads. Checking out there would corrupt every
    other run in flight. Worktrees share the object store, cost almost nothing,
    and are independent.

Usage:
    harness_vintage.py pin --clone-dir <dir> --vuln-commit <sha> \\
        --oss-fuzz-repo <dir> [--anchor-date <iso8601>] [--tag <slug>]
    harness_vintage.py check --harness-dir <dir> --clone-dir <dir> \\
        --vuln-commit <sha> --oss-fuzz-repo <dir> --ossfuzz-commit <sha> \\
        [--upstream-head <sha>]
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import onboarding_lib as lib

# Files that live next to a harness but are never the harness itself; comparing
# them against upstream is noise.
IGNORED_NAMES = {".gitkeep", "README", "README.md"}


def _git(repo: Path, *args: str, check: bool = True) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} in {repo} failed: {p.stderr.strip()}")
    return p.stdout


def _git_bytes(repo: Path, *args: str) -> bytes | None:
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    return p.stdout if p.returncode == 0 else None


# ---------------------------------------------------------------------------
# pin

def resolve_ossfuzz_commit(oss_fuzz_repo: Path, anchor_date: str | None) -> str:
    """The oss-fuzz commit that was current when the bug was reported. Falls
    back to HEAD when no usable anchor date is known -- callers get told which
    happened via the returned `anchor_date`, so a fallback is visible rather
    than silently pretending to be pinned."""
    if anchor_date:
        sha = _git(oss_fuzz_repo, "rev-list", "-1", f"--before={anchor_date}", "HEAD").strip()
        if sha:
            return sha
    return _git(oss_fuzz_repo, "rev-parse", "HEAD").strip()


def add_worktree(repo: Path, commit: str, dest: Path) -> dict:
    """Idempotent `git worktree add --detach`. Reused as-is when it already
    sits at the right commit, so a --from-stage rerun doesn't have to rebuild
    it (and doesn't fail on 'already exists')."""
    if dest.is_dir():
        try:
            if _git(dest, "rev-parse", "HEAD").strip() == commit:
                return {"path": str(dest), "commit": commit, "reused": True}
        except RuntimeError:
            pass  # not a usable worktree -- fall through and let git prune/re-add
        _git(repo, "worktree", "remove", "--force", str(dest), check=False)
    # Serialized: several pipelines run concurrently against the SHARED oss-fuzz
    # repo, and `worktree add` is a read-modify-write on .git/worktrees/.
    with lib.file_lock(Path("/tmp") / f"fbbench-worktree-{repo.name}.lock"):
        _git(repo, "worktree", "prune", check=False)
        _git(repo, "worktree", "add", "--detach", str(dest), commit)
    return {"path": str(dest), "commit": commit, "reused": False}


def pin(clone_dir: Path, vuln_commit: str, oss_fuzz_repo: Path,
        anchor_date: str | None, tag: str) -> dict:
    vuln_wt = add_worktree(clone_dir, vuln_commit, Path(f"{clone_dir}-at-vuln"))

    ossfuzz_commit = resolve_ossfuzz_commit(oss_fuzz_repo, anchor_date)
    ossfuzz_wt = add_worktree(oss_fuzz_repo, ossfuzz_commit,
                              Path("/tmp") / f"fbbench-ossfuzz-{tag}")
    return {
        "vuln_src_dir": vuln_wt["path"],
        "vuln_commit": vuln_commit,
        "vuln_src_reused": vuln_wt["reused"],
        "ossfuzz_src_dir": ossfuzz_wt["path"],
        "ossfuzz_commit": ossfuzz_commit,
        "ossfuzz_src_reused": ossfuzz_wt["reused"],
        # null means "no usable date -- oss-fuzz fell back to HEAD", which the
        # check step downgrades to a warning instead of asserting vintage.
        "anchor_date": anchor_date,
    }


# ---------------------------------------------------------------------------
# check

def _basename_index(repo: Path, commit: str) -> dict[str, list[str]]:
    out = _git(repo, "ls-tree", "-r", "--name-only", commit)
    index: dict[str, list[str]] = {}
    for path in out.splitlines():
        index.setdefault(Path(path).name, []).append(path)
    return index


def _matches_at(repo: Path, commit: str, paths: list[str], content: bytes) -> str | None:
    for path in paths:
        if _git_bytes(repo, "show", f"{commit}:{path}") == content:
            return path
    return None


def check(harness_dir: Path, clone_dir: Path, vuln_commit: str, upstream_head: str | None,
          oss_fuzz_repo: Path, ossfuzz_commit: str) -> dict:
    """Classify every file the scaffolding agent left in harness/.

    verdict per file:
      pinned    -- byte-identical to that file at the pinned commit. Correct.
      stale     -- byte-identical to the CURRENT tip but not to the pinned
                   commit. This is the exact skew this module exists to catch,
                   and it is a hard failure.
      authored  -- matches neither. Legitimate: plenty of harnesses are
                   hand-written or adapted (provenance: fuzzingbrain), and for
                   ~22% of projects the harness isn't in upstream at all. Only
                   ever a warning -- we cannot distinguish "carefully adapted"
                   from "wrong" by content alone, so we don't pretend to.
    """
    sources = [
        ("upstream", clone_dir, vuln_commit,
         upstream_head or _git(clone_dir, "rev-parse", "HEAD").strip()),
        ("oss-fuzz", oss_fuzz_repo, ossfuzz_commit,
         _git(oss_fuzz_repo, "rev-parse", "HEAD").strip()),
    ]
    indexes = {name: _basename_index(repo, pinned) for name, repo, pinned, _ in sources}
    head_indexes = {name: _basename_index(repo, head) for name, repo, _, head in sources}

    files, violations, warnings = [], [], []
    for path in sorted(p for p in harness_dir.rglob("*") if p.is_file()):
        if path.name in IGNORED_NAMES:
            continue
        content = path.read_bytes()
        rel = str(path.relative_to(harness_dir))
        entry = {"file": rel, "verdict": "authored", "source": None, "matched_path": None}

        for name, repo, pinned, _head in sources:
            hit = _matches_at(repo, pinned, indexes[name].get(path.name, []), content)
            if hit:
                entry.update(verdict="pinned", source=name, matched_path=hit)
                break
        else:
            for name, repo, pinned, head in sources:
                if head == pinned:
                    continue  # nothing to be stale relative to
                hit = _matches_at(repo, head, head_indexes[name].get(path.name, []), content)
                if hit:
                    entry.update(verdict="stale", source=name, matched_path=hit)
                    violations.append(
                        f"harness/{rel} is the {name} CURRENT-TIP version of {hit} "
                        f"({head[:12]}), not the version at the pinned commit {pinned[:12]}. "
                        f"The image builds the library at {pinned[:12]}, so this harness may "
                        f"call APIs that do not exist yet."
                    )
                    break
            else:
                warnings.append(
                    f"harness/{rel} matches no known upstream/oss-fuzz file at either the pinned "
                    f"commit or the current tip -- assuming it was hand-authored or adapted on "
                    f"purpose. Not verifiable by content."
                )
        files.append(entry)

    return {"ok": not violations, "files": files,
            "violations": violations, "warnings": warnings}


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_pin = sub.add_parser("pin", help="create the two era-pinned worktrees")
    p_pin.add_argument("--clone-dir", required=True)
    p_pin.add_argument("--vuln-commit", required=True)
    p_pin.add_argument("--oss-fuzz-repo", required=True)
    p_pin.add_argument("--anchor-date", default=None,
                       help="report-filed date; oss-fuzz is pinned to its tip at that moment. "
                            "Omitted/unparseable -> falls back to oss-fuzz HEAD.")
    p_pin.add_argument("--tag", required=True,
                       help="per-run slug so concurrent pipelines get their own oss-fuzz worktree")

    p_check = sub.add_parser("check", help="verify harness/ came from the pinned trees")
    p_check.add_argument("--harness-dir", required=True)
    p_check.add_argument("--clone-dir", required=True)
    p_check.add_argument("--vuln-commit", required=True)
    p_check.add_argument("--oss-fuzz-repo", required=True)
    p_check.add_argument("--ossfuzz-commit", required=True)
    p_check.add_argument("--upstream-head", default=None,
                         help="upstream default-branch tip; defaults to the clone's HEAD")

    args = ap.parse_args()
    # Always emit parseable JSON, including on failure. The caller reads the
    # last stdout line and reports it; letting an exception escape instead
    # turns a legible cause ("the clone is gone") into "produced no stdout"
    # plus a traceback, which is what the operator actually sees.
    try:
        if args.cmd == "pin":
            lib.emit(pin(Path(args.clone_dir), args.vuln_commit,
                         Path(args.oss_fuzz_repo), args.anchor_date, args.tag))
        else:
            lib.emit(check(Path(args.harness_dir), Path(args.clone_dir), args.vuln_commit,
                           args.upstream_head, Path(args.oss_fuzz_repo), args.ossfuzz_commit))
    except Exception as e:
        lib.emit({"ok": False, "error": f"{type(e).__name__}: {e}",
                  "files": [], "violations": [], "warnings": []})
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
