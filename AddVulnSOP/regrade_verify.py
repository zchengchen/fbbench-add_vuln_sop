#!/usr/bin/env python3
"""Re-grade a bug's PoC blob(s) using native_grader.py -- a self-contained
Python port of the grading algorithm (tools/mcp-server's grade.go +
reach.go). Does NOT build, run, or otherwise depend on the answers/public
repos' own Go code at all anymore: only their bug DATA (grader/expected.yaml,
bench.yaml, binaries/) is read, which can't be avoided since that's what's
being graded. See native_grader.py's own docstring for the full rationale
and exactly what was ported from where.

(Earlier history, for context: this used to shell out to tools/regrade.py /
fbbench.grading.grader.grade_blob, which called a since-removed MCP tool
name over stdio and only "worked" against whichever stale binary happened to
be committed. Then it shelled out to a freshly-built mcp-server via
-grade-server -- correct, but still needed Docker + a golang toolchain +
trusting that repo's tools/mcp-server source not to drift again. Now it
doesn't need either repo's code at all.)
"""
from __future__ import annotations

import argparse
import glob
import os
import shutil
import sys
from pathlib import Path

import onboarding_lib as lib
from native_grader import grade_bug


def run_regrade(answers_repo: Path, bug_id: str, pocs: list[str], pocs_dir: str | None,
                 llvm14_path: str | None, asan_symbolizer: str | None) -> dict:
    remediations_applied = []

    try:
        bug_dir = lib.bug_dir(answers_repo, bug_id)
    except FileNotFoundError as e:
        return {
            "solved": False, "fired": [], "kb_required": [], "missing": [],
            "remediations_applied": [], "error": str(e),
            "returncode": -1, "raw_stdout": "", "raw_stderr": "",
        }

    blobs = list(pocs)
    if pocs_dir:
        blobs += sorted(glob.glob(os.path.join(pocs_dir, "**", "*.bin"), recursive=True))
    if not blobs:
        return {
            "solved": False, "fired": [], "kb_required": [], "missing": [],
            "remediations_applied": [], "error": "no --poc or --pocs-dir given",
            "returncode": -1, "raw_stdout": "", "raw_stderr": "",
        }

    # llvm-profdata/llvm-cov (used only by the `reach` capability) don't
    # auto-search PATH for a compatible version -- same remediation
    # ensure_llvm14.py already provides for gen_expected_yaml.py.
    if llvm14_path:
        os.environ["PATH"] = f"{llvm14_path}{os.pathsep}{os.environ.get('PATH', '')}"
        remediations_applied.append("llvm14_path")
    symbolizer = asan_symbolizer or shutil.which("llvm-symbolizer")
    if symbolizer:
        os.environ["ASAN_SYMBOLIZER_PATH"] = symbolizer
        if asan_symbolizer:
            remediations_applied.append("asan_symbolizer")

    result = grade_bug(bug_dir, [Path(b) for b in blobs])
    result["remediations_applied"] = remediations_applied
    return result


def main():
    ap = argparse.ArgumentParser(
        description="Re-grade a bug's PoC blob(s) with native_grader.py (self-contained Python "
                    "port of the grading algorithm -- no answers/public repo CODE dependency) and "
                    "report structured pass/fail, with optional llvm14/asan-symbolizer remediation env."
    )
    ap.add_argument("--bug-id", required=True)
    ap.add_argument("--poc", action="append", default=[], help="path to a PoC blob (repeatable)")
    ap.add_argument("--pocs-dir", default=None, help="directory of *.bin blobs to also grade")
    ap.add_argument("--llvm14-path", default=None,
                     help="dir to prepend to PATH so llvm-profdata-14/llvm-cov-14 resolve (see ensure_llvm14.py)")
    ap.add_argument("--asan-symbolizer", default=None,
                     help="path to llvm-symbolizer; falls back to `which llvm-symbolizer` if omitted "
                          "(the auto-fallback is not recorded in remediations_applied)")
    ap.add_argument("--answers-repo", default=None)
    ap.add_argument("--public-repo", default=None, help="unused here, accepted for CLI consistency")
    ap.add_argument("--oss-fuzz-repo", default=None, help="unused here, accepted for CLI consistency")
    args = ap.parse_args()

    paths = lib.find_repo_paths(
        answers_repo=args.answers_repo,
        public_repo=args.public_repo,
        oss_fuzz_repo=args.oss_fuzz_repo,
    )

    if not args.poc and not args.pocs_dir:
        lib.emit({
            "solved": False, "fired": [], "kb_required": [], "missing": [],
            "remediations_applied": [], "error": "no --poc or --pocs-dir given",
            "returncode": -1, "raw_stdout": "", "raw_stderr": "",
        })
        sys.exit(1)

    result = run_regrade(
        paths.answers, args.bug_id, args.poc, args.pocs_dir,
        args.llvm14_path, args.asan_symbolizer,
    )
    lib.emit(result)
    if "error" in result:
        sys.exit(1)


if __name__ == "__main__":
    main()
