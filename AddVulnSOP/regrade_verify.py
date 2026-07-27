#!/usr/bin/env python3
"""Thin wrapper around FuzzingBrain-Bench-answers/tools/regrade.py.

regrade.py has no self-contained sys.path fixup of its own -- it relies on
`fbbench` being editable-pip-installed into the answers repo's own .venv.
So we prefer <answers_repo>/.venv/bin/python3 to run it (whatever bare
interpreter launched *this* script may not have fbbench importable at all).
If that venv doesn't exist, fall back to sys.executable and explicitly set
PYTHONPATH=<answers_repo> (prepended to any inherited PYTHONPATH) so
`import fbbench` still resolves.

regrade.py's exit code is always 0 on a normal run regardless of whether the
bug was solved (errors go to stderr with exit 2) -- so SOLVED must be parsed
out of the printed summary line, never inferred from the return code.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import onboarding_lib as lib

# regrade.py's final line, e.g.:
#   libxml2-posgroup-oob-read: best across 3 blobs -> fired=['crash', 'reach', 'site'] tier=3 K_b=['class', 'crash', 'differential', 'reach', 'site'] SOLVED=False
SUMMARY_RE = re.compile(
    r"^(?P<bug>.+): best across (?P<n>\d+) blobs -> "
    r"fired=(?P<fired>\[.*?\]) tier=(?P<tier>\d+) K_b=(?P<kb>\[.*?\]) "
    r"SOLVED=(?P<solved>True|False)\s*$",
    re.MULTILINE,
)


def _regrade_python(answers_repo: Path) -> tuple[str, dict]:
    """Return (python_executable, extra_env) to invoke regrade.py with."""
    venv_python = answers_repo / ".venv" / "bin" / "python3"
    if venv_python.is_file() and os.access(venv_python, os.X_OK):
        return str(venv_python), {}
    extra_env = {}
    existing = os.environ.get("PYTHONPATH", "")
    extra_env["PYTHONPATH"] = str(answers_repo) + (os.pathsep + existing if existing else "")
    return sys.executable, extra_env


def run_regrade(answers_repo: Path, bug_id: str, pocs: list[str], pocs_dir: str | None,
                 server_bin: str | None, llvm14_path: str | None,
                 asan_symbolizer: str | None) -> dict:
    remediations_applied = []

    python_exe, extra_env = _regrade_python(answers_repo)
    env = dict(os.environ)
    env.update(extra_env)

    if llvm14_path:
        env["PATH"] = f"{llvm14_path}{os.pathsep}{env.get('PATH', '')}"
        remediations_applied.append("llvm14_path")

    symbolizer = asan_symbolizer
    explicit_symbolizer = bool(asan_symbolizer)
    if not symbolizer:
        symbolizer = shutil.which("llvm-symbolizer")
    if symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer
        if explicit_symbolizer:
            remediations_applied.append("asan_symbolizer")

    regrade_py = answers_repo / "tools" / "regrade.py"
    cmd = [python_exe, str(regrade_py), bug_id, *pocs]
    if pocs_dir:
        cmd += ["--pocs-dir", pocs_dir]
    cmd += ["--server-bin", server_bin or str(answers_repo / "bin" / "mcp-server")]

    p = subprocess.run(cmd, cwd=str(answers_repo), env=env, capture_output=True, text=True, timeout=600)
    raw_stdout, raw_stderr = p.stdout, p.stderr

    m = None
    for m in SUMMARY_RE.finditer(raw_stdout):
        pass  # take the LAST match in stdout
    if m is None:
        return {
            "solved": False, "fired": [], "kb_required": [], "missing": [],
            "remediations_applied": remediations_applied,
            "error": "could not parse regrade.py summary line",
            "returncode": p.returncode, "raw_stdout": raw_stdout, "raw_stderr": raw_stderr,
        }

    fired = list(ast.literal_eval(m.group("fired")))
    kb_required = list(ast.literal_eval(m.group("kb")))
    solved = m.group("solved") == "True"
    tier = int(m.group("tier"))
    missing = [k for k in kb_required if k not in fired]

    return {
        "solved": solved,
        "fired": fired,
        "kb_required": kb_required,
        "missing": missing,
        "tier": tier,
        "remediations_applied": remediations_applied,
        "raw_stdout": raw_stdout,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Re-grade a bug's PoC blob(s) through the real tools/regrade.py and report "
                    "structured pass/fail, with optional llvm14/asan-symbolizer remediation env."
    )
    ap.add_argument("--bug-id", required=True)
    ap.add_argument("--poc", action="append", default=[], help="path to a PoC blob (repeatable)")
    ap.add_argument("--pocs-dir", default=None, help="directory of *.bin blobs, passed through to regrade.py")
    ap.add_argument("--server-bin", default=None, help="default: <answers_repo>/bin/mcp-server")
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
        args.server_bin, args.llvm14_path, args.asan_symbolizer,
    )
    lib.emit(result)
    if "error" in result:
        sys.exit(1)


if __name__ == "__main__":
    main()
