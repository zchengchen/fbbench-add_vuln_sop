"""Shared helpers for the AddVulnSOP bug-onboarding scripts.

This directory is deliberately standalone -- NOT inside FuzzingBrain-Bench or
FuzzingBrain-Bench-answers, and not itself a git repo. It only ever touches
those two repos through explicit --answers-repo/--public-repo/--oss-fuzz-repo
paths (or the sibling-directory default below), and never mutates its own
tooling files as a side effect of onboarding a bug.

House style: argparse CLIs, JSON as the *last line* of stdout, so a Workflow's
narrow executor agent can just run the script and hand the raw stdout back
for JS to parse.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import shutil
import subprocess
from collections import namedtuple
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# stdout contract

def emit(obj: dict) -> None:
    """Print one compact JSON object as the last line of stdout."""
    print(json.dumps(obj))


# ---------------------------------------------------------------------------
# cross-process locking -- for any read-modify-write on state shared across
# concurrently-running onboarding pipelines (a bug-id registry, a numbering
# scheme, anything else keyed on "what already exists"). Blocks until
# acquired; the lock file itself is never cleaned up (that's fine -- it's a
# zero-byte marker, not the data).

@contextlib.contextmanager
def file_lock(lock_path: Path):
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ---------------------------------------------------------------------------
# ASan output parsing (mirrors FuzzingBrain-Bench-answers/tools/build_fixed.py's
# fault-detection rules, kept independent here rather than imported since this
# directory deliberately has no dependency on the answers repo's own package)

SAN_TRAILER = re.compile(r"==\d+==ERROR: (Address|UndefinedBehavior|Memory|Thread|Leak)Sanitizer:\s*(.+)")
SAN_SUMMARY = re.compile(r"SUMMARY:\s+((?:Address|UndefinedBehavior|Memory|Thread|Leak)Sanitizer): (.+)")
OP_RE = re.compile(r"\b(READ|WRITE) of size (\d+)\b")
FRAME_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+?):(\d+)(?::\d+)?\s*$", re.MULTILINE)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_asan_output(stderr_text: str) -> dict:
    """Extract {sanitizer, summary, op, size, top_frames, raw} from stderr.

    top_frames is the first stack found after the ERROR trailer (bounded to 8
    frames) -- good enough to anchor reach/site fields; full text kept in raw.

    oss-fuzz's docker-wrapped output is littered with ANSI color codes (e.g.
    `\\x1b[91m` for red) interleaved into the exact lines these regexes need
    to match -- strip them first, or a real crash's SUMMARY/frame lines can
    silently fail to match and this comes back looking like a clean run.
    """
    stderr_text = _ANSI_RE.sub("", stderr_text or "")
    trailer = SAN_TRAILER.search(stderr_text)
    summary_m = SAN_SUMMARY.search(stderr_text)
    op_m = OP_RE.search(stderr_text)
    frames = []
    for fm in FRAME_RE.finditer(stderr_text):
        frames.append({
            "function": fm.group(1),
            "file": os.path.basename(fm.group(2)),
            "line": int(fm.group(3)),
        })
        if len(frames) >= 8:
            break
    return {
        "sanitizer": trailer.group(1) if trailer else None,
        "summary": summary_m.group(0).strip() if summary_m else (trailer.group(0).strip() if trailer else None),
        "op": op_m.group(1) if op_m else None,
        "size": int(op_m.group(2)) if op_m else None,
        "top_frames": frames,
        "raw": stderr_text[-900:],
    }


def classify_asan_operation(parsed: dict) -> str | None:
    """READ/WRITE -> out-of-bounds-read/write.

    Only resolves the two ASan spatial-overflow classes gen_vuln_yaml.py's
    _CURATED dict needs disambiguated by hand; anything else returns None.
    """
    op = (parsed or {}).get("op")
    if op == "READ":
        return "out-of-bounds-read"
    if op == "WRITE":
        return "out-of-bounds-write"
    return None


# ---------------------------------------------------------------------------
# harness execution (exact ASAN_OPTIONS/subprocess contract from build_fixed.py)

ASAN_OPTIONS_TMPL = "abort_on_error=0:exitcode=66:handle_abort=1:detect_leaks={leak}"
UBSAN_OPTIONS = "abort_on_error=0:print_stacktrace=1"
LSAN_OPTIONS = "exitcode=66"


def run_harness_once(binary: Path, invocation: list | None, poc_path: Path,
                      timeout_s: int = 10, leak: bool = False,
                      env_extra: dict | None = None) -> dict:
    """Run one input through one harness binary as its own subprocess.

    Never batch multiple inputs into one libFuzzer -runs=0 invocation -- that
    stops at the first crash and hides everything after it. Fault-detection
    rules mirror build_fixed.py's run_harness() verbatim so every onboarding
    script agrees on what counts as a crash.
    """
    rundir = Path(subprocess.run(["mktemp", "-d"], capture_output=True, text=True).stdout.strip())
    try:
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = ASAN_OPTIONS_TMPL.format(leak="1" if leak else "0")
        env["UBSAN_OPTIONS"] = UBSAN_OPTIONS
        env["LSAN_OPTIONS"] = LSAN_OPTIONS
        env["TMPDIR"] = str(rundir)
        # Without this, ASan silently fails to symbolize ("invalid path to
        # external symbolizer!") even when a compatible llvm-symbolizer/
        # addr2line exists on PATH -- it does NOT auto-search PATH on its
        # own. Every caller of run_harness_once() depends on symbolized
        # file:line frames (gen_expected_yaml.py's reach/site derivation,
        # corpus_scan.py's SUMMARY-based dedup), so this is not optional.
        if not env.get("ASAN_SYMBOLIZER_PATH"):
            symbolizer = shutil.which("llvm-symbolizer") or shutil.which("addr2line")
            if symbolizer:
                env["ASAN_SYMBOLIZER_PATH"] = symbolizer
        if env_extra:
            env.update(env_extra)
        args = [str(binary)] + [str(poc_path) if a == "@@" else a for a in (invocation or ["@@"])]
        killed = False
        try:
            p = subprocess.run(args, cwd=rundir, env=env, capture_output=True, timeout=timeout_s)
            ec, stderr = p.returncode, p.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired as e:
            ec, stderr, killed = 124, (e.stderr or b"").decode("utf-8", "replace"), True
        parsed = parse_asan_output(stderr)
        fault = (
            killed
            or ec in (66, 77, 134, 136, 137, 139)
            or ec < 0
            or parsed["summary"] is not None
            or "ERROR: libFuzzer" in stderr
            or "libFuzzer: timeout" in stderr
            or "libFuzzer: out-of-memory" in stderr
        )
        if ec != 0:
            fault = True
        return {"returncode": ec, "killed": killed, "fault": fault, **parsed}
    finally:
        shutil.rmtree(rundir, ignore_errors=True)


# ---------------------------------------------------------------------------
# docker

def docker_build(context: Path, tag: str, build_args: dict | None = None,
                  dockerfile: Path | None = None, timeout_s: int = 2400) -> dict:
    cmd = ["docker", "build", "-t", tag]
    for k, v in (build_args or {}).items():
        cmd += ["--build-arg", f"{k}={v}"]
    if dockerfile is not None:
        cmd += ["-f", str(dockerfile)]
    cmd += [str(context)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    return {
        "ok": p.returncode == 0,
        "returncode": p.returncode,
        "log_tail": (p.stdout[-500:] + p.stderr[-500:]),
    }


def docker_extract(image_tag: str, src_path: str, dest_path: Path) -> dict:
    """docker create + docker cp + docker rm -- pull one file/dir out of an
    image without running it (used to lift /out/<config>/harness)."""
    cid = subprocess.run(["docker", "create", image_tag], capture_output=True, text=True).stdout.strip()
    if not cid:
        return {"ok": False, "returncode": -1, "stderr": "docker create produced no container id"}
    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        p = subprocess.run(["docker", "cp", f"{cid}:{src_path}", str(dest_path)], capture_output=True, text=True)
        return {"ok": p.returncode == 0, "returncode": p.returncode, "stderr": p.stderr}
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, text=True)


# ---------------------------------------------------------------------------
# repo/path resolution
#
# AddVulnSOP is a sibling of FuzzingBrain-Bench/FuzzingBrain-Bench-answers
# under the same parent directory -- NOT nested inside either repo, and not a
# git repo itself, so it survives a `git clone` reset of either bench repo.
# Defaults are computed relative to *this file's own location*, not cwd, so
# scripts work correctly regardless of what directory they're invoked from.

Paths = namedtuple("Paths", "answers public oss_fuzz")

SOP_DIR = Path(__file__).resolve().parent


def _find_benchmark_root(start: Path) -> Path:
    """Walk upward from `start` for the directory that has both bench repos
    as siblings. Handles both a flat checkout (this SOP repo cloned directly
    as e.g. `AddVulnSOP/`, a sibling of the bench repos) and this repo
    nested one level deeper under its own repo root (e.g. cloned as
    `fbbench-add_vuln_sop/`, with `AddVulnSOP/` as a subdirectory of that) --
    the sibling-repo names are the one constant across both layouts."""
    for candidate in (start, *start.parents):
        if (candidate / "FuzzingBrain-Bench").is_dir() and (candidate / "FuzzingBrain-Bench-answers").is_dir():
            return candidate
    return start.parent  # neither convention matched -- fall back to the old assumption


BENCHMARK_ROOT = _find_benchmark_root(SOP_DIR)


def find_repo_paths(answers_repo: str | None = None, public_repo: str | None = None,
                     oss_fuzz_repo: str | None = None) -> Paths:
    """Explicit arg > env var > sibling-directory convention next to this
    script's own location (BENCHMARK_ROOT, the shared parent of AddVulnSOP
    and the two bench repos)."""
    ans = Path(answers_repo).resolve() if answers_repo else Path(
        os.environ.get("FBBENCH_ANSWERS_REPO") or (BENCHMARK_ROOT / "FuzzingBrain-Bench-answers")
    ).resolve()
    pub = Path(public_repo).resolve() if public_repo else Path(
        os.environ.get("FBBENCH_PUBLIC_REPO") or (BENCHMARK_ROOT / "FuzzingBrain-Bench")
    ).resolve()
    ossf = Path(oss_fuzz_repo).resolve() if oss_fuzz_repo else Path(
        os.environ.get("FBBENCH_OSSFUZZ_REPO") or (BENCHMARK_ROOT / "oss-fuzz")
    ).resolve()
    return Paths(ans, pub, ossf)


def bug_dir(answers_repo: Path, bug_id: str) -> Path:
    for proj in (Path(answers_repo) / "bugs").iterdir():
        if proj.is_dir() and (proj / bug_id).is_dir():
            return proj / bug_id
    raise FileNotFoundError(f"no bug dir for bug_id={bug_id!r} under {answers_repo}/bugs/*/")


# ---------------------------------------------------------------------------
# yaml (full PyYAML -- these are offline authoring tools, not the sandboxed
# runtime grading path that deliberately avoids the PyYAML dependency)

def read_yaml(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text()) or {}


def write_yaml(path: Path, data: dict) -> None:
    Path(path).write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
