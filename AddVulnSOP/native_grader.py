#!/usr/bin/env python3
"""Self-contained Python port of the grading oracle (tools/mcp-server's
grade.go + reach.go) -- computes reach/crash/differential/class/site
DIRECTLY against a bug's own binaries/expected.yaml, without building or
running the answers/public repos' Go mcp-server at all.

Why this exists: regrade_verify.py used to shell out to a freshly-built
mcp-server binary (ensure_mcp_server.py + -grade-server mode). That's more
resilient than trusting a stale committed binary, but it still means every
regrade needs Docker + a golang toolchain + whatever tools/mcp-server/*.go
currently says -- and that source can change (it already has, twice, in one
week: the binaries/ directory rename, and the grade->run_poc_on_harness tool
rename). This module ports the actual grading ALGORITHM to Python so
regrade_verify never depends on the answers/public repos' CODE again -- only
their bug DATA (grader/expected.yaml, bench.yaml, binaries/), which is the
whole point of grading in the first place and can't be avoided.

Ported ~1:1 from, as of this writing:
    FuzzingBrain-Bench-answers/tools/mcp-server/grade.go
    FuzzingBrain-Bench-answers/tools/mcp-server/reach.go
No shared test corpus exists to auto-detect drift -- if that Go logic
changes upstream, this needs a matching hand-update.

Needs on PATH: llvm-profdata(-14) + llvm-cov(-14) for the `reach` capability
only (same tools AddVulnSOP's own gen_expected_yaml.py/ensure_llvm14.py
already require elsewhere in this pipeline -- not a new dependency). crash/
class/site/differential need nothing but the bug's own harness binaries.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal as signal_module
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import onboarding_lib as lib

# ---------------------------------------------------------------------------
# harness execution -- port of grade.go's runHarness()

_SIGNAL_NAMES = {
    signal_module.SIGSEGV: "SIGSEGV",
    signal_module.SIGABRT: "SIGABRT",
    signal_module.SIGBUS: "SIGBUS",
    signal_module.SIGILL: "SIGILL",
    signal_module.SIGFPE: "SIGFPE",
    signal_module.SIGKILL: "SIGKILL",
}


@dataclass
class HarnessRun:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    signal: str | None = None
    timed_out: bool = False


def _decode(b) -> str:
    if b is None:
        return ""
    if isinstance(b, bytes):
        return b.decode("utf-8", "replace")
    return b


def run_harness(binary: Path, invocation: list[str] | None, poc_path: Path, run_dir: Path,
                 timeout_s: int, detect_leaks: bool) -> HarnessRun:
    if timeout_s <= 0:
        timeout_s = 30
    args = [str(poc_path) if a == "@@" else a for a in (invocation or ["@@"])]
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = f"abort_on_error=0:exitcode=66:handle_abort=1:detect_leaks={'1' if detect_leaks else '0'}"
    env["UBSAN_OPTIONS"] = "abort_on_error=0:print_stacktrace=1"
    env["LSAN_OPTIONS"] = "exitcode=66"
    env["TMPDIR"] = str(run_dir)
    # ASan does not search PATH for a symbolizer on its own -- without this,
    # frames come back unsymbolized and every regex below silently misses.
    if not env.get("ASAN_SYMBOLIZER_PATH"):
        symbolizer = shutil.which("llvm-symbolizer") or shutil.which("addr2line")
        if symbolizer:
            env["ASAN_SYMBOLIZER_PATH"] = symbolizer

    try:
        p = subprocess.run([str(binary), *args], cwd=str(run_dir), env=env,
                            capture_output=True, timeout=timeout_s)
        stdout, stderr = _decode(p.stdout), _decode(p.stderr)
        if p.returncode < 0:
            sig_num = -p.returncode
            return HarnessRun(stdout, stderr, 128 + sig_num, _SIGNAL_NAMES.get(sig_num), False)
        return HarnessRun(stdout, stderr, p.returncode, None, False)
    except subprocess.TimeoutExpired as e:
        return HarnessRun(_decode(e.stdout), _decode(e.stderr), 124, None, True)


# ---------------------------------------------------------------------------
# crash -- port of grade.go's crashFired()

_SANITIZER_TRAILER = re.compile(r"==\d+==ERROR: (Address|UndefinedBehavior|Memory|Thread|Leak)Sanitizer:")
_SANITIZER_SUMMARY = re.compile(r"SUMMARY:\s+(Address|UndefinedBehavior|Memory|Thread|Leak)Sanitizer:")
_JAVA_EXCEPTION_LINE = re.compile(
    r'(?:Caused by:|Exception in thread "[^"]*"|== Java Exception:)\s+([a-zA-Z0-9_.$]+(?:Exception|Error))')


def crash_fired(r: HarnessRun) -> bool:
    if r.signal in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE"):
        # A bare, output-less signal is a pre-init host flake, not a crash
        # the input triggered (see grade.go's crashFired comment).
        if not r.stdout.strip() and not r.stderr.strip():
            return False
        return True
    if r.exit_code == 137:
        return True
    if _SANITIZER_TRAILER.search(r.stderr) or _SANITIZER_SUMMARY.search(r.stderr):
        return True
    if r.exit_code != 0 and "ERROR: libFuzzer" in r.stderr:
        return True
    if r.exit_code != 0 and "Test unit written to" in r.stderr:
        return True
    if "libFuzzer: timeout" in r.stderr or "libFuzzer: out-of-memory" in r.stderr:
        return True
    if _JAVA_EXCEPTION_LINE.search(r.stderr):
        return True
    return False


def fixed_faulted(r: HarnessRun) -> bool:
    return r.timed_out or r.exit_code != 0 or crash_fired(r)


def fixed_run_attempts() -> int:
    v = os.environ.get("BENCH_FIXED_RUN_ATTEMPTS")
    if v:
        try:
            n = int(v)
            if n > 0:
                return n
        except ValueError:
            pass
    return 5


# ---------------------------------------------------------------------------
# class -- port of grade.go's classMatches() + canonClass/mapUBSan/mapJavaException

_ASAN_ERROR_LINE = re.compile(r"AddressSanitizer:\s+([a-zA-Z0-9_-]+)")
_UBSAN_ERROR_LINE = re.compile(r"runtime error:\s+([^\n]+)")
_ASSERT_FAIL_LINE = re.compile(r": Assertion .+ failed")
_LSAN_LEAK_LINE = re.compile(r"(Direct|Indirect) leak of")
_STACK_OVERFLOW_LINE = re.compile(r"Sanitizer: stack-overflow|stack-overflow on address")


def _canon_class(s: str) -> str:
    return s.strip().lower()


def _map_ubsan(msg: str) -> str:
    low = msg.lower()
    table = [
        ("null pointer", "null-deref"),
        ("applying zero offset to null", "null-deref"),
        ("signed integer overflow", "integer-overflow"),
        ("unsigned integer overflow", "integer-overflow"),
        ("negation of", "integer-overflow"),
        ("shift exponent", "integer-overflow"),
        ("misaligned address", "misaligned-access"),
        ("load of misaligned", "misaligned-access"),
        ("addition of unsigned offset", "integer-overflow"),
        ("applying non-zero offset", "integer-overflow"),
        ("implicit conversion", "integer-overflow"),
        ("outside the range of representable", "float-cast-overflow"),
        ("out of bounds", "oob-read"),
    ]
    for needle, cls in table:
        if needle in low:
            return cls
    return ""


def _map_java_exception(fqn: str) -> str:
    low = fqn.lower()
    if low.endswith("outofmemoryerror"):
        return "oom"
    if low.endswith("stackoverflowerror"):
        return "stack-overflow"
    if low.endswith("nullpointerexception"):
        return "null-deref"
    if "indexoutofbounds" in low:
        return "oob-read"
    if "arrayindexoutofbounds" in low:
        return "oob-read"
    if low.endswith("classcastexception"):
        return "class-cast"
    if low.endswith("numberformatexception"):
        return "uncaught-exception"
    if low.endswith("negativearraysizeexception"):
        return "uncaught-exception"
    if low.endswith("arithmeticexception"):
        return "integer-overflow"
    if "exception" in low or "error" in low:
        return "uncaught-exception"
    return ""


def class_matches(r: HarnessRun, expected: str) -> bool:
    if not expected:
        return False
    if expected == "allocation-size-too-big":
        if "allocation-size-too-big" in r.stderr or "requested allocation size" in r.stderr:
            return True
    elif expected == "memory-leak":
        if _LSAN_LEAK_LINE.search(r.stderr):
            return True
    elif expected == "stack-overflow":
        if _STACK_OVERFLOW_LINE.search(r.stderr):
            return True
    elif expected == "oom":
        if r.exit_code == 137 or "out-of-memory" in r.stderr:
            return True
        if "libFuzzer: timeout" in r.stderr or "libFuzzer: out-of-memory" in r.stderr:
            return True
    elif expected == "abrt":
        if _ASSERT_FAIL_LINE.search(r.stderr):
            return True

    m = _ASAN_ERROR_LINE.search(r.stderr)
    if m and _canon_class(m.group(1)) == expected:
        return True
    m = _UBSAN_ERROR_LINE.search(r.stderr)
    if m and _map_ubsan(m.group(1)) == expected:
        return True
    m = _JAVA_EXCEPTION_LINE.search(r.stderr)
    if m and (_map_java_exception(m.group(1)) == expected or m.group(1) == expected):
        return True
    return False


# ---------------------------------------------------------------------------
# site / reach shared frame-matching -- port of grade.go's frameRe/isHarnessFrame/
# suffixMatch + Java equivalents

_FRAME_RE = re.compile(r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+.+?\s+(/[^\s:]+):(\d+)")
_JAVA_FRAME_RE = re.compile(r"\s+at\s+([a-zA-Z0-9_.$]+)\(([A-Za-z0-9_$]+\.java):(\d+)\)")
_UBSAN_SITE_LINE = re.compile(r"([^\s:]+):(\d+):\d+: runtime error")
_CHROMIUM_FATAL_LINE = re.compile(r":FATAL:([^\s:\]]+):(\d+)\]")


def _is_harness_frame(file: str) -> bool:
    return "/harness/" in file or file.endswith("_fuzzer.c") or file.endswith("_fuzzer.cc")


def _is_java_harness_frame(file: str) -> bool:
    return "Fuzzer.java" in file or "PocRunner.java" in file


def _suffix_match(frame_path: str, expected: str) -> bool:
    frame_path = frame_path.replace("/./", "/")
    expected = expected.replace("/./", "/")
    if frame_path == expected:
        return True
    if frame_path.endswith("/" + expected):
        return True
    if "/" not in expected and os.path.basename(frame_path) == os.path.basename(expected):
        return True
    return False


def _java_qualified_path(fqn: str, file: str) -> str:
    cls = file[:-len(".java")] if file.endswith(".java") else file
    i = fqn.find("." + cls)
    if i <= 0:
        return file
    return fqn[:i].replace(".", "/") + "/" + file


def _java_suffix_match(qualified: str, expected: str) -> bool:
    if qualified == expected:
        return True
    if expected.endswith("/" + qualified):
        return True
    if "/" not in expected and os.path.basename(qualified) == expected:
        return True
    return False


# ---------------------------------------------------------------------------
# site -- port of grade.go's siteMatches()

def site_matches(r: HarnessRun, expected: dict) -> bool:
    site = expected.get("site") or {}
    expected_file = site.get("expected_file") or ""
    if not expected_file:
        return False
    tol = max(site.get("line_tolerance", 0) or 0, 0)
    max_frame = site.get("max_frame_distance") or 3
    if max_frame <= 0:
        max_frame = 3
    expected_line = site.get("expected_line") or 0

    distance = 0
    for m in _FRAME_RE.finditer(r.stderr):
        file = m.group(2)
        if _is_harness_frame(file):
            continue
        distance += 1
        if distance > max_frame:
            break
        if not _suffix_match(file, expected_file):
            continue
        line = int(m.group(3))
        if abs(line - expected_line) <= tol:
            return True

    j_dist = 0
    for m in _JAVA_FRAME_RE.finditer(r.stderr):
        file = m.group(2)
        if _is_java_harness_frame(file):
            continue
        j_dist += 1
        if j_dist > max_frame:
            break
        if not _java_suffix_match(_java_qualified_path(m.group(1), file), expected_file):
            continue
        line = int(m.group(3))
        if abs(line - expected_line) <= tol:
            return True

    for pat in (_UBSAN_SITE_LINE, _CHROMIUM_FATAL_LINE):
        for m in pat.finditer(r.stderr):
            if not _suffix_match(m.group(1), expected_file):
                continue
            line = int(m.group(2))
            if abs(line - expected_line) <= tol:
                return True
    return False


# ---------------------------------------------------------------------------
# reach -- port of reach.go's reachFired()/reachFromBacktrace()/llvmCovHit()

def _sibling_shared_objects(cov_bin: Path) -> list[str]:
    return [str(p) for p in cov_bin.parent.glob("*.so*")]


def _llvm_cov_hit(raw: bytes, expected_file: str, lo: int, hi: int) -> bool:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return False
    for d in doc.get("data", []):
        for f in d.get("files", []):
            if not _suffix_match(f.get("filename", ""), expected_file):
                continue
            for seg in f.get("segments", []):
                if len(seg) < 4:
                    continue
                try:
                    line, count = int(seg[0]), int(seg[2])
                except (TypeError, ValueError):
                    continue
                if count == 0:
                    continue
                if lo == 0 and hi == 0:
                    return True
                if lo <= line <= hi:
                    return True
    return False


def reach_fired(cov_bin: Path, invocation: list[str] | None, poc_path: Path, run_dir: Path,
                timeout_s: int, expected: dict) -> bool:
    reach = expected.get("reach") or {}
    expected_function = reach.get("expected_function") or ""
    expected_file = reach.get("expected_file") or ""
    if not expected_function and not expected_file:
        return False
    if not cov_bin.is_file():
        return False

    profraw = run_dir / "default.profraw"
    profdata = run_dir / "default.profdata"
    args = [str(poc_path) if a == "@@" else a for a in (invocation or ["@@"])]
    profile_env = str(run_dir / "default%c.profraw") if reach.get("coverage_continuous") else str(profraw)

    env = dict(os.environ)
    env["LLVM_PROFILE_FILE"] = profile_env
    env["ASAN_OPTIONS"] = "abort_on_error=0:detect_leaks=0"
    env["TMPDIR"] = str(run_dir)
    cov_timeout = max(timeout_s, 120)
    try:
        subprocess.run([str(cov_bin), *args], cwd=str(run_dir), env=env,
                        capture_output=True, timeout=cov_timeout, start_new_session=True)
    except subprocess.TimeoutExpired:
        pass  # continuous-mode coverage may still have flushed a profile

    if not profraw.is_file():
        return False

    merge_ok = False
    for profdata_tool in ("llvm-profdata", "llvm-profdata-14"):
        if shutil.which(profdata_tool) is None:
            continue
        p = subprocess.run([profdata_tool, "merge", "-sparse", str(profraw), "-o", str(profdata)],
                            capture_output=True)
        if p.returncode == 0:
            merge_ok = True
            break
    if not merge_ok:
        return False

    cov_args = ["export", "--format=text", "-instr-profile", str(profdata), str(cov_bin)]
    for so in _sibling_shared_objects(cov_bin):
        cov_args += ["-object", so]
    for cov_tool in ("llvm-cov", "llvm-cov-14"):
        if shutil.which(cov_tool) is None:
            continue
        p = subprocess.run([cov_tool, *cov_args], capture_output=True)
        if p.returncode == 0:
            lo, hi = (reach.get("expected_line_range") or [0, 0])[:2] or (0, 0)
            return _llvm_cov_hit(p.stdout, expected_file, lo, hi)
    return False


def reach_from_backtrace(stderr: str, expected: dict) -> bool:
    reach = expected.get("reach") or {}
    expected_file = reach.get("expected_file") or ""
    expected_function = reach.get("expected_function") or ""
    if not expected_file and not expected_function:
        return False
    line_range = reach.get("expected_line_range") or []
    lo, hi = (line_range[0], line_range[1]) if len(line_range) == 2 else (0, 0)

    for m in _FRAME_RE.finditer(stderr):
        file = m.group(2)
        if _is_harness_frame(file):
            continue
        if expected_file and not _suffix_match(file, expected_file):
            continue
        line = int(m.group(3))
        if lo > 0 and hi > 0:
            if lo <= line <= hi:
                return True
            continue
        return True

    for m in _JAVA_FRAME_RE.finditer(stderr):
        file = m.group(2)
        if _is_java_harness_frame(file):
            continue
        if expected_file and not _java_suffix_match(_java_qualified_path(m.group(1), file), expected_file):
            continue
        line = int(m.group(3))
        if lo > 0 and hi > 0:
            if lo <= line <= hi:
                return True
            continue
        return True
    return False


# ---------------------------------------------------------------------------
# orchestration -- port of grade.go's runRound()

BIN_VULN_ASAN = Path("binaries/vuln/asan/harness")
BIN_VULN_COV = Path("binaries/vuln/cov/harness")
BIN_FIXED_ASAN = Path("binaries/fixed/asan/harness")

DEFAULT_CAPS = ("reach", "crash", "differential", "class", "site")


def _is_leak_class(expected_class: str) -> bool:
    return "leak" in (expected_class or "").lower()


def grade_one_round(bug_dir: Path, poc_path: Path, bench: dict, expected: dict) -> dict:
    """One grading round against bug_dir's own binaries/expected.yaml.
    Returns {capabilities: {flag: fired|not_fired|n/a}, evidence: {...}}."""
    capability_set = bench.get("capability_set") or list(DEFAULT_CAPS)
    caps = {c: "n/a" for c in DEFAULT_CAPS}
    for c in capability_set:
        if c in caps:
            caps[c] = "not_fired"

    harness = bench.get("harness") or {}
    invocation = harness.get("invocation") or ["@@"]
    timeout_s = harness.get("timeout_s") or 30
    expected_class = (expected.get("class") or {}).get("expected") or ""
    detect_leaks = _is_leak_class(expected_class)

    with tempfile.TemporaryDirectory(prefix="fbbench-grade-") as run_dir_s:
        run_dir = Path(run_dir_s)
        vuln_bin = bug_dir / BIN_VULN_ASAN
        out = run_harness(vuln_bin, invocation, poc_path, run_dir, timeout_s, detect_leaks)

        timeout_hit = expected_class == "timeout" and out.timed_out
        if "crash" in caps:
            if crash_fired(out) or timeout_hit:
                caps["crash"] = "fired"
        if "class" in caps:
            if class_matches(out, expected_class) or timeout_hit:
                caps["class"] = "fired"
        if "site" in caps:
            if site_matches(out, expected):
                caps["site"] = "fired"
        if "reach" in caps:
            cov_bin = bug_dir / BIN_VULN_COV
            if caps["site"] == "fired":
                # site is strictly stronger than reach: crashing AT the
                # expected file:line necessarily executed the function.
                caps["reach"] = "fired"
            elif reach_fired(cov_bin, invocation, poc_path, run_dir, timeout_s, expected):
                caps["reach"] = "fired"
            elif reach_from_backtrace(out.stderr, expected):
                caps["reach"] = "fired"

        if "differential" in caps and caps["crash"] == "fired":
            fixed_bin = bug_dir / BIN_FIXED_ASAN
            if fixed_bin.is_file():
                for _ in range(fixed_run_attempts()):
                    fout = run_harness(fixed_bin, invocation, poc_path, run_dir, timeout_s, detect_leaks)
                    if not fixed_faulted(fout):
                        caps["differential"] = "fired"
                        break

        return {
            "capabilities": caps,
            "evidence": {
                "crash": {"vuln_exit": out.exit_code, "vuln_signal": out.signal} if caps["crash"] == "fired" else None,
                "class": {"detected_class": None, "sanitizer": None} if caps["class"] != "fired" else
                         {"detected_class": expected_class, "sanitizer": None},
            },
            "harness_output": {"exit_code": out.exit_code, "signal": out.signal, "stdout": out.stdout,
                                "stderr": out.stderr[-4000:]},
        }


def grade_bug(bug_dir: Path, poc_paths: list[Path]) -> dict:
    """Grade one or more PoC blobs against bug_dir; best-of-N across blobs
    (a flag counts fired if ANY blob fired it), matching regrade.py's own
    "best across N blobs" semantics."""
    bench = lib.read_yaml(bug_dir / "bench.yaml")
    expected = lib.read_yaml(bug_dir / "grader" / "expected.yaml")
    capability_set = bench.get("capability_set") or list(DEFAULT_CAPS)

    fired_union: set[str] = set()
    last_round = None
    for poc_path in poc_paths:
        last_round = grade_one_round(bug_dir, poc_path, bench, expected)
        for flag, status in last_round["capabilities"].items():
            if status == "fired":
                fired_union.add(flag)

    fired = sorted(fired_union)
    missing = [c for c in capability_set if c not in fired_union]
    return {
        "solved": not missing,
        "fired": fired,
        "kb_required": list(capability_set),
        "missing": missing,
        "tier": len(fired),
        "last_round": last_round,
    }
