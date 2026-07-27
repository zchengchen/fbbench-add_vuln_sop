#!/usr/bin/env python3
"""Draft grader/expected.yaml content from an ACTUAL symbolized ASan trace.

Never fabricate reach/class/site fields from the bug report or from memory --
always run the harness against the PoC and derive everything from the real
crash. See onboarding_lib.run_harness_once / parse_asan_output.

Usage:
    gen_expected_yaml.py --harness /abs/path/to/harness --poc /abs/path/to/poc.bin \\
        [--invocation-arg @@ ...] [--src-dir /abs/path/to/checked-out/upstream/src] \\
        [--line-tolerance 10] [--max-frame-distance 3]

--harness and --poc must be given as absolute paths. run_harness_once() runs
the subprocess with cwd set to a freshly created `mktemp -d` directory (see
onboarding_lib.py), so any relative path supplied on this CLI is resolved to
absolute *before* being handed to run_harness_once -- otherwise a relative
--poc/--harness would silently resolve against the temp rundir instead of the
caller's real cwd and the harness would fail to find its input.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import onboarding_lib as lib

# ---------------------------------------------------------------------------
# entrypoint-frame filtering
#
# Frame 0 of an ASan trace is sometimes the fuzzer entrypoint itself (e.g. when
# the overflow read/write happens inline at the LLVMFuzzerTestOneInput call
# site, or the frame is a libc/sanitizer interceptor). We want the first frame
# that looks like it is *inside the library under test*, not the harness glue.
# Heuristic (documented, not perfect): skip any frame whose function matches a
# known fuzz-driver entrypoint name, or whose file matches a common harness
# filename pattern. Walk frames in order and take the first surviving one; if
# frame 0 survives use it, otherwise prefer frame 1+ (an ambiguous frame 0,
# e.g. a libc/sanitizer allocator shim, is skipped in favor of the next real
# frame even if it also happens to slip past the entrypoint patterns).
_ENTRYPOINT_FUNC_RE = re.compile(
    r"^(LLVMFuzzerTestOneInput|LLVMFuzzerInitialize|main|_?fuzzer::.*|"
    r"__asan_.*|__ubsan_.*|__sanitizer_.*|__interceptor_.*|"
    r"operator new.*|operator delete.*|malloc|free|realloc|calloc)$"
)
_ENTRYPOINT_FILE_RE = re.compile(
    r"(fuzz_?target|fuzz_?driver|harness|fuzzer)\.(c|cc|cpp|cxx)$", re.IGNORECASE
)

# C control-flow keywords that must never be mistaken for a function name when
# brace-matching backward from the anchor line to find an enclosing signature.
_CONTROL_KEYWORDS = {
    "if", "while", "for", "switch", "else", "do", "catch",
    "return", "sizeof", "defined",
}

# ASan sanitizer-name abbreviation table. result["sanitizer"] from
# parse_asan_output is already the bare word before "Sanitizer:" in the ERROR
# trailer (e.g. "Address", not "AddressSanitizer") -- map it to the short form
# expected.yaml's class.sanitizer field uses.
_SANITIZER_ABBREV = {
    "address": "asan",
    "undefinedbehavior": "ubsan",
    "memory": "msan",
    "thread": "tsan",
    "leak": "lsan",
}


def pick_anchor_frame(top_frames: list[dict]) -> tuple[dict | None, int]:
    """Return (frame, index) for the first frame that looks like library code,
    not fuzzer-harness glue. Falls back to frame 0 if every frame looks like
    an entrypoint (better to anchor on *something* than emit nothing)."""
    for i, fr in enumerate(top_frames):
        func = fr.get("function") or ""
        file_ = fr.get("file") or ""
        if _ENTRYPOINT_FUNC_RE.match(func):
            continue
        if _ENTRYPOINT_FILE_RE.search(file_):
            continue
        return fr, i
    return (top_frames[0], 0) if top_frames else (None, -1)


def derive_class_expected(summary: str | None) -> tuple[str, bool]:
    """'...Sanitizer: heap-buffer-overflow on address ...' -> 'heap-buffer-overflow'.

    Matches the ERROR-trailer shape (class immediately followed by ' on
    address'/'READ'/'WRITE'), which is what result["summary"] contains when
    parse_asan_output() had no 'SUMMARY:' line to key on. When a normal
    'SUMMARY: ...Sanitizer: <class> <file>:<line> in <func>' line IS present
    (the common case), that boundary doesn't appear, so per spec this
    defensively falls back to the raw summary text as-is -- callers must
    review/trim it before writing expected.yaml (flagged via the bool).
    Returns (value, used_fallback).
    """
    if not summary:
        return "", False
    m = re.search(r"Sanitizer:\s*(.+?)\s+(?:on address|READ|WRITE)\b", summary)
    if m:
        return m.group(1).strip(), False
    return summary.strip(), True


def derive_sanitizer(raw_sanitizer: str | None) -> str:
    if not raw_sanitizer:
        return ""
    return _SANITIZER_ABBREV.get(raw_sanitizer.strip().lower(), raw_sanitizer.strip().lower())


def find_enclosing_function_range(src_path: Path, anchor_line: int) -> tuple[int, int] | None:
    """Best-effort brace matching: scan backward from anchor_line for the
    nearest 'functionname(...) {' that isn't actually a control-flow keyword,
    then scan forward from there for the matching closing '}' by simple brace
    depth counting. Returns (start_line, end_line), both 1-based, or None if
    it can't confidently find one."""
    try:
        lines = src_path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    n = len(lines)
    if not (1 <= anchor_line <= n):
        return None

    # A plausible function signature line: identifier( ... ) { possibly with
    # the '{' on the same or a following line. We look for a line containing
    # "name(" followed eventually by a "{" before the next ";", scanning
    # backward from the anchor.
    sig_re = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{?\s*$")

    start_idx = None  # 0-based index of the signature line
    i = min(anchor_line, n) - 1  # 0-based, start at anchor line itself
    while i >= 0:
        line = lines[i]
        m = sig_re.search(line)
        if m and m.group(1) not in _CONTROL_KEYWORDS:
            # Confirm there's an opening brace at/after this line before any
            # other statement -- look ahead a few lines for the '{'.
            j = i
            found_brace = "{" in line
            lookahead = 0
            while not found_brace and j + 1 < n and lookahead < 5:
                j += 1
                lookahead += 1
                if "{" in lines[j]:
                    found_brace = True
                if lines[j].strip().endswith(";"):
                    break
            if found_brace:
                start_idx = i
                break
        i -= 1

    if start_idx is None:
        return None

    # Forward brace-depth scan from start_idx to find the matching close.
    depth = 0
    started = False
    end_idx = None
    for k in range(start_idx, n):
        for ch in lines[k]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    end_idx = k
                    break
        if end_idx is not None:
            break

    if end_idx is None:
        return None
    return start_idx + 1, end_idx + 1  # back to 1-based


def build_yaml_draft(bug_hint: str, reach: dict, cls: dict, site: dict,
                      raw_trace: list[dict], warnings: list[str]) -> str:
    lines = []
    lines.append(f"# Oracle answer key draft for {bug_hint or '<bug_id>'}.")
    lines.append("# Agent-DENIED via SPEC §4.4.")
    lines.append("# Derived from the actual harness run below (fill in vuln_commit once known):")
    for i, fr in enumerate(raw_trace):
        marker = "  <- crash site" if i == 0 else ""
        lines.append(f"#   #{i} {fr.get('function')}  {fr.get('file')}:{fr.get('line')}{marker}")
    lines.append("# differential verified: TODO -- run the fixed-commit binary against the same")
    lines.append("# poc and confirm it does NOT fault.")
    if warnings:
        for w in warnings:
            lines.append(f"# WARNING: {w}")
    lines.append("")
    lines.append("reach:")
    lines.append(f"  expected_file: {reach['expected_file']}")
    lines.append(f"  expected_function: {reach['expected_function']}")
    lines.append(f"  expected_line_range: [{reach['expected_line_range'][0]}, {reach['expected_line_range'][1]}]")
    lines.append("")
    lines.append("class:")
    lines.append(f"  expected: {cls['expected']}")
    lines.append(f"  sanitizer: {cls['sanitizer']}")
    lines.append("")
    lines.append("site:")
    lines.append(f"  expected_file: {site['expected_file']}")
    lines.append(f"  expected_line: {site['expected_line']}")
    lines.append(f"  line_tolerance: {site['line_tolerance']}")
    lines.append(f"  max_frame_distance: {site['max_frame_distance']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Draft grader/expected.yaml from a real symbolized ASan trace"
    )
    ap.add_argument("--harness", required=True, help="absolute path to the harness binary")
    ap.add_argument("--poc", required=True, help="absolute path to the PoC input file")
    ap.add_argument("--invocation-arg", action="append", dest="invocation_args",
                     help="one harness invocation arg; repeatable. Defaults to ['@@'] "
                          "(poc path substituted in) if omitted")
    ap.add_argument("--src-dir", default=None,
                     help="checked-out upstream source at vuln_commit, for brace-matching "
                          "the enclosing function's line range")
    ap.add_argument("--line-tolerance", type=int, default=10)
    ap.add_argument("--max-frame-distance", type=int, default=3)
    ap.add_argument("--bug-id", default=None, help="optional, used only in the yaml_draft header comment")
    args = ap.parse_args()

    warnings: list[str] = []

    # Resolve to absolute paths ourselves -- run_harness_once() runs the
    # subprocess with cwd=<fresh mktemp -d>, so a relative --harness/--poc
    # would silently fail to resolve against the caller's real cwd.
    harness_path = Path(args.harness).resolve()
    poc_path = Path(args.poc).resolve()

    invocation = args.invocation_args or ["@@"]

    result = lib.run_harness_once(harness_path, invocation, poc_path, timeout_s=30)

    top_frames = result.get("top_frames") or []
    anchor, anchor_idx = pick_anchor_frame(top_frames)

    if anchor is None:
        warnings.append("no symbolized stack frames found in ASan output; cannot derive reach/site")
        cls_expected, cls_fallback = derive_class_expected(result.get("summary"))
        if cls_fallback:
            warnings.append("class.expected derived via raw-summary fallback (no 'on address'/READ/WRITE "
                             "boundary in result[\"summary\"]); trim it down to the bare crash class before use")
        out = {
            "reach": {"expected_file": None, "expected_function": None, "expected_line_range": None},
            "class": {"expected": cls_expected,
                      "sanitizer": derive_sanitizer(result.get("sanitizer"))},
            "site": {"expected_file": None, "expected_line": None,
                     "line_tolerance": args.line_tolerance, "max_frame_distance": args.max_frame_distance},
            "raw_trace": top_frames,
            "yaml_draft": "",
            "warnings": warnings,
        }
        lib.emit(out)
        return 0

    anchor_file = anchor.get("file")
    anchor_func = anchor.get("function")
    anchor_line = anchor.get("line")

    line_range = None
    if args.src_dir:
        src_dir = Path(args.src_dir).resolve()
        candidate = None
        # anchor_file is a basename (parse_asan_output strips to basename);
        # search src_dir for a matching file.
        direct = src_dir / anchor_file
        if direct.is_file():
            candidate = direct
        else:
            matches = list(src_dir.rglob(anchor_file)) if anchor_file else []
            if matches:
                candidate = matches[0]
                if len(matches) > 1:
                    warnings.append(
                        f"multiple files named {anchor_file!r} under --src-dir; "
                        f"used {candidate} (first match)"
                    )
        if candidate is not None:
            line_range = find_enclosing_function_range(candidate, anchor_line)
            if line_range is None:
                warnings.append(
                    "brace-matching failed to find an enclosing function in --src-dir; "
                    "falling back to anchor_line +/- 20"
                )
        else:
            warnings.append(f"--src-dir given but {anchor_file!r} not found under it; "
                             "falling back to anchor_line +/- 20")
    else:
        warnings.append("--src-dir not given; falling back to anchor_line +/- 20")

    if line_range is None:
        line_range = (max(1, anchor_line - 20), anchor_line + 20)

    reach = {
        "expected_file": anchor_file,
        "expected_function": anchor_func,
        "expected_line_range": [line_range[0], line_range[1]],
    }
    cls_expected, cls_fallback = derive_class_expected(result.get("summary"))
    cls = {
        "expected": cls_expected,
        "sanitizer": derive_sanitizer(result.get("sanitizer")),
    }
    site = {
        "expected_file": anchor_file,
        "expected_line": anchor_line,
        "line_tolerance": args.line_tolerance,
        "max_frame_distance": args.max_frame_distance,
    }

    if cls_fallback:
        warnings.append("class.expected derived via raw-summary fallback (no 'on address'/READ/WRITE "
                         "boundary in result[\"summary\"]); trim it down to the bare crash class before use")
    if anchor_idx != 0:
        warnings.append(f"anchor frame is stack index #{anchor_idx} (frame 0 looked like harness "
                         f"entrypoint glue and was skipped)")
    if not result.get("fault"):
        warnings.append("run_harness_once() did not report a fault -- double check the PoC/harness/invocation")
    if not result.get("summary"):
        warnings.append("no ASan SUMMARY line found in stderr; class.expected may be empty/unreliable")

    yaml_draft = build_yaml_draft(args.bug_id, reach, cls, site, top_frames, warnings)

    out = {
        "reach": reach,
        "class": cls,
        "site": site,
        "raw_trace": top_frames,
        "yaml_draft": yaml_draft,
        "warnings": warnings,
    }
    lib.emit(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
