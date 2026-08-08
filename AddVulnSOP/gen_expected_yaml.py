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

# Span bounds for a believable function body, used only to route a range to the
# finalize agent for confirmation -- neither end is an error. Real functions do
# sit outside them (the corpus holds a 5-line one and an 1801-line one), but a
# range this far from the 61-line median is more often the brace matcher having
# latched onto an inner block or run past the closing brace.
MIN_PLAUSIBLE_SPAN = 8
MAX_PLAUSIBLE_SPAN = 1200

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
    an entrypoint (better to anchor on *something* than emit nothing).

    Drives `reach`, whose question is "did execution get here" -- harness code
    is legitimately reached, so this stays a soft heuristic. `site` has a
    stricter rule of its own; see pick_site_frame."""
    for i, fr in enumerate(top_frames):
        func = fr.get("function") or ""
        file_ = fr.get("file") or ""
        if _ENTRYPOINT_FUNC_RE.match(func):
            continue
        if _ENTRYPOINT_FILE_RE.search(file_):
            continue
        return fr, i
    return (top_frames[0], 0) if top_frames else (None, -1)


def is_harness_frame(frame: dict) -> bool:
    """EXACT mirror of the grading oracle's isHarnessFrame (grade.go, ported in
    native_grader.py:_is_harness_frame). These two MUST stay in lockstep.

    The oracle skips harness frames entirely when matching `site`, so a site
    anchored on one can never fire no matter how correct it looks -- the bug
    builds and reproduces, and the mis-anchored value goes unnoticed into the
    archived expected.yaml with everything already built. Keying on the full
    path is the whole point: libxml2's `api` target crashes at
    /src/harness/api.c, whose BASENAME (api.c) looks like ordinary library code.
    """
    path = frame.get("path") or frame.get("file") or ""
    return ("/harness/" in path
            or path.endswith("_fuzzer.c")
            or path.endswith("_fuzzer.cc"))


def pick_site_frame(top_frames: list[dict]) -> tuple[dict | None, int]:
    """First frame the grading oracle would actually consider for `site`.

    Deliberately has NO fallback to frame 0: if every frame is harness code,
    this bug's crash site simply is not expressible as a `site` the oracle can
    match, and saying so here is worth far more than emitting a plausible value
    that is guaranteed to fail six stages later.
    """
    for i, fr in enumerate(top_frames):
        if is_harness_frame(fr):
            continue
        return fr, i
    return None, -1


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
    it can't confidently find one.

    The range this returns is the ENCLOSING FUNCTION BODY -- reach is scored
    over the whole function named by expected_function, never over the handful
    of lines around the fault. A narrower range makes reach harder to earn than
    site, which inverts the capability ladder.

    A candidate is only accepted if its matched body actually CONTAINS
    anchor_line. Without that check the signature regex happily latches onto the
    continuation line of a multi-line condition -- `} else if ((a == b) &&\\n
    (f(x)))) {` ends in `) {` and its trailing call reads as `f(...)`, so the
    inner block gets returned as if it were the function. That produced a
    three-line reach range on a 131-line function once already (libxml2-01,
    SAX2.c:xmlSAX2Text), and nothing downstream caught it: the reference PoC
    still graded 5/5 because the oracle short-circuits `site fired => reach
    fired`, so only a NON-crashing input would ever have exposed it. When no
    candidate contains the anchor this returns None, and the caller degrades to
    an explicitly-flagged fallback rather than shipping a confident wrong
    answer."""
    try:
        lines = src_path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    n = len(lines)
    if not (1 <= anchor_line <= n):
        return None

    i = min(anchor_line, n) - 1  # 0-based, start at anchor line itself
    while i >= 0:
        if _declarator_at(lines, i, n):
            end_idx = _match_closing_brace(lines, i, n)
            # The anchor must lie inside the body, or this was an inner block
            # that merely looked like a signature -- keep scanning outward
            # instead of returning it. This check is what lets the matcher
            # above stay permissive: a false positive costs one more loop
            # iteration, never a wrong answer.
            if end_idx is not None and i + 1 <= anchor_line <= end_idx + 1:
                return i + 1, end_idx + 1  # back to 1-based
        i -= 1

    return None


# A function definition's declarator: identifier(params) [const] {, with the
# parameter list and the brace allowed to spill over the following lines. C
# wraps long parameter lists constantly (xmlSAX2Text spans two lines before its
# brace), and a single-line regex silently skips every such function -- which is
# how the scan used to walk past the real declarator and settle on an inner
# block instead.
_DEF_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{")
_DEF_JOIN_LOOKAHEAD = 6


def _declarator_at(lines: list[str], i: int, n: int) -> bool:
    """Does a function definition's declarator begin at 0-based line i?

    Deliberately permissive -- it accepts things that are not definitions (the
    tail of a wrapped `else if` condition reads as `f(x)) {`). The caller's
    containment check rejects those, so the cost of a false positive is one
    loop iteration; the cost of a false NEGATIVE would be a range anchored on
    the wrong function entirely.
    """
    joined = lines[i]
    for k in range(i + 1, min(i + 1 + _DEF_JOIN_LOOKAHEAD, n)):
        if "{" in joined or ";" in joined:
            break
        joined += " " + lines[k]
    m = _DEF_RE.search(joined)
    return bool(m and m.group(1) not in _CONTROL_KEYWORDS)


def _match_closing_brace(lines: list[str], start_idx: int, n: int) -> int | None:
    """0-based index of the '}' closing the first '{' at/after start_idx."""
    depth = 0
    started = False
    for k in range(start_idx, n):
        for ch in lines[k]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    return k
    return None


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
            "fatal": None,
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
        warnings.append(
            f"REACH RANGE NOT DERIVED: [{line_range[0]}, {line_range[1]}] is anchor_line +/- 20, "
            f"NOT the body of {anchor_func or 'the enclosing function'}. reach is scored over the "
            f"whole function; open {anchor_file} in the vuln-commit tree, find that function, and "
            f"replace the range with [declarator_line, closing_brace_line]."
        )
    else:
        span = line_range[1] - line_range[0] + 1
        if span < MIN_PLAUSIBLE_SPAN or span > MAX_PLAUSIBLE_SPAN:
            warnings.append(
                f"REACH RANGE SUSPICIOUS: [{line_range[0]}, {line_range[1]}] spans {span} lines for "
                f"{anchor_func or '<unknown>'}. Outside {MIN_PLAUSIBLE_SPAN}-{MAX_PLAUSIBLE_SPAN} the "
                f"brace matcher has usually latched onto an inner block or run past the function; "
                f"confirm it against {anchor_file} in the vuln-commit tree."
            )

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
    # `site` gets its own anchor, under the oracle's rule rather than reach's
    # looser one -- the two frames coincide for most bugs and diverge exactly
    # when the crash lands inside the harness.
    site_frame, site_idx = pick_site_frame(top_frames)
    fatal = None
    if site_frame is None:
        fatal = (
            "every symbolized frame is harness code, so no `site` the grading oracle would "
            "even look at exists for this bug (it skips harness frames outright). Anchoring "
            "site here would produce an expected.yaml that can never grade solved. Either "
            "move the crashing logic out of the harness, or drop `site` from this bug's "
            f"capability_set. Frames seen: {[f.get('path') or f.get('file') for f in top_frames]}"
        )
    site = {
        "expected_file": (site_frame or {}).get("file"),
        "expected_line": (site_frame or {}).get("line"),
        "line_tolerance": args.line_tolerance,
        "max_frame_distance": args.max_frame_distance,
    }
    if site_frame is not None and site_frame is not anchor:
        warnings.append(
            f"site is anchored on frame #{site_idx} ({site_frame.get('path') or site_frame.get('file')}"
            f":{site_frame.get('line')} in {site_frame.get('function')}), NOT on reach's frame "
            f"#{anchor_idx} ({anchor_file}:{anchor_line}) -- the frames before it are harness code, "
            f"which the grading oracle skips when matching site."
        )

    # reach must contain site whenever both name the same file. They legitimately
    # differ when the fault surfaces in shared plumbing (a memcpy interceptor, an
    # allocator, a header accessor) while the bug lives in the caller -- 7 of the
    # corpus's bugs are that shape. Same file but site outside the range is not
    # that case; it means the range is wrong, and it is invisible in grading
    # because `site fired => reach fired` short-circuits ahead of the coverage
    # probe, so the reference PoC still scores 5/5.
    if (site["expected_file"] and reach["expected_file"]
            and Path(site["expected_file"]).name == Path(reach["expected_file"]).name
            and site["expected_line"] is not None
            and not (line_range[0] <= site["expected_line"] <= line_range[1])):
        warnings.append(
            f"REACH RANGE EXCLUDES THE CRASH LINE: site is {site['expected_file']}:"
            f"{site['expected_line']} but reach covers only [{line_range[0]}, {line_range[1]}] of the "
            f"same file. An input can then crash at the expected site without being credited with "
            f"reaching it. Widen the range to the body of {anchor_func or 'the enclosing function'}."
        )

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
        # Non-null means the draft could not be anchored. expected.yaml is
        # archival now, so the pipeline stage downgrades this to a warning
        # rather than ending the run -- see stage_gen_expected_yaml.
        "fatal": fatal,
    }
    lib.emit(out)
    return 1 if fatal else 0


if __name__ == "__main__":
    raise SystemExit(main())
