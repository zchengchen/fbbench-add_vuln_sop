#!/usr/bin/env python3
"""Reproduce a candidate commit's crash via OSS-Fuzz's infra/helper.py.

Temporarily patches the target project's Dockerfile so its upstream clone
checks out a specific candidate SHA, builds the fuzzer with ASan, reproduces
a testcase against it, parses the ASan output, and ALWAYS restores the
original Dockerfile afterward (even on error) -- the Dockerfile on disk must
never be left in a patched state.

Confirmed by reading oss-fuzz/infra/helper.py directly:
  build_fuzzers_parser: positional 'project', optional positional
    'source_path' (nargs='?', unused here), and '--sanitizer' added via
    _add_sanitizer_args() with default=None (help text: 'the default is
    "address"' -- so we always pass --sanitizer address explicitly).
    Invocation: python3 infra/helper.py build_fuzzers --sanitizer address <project>
  reproduce_parser: positional 'project', 'fuzzer_name', 'testcase_path',
    then 'fuzzer_args' (nargs='*', unused here).
    Invocation: python3 infra/helper.py reproduce <project> <fuzzer> <testcase>
Both run with cwd = the oss-fuzz repo root.
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

import onboarding_lib

# ---------------------------------------------------------------------------
# Dockerfile clone/checkout patching
#
# Real oss-fuzz Dockerfiles vary: some clone exactly one repo (libxml2, re2),
# some clone a dependency BEFORE the target repo (libphonenumber clones
# googletest/protobuf/abseil-cpp before or after its own plain
# `git clone .../libphonenumber` line with no explicit dest dir), some chain
# `git clone URL && cd DEST && git checkout REF` across backslash-continued
# lines (xnu's SockFuzzer clone). A naive "patch the first git clone line"
# is wrong for all of the multi-clone cases, and naive `str.split()` on the
# clone line is wrong once `--depth 1` / `--branch X` flags are present
# (the flag's value token would be mistaken for the destination directory).
# So: a tiny custom tokenizer walks the RUN block char-by-char (tracking
# original-file offsets so edits can be spliced back in place), a bounded
# list of git-clone flags that consume a following value is used to skip
# past flag values when hunting for the positional dest-dir argument, and
# the resulting clone destination directory name is matched against
# --project (both normalized) to pick the right clone among several.

# git-clone flags known to consume a following value token (so that value
# isn't mistaken for the positional <repository> or <directory> argument).
_VALUE_FLAGS = {
    "--depth", "--branch", "-b", "--origin", "-o", "--config", "-c",
    "--reference", "--reference-if-able", "--shallow-since",
    "--shallow-exclude", "--template", "--separate-git-dir", "--jobs", "-j",
    "--filter", "--upload-pack", "-u", "--server-option",
}

# Flags that make the clone's history incomplete -- pinning an arbitrary sha
# with `git checkout` after one of these is present fails with "fatal:
# reference is not a tree", since the commit object was never fetched. Real
# example hit in production: oss-fuzz's libxml2 Dockerfile does
# `git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git`. These
# must be stripped from the clone invocation itself (not just skipped over
# while hunting for the url/dest positionals) so the clone becomes full,
# matching the SOP's explicit "full-clone upstream (no --depth)" rule.
_SHALLOW_FLAGS = {"--depth", "--shallow-since", "--shallow-exclude"}

_RUN_LINE_RE = re.compile(r"^RUN\b", re.IGNORECASE)


def _find_run_blocks(content: str):
    """Return [(start, end, text)] for each RUN instruction, including its
    backslash-continued lines.

    Deliberately NOT a single `.*(?:\\\\\\n.*)*`-style regex: with a greedy
    `.*` consuming a line's trailing backslash and no DOTALL, Python's re
    engine finds the trailing `(?:...)* ` satisfiable with zero repetitions
    (an empty match is a valid match for a star group) before it ever needs
    to backtrack `.*` off that backslash -- so it silently stops after the
    first line instead of continuing across the continuation. Plain
    line-by-line scanning avoids that trap entirely.
    """
    lines = content.splitlines(keepends=True)
    offsets = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln)
    blocks = []
    i, n = 0, len(lines)
    while i < n:
        body = lines[i].rstrip("\r\n")
        if _RUN_LINE_RE.match(body):
            start = offsets[i]
            j = i
            while body.rstrip().endswith("\\"):
                j += 1
                if j >= n:
                    break
                body = lines[j].rstrip("\r\n")
            end_line = j if j < n else n - 1
            end = offsets[end_line] + len(lines[end_line])
            blocks.append((start, end, content[start:end]))
            i = end_line + 1
        else:
            i += 1
    return blocks


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _url_basename(url: str) -> str:
    base = (url or "").rstrip("/").split("/")[-1]
    if base.endswith(".git"):
        base = base[:-4]
    return base


def _tokenize_with_offsets(text: str):
    """Split shell-ish text into (token, start, end) triples.

    Treats backslash-newline as pure whitespace (matching real shell line
    continuation semantics, which Dockerfile RUN instructions rely on) and
    '&&' as its own token so callers can segment the command chain.
    """
    tokens = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "\\" and text[i + 1:i + 2] in ("\n", "\r"):
            i += 2
            if text[i - 1:i] == "\r" and text[i:i + 1] == "\n":
                i += 1
            continue
        if text[i:i + 2] == "&&":
            tokens.append(("&&", i, i + 2))
            i += 2
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 1
            j = min(j + 1, n)
            tokens.append((text[i:j], i, j))
            i = j
            continue
        j = i
        while j < n and text[j] not in " \t\r\n\"'" and text[j:j + 2] != "&&" and not (
            text[j] == "\\" and text[j + 1:j + 2] in ("\n", "\r")
        ):
            j += 1
        if j == i:
            j += 1
        tokens.append((text[i:j], i, j))
        i = j
    return tokens


def _split_segments(tokens):
    """Split a flat token list on literal '&&' tokens into sub-command segments."""
    segments, cur = [], []
    for tok, s, e in tokens:
        if tok == "&&":
            segments.append(cur)
            cur = []
        else:
            cur.append((tok, s, e))
    segments.append(cur)
    return segments


def _analyze_block(block_text: str):
    """Find every `git clone` sub-command in one RUN block.

    Returns a list of dicts (offsets relative to block_text):
      {url, dest, clone_end, checkout_ref_span (start,end)|None, seg_index}
    """
    segments = _split_segments(_tokenize_with_offsets(block_text))
    results = []
    for idx, seg in enumerate(segments):
        toks = [t[0] for t in seg]
        # The first segment of a block is prefixed by the 'RUN' keyword
        # itself, so look for a 'git','clone' pair anywhere in the segment
        # rather than requiring it at position 0.
        clone_at = None
        for k in range(len(toks) - 1):
            if toks[k] == "git" and toks[k + 1] == "clone":
                clone_at = k
                break
        if clone_at is None:
            continue
        positionals = []
        shallow_flag_spans = []
        i = clone_at + 2
        while i < len(seg):
            tok = seg[i][0]
            if tok.startswith("-"):
                bare = tok.split("=", 1)[0]
                if "=" in tok:
                    if bare in _SHALLOW_FLAGS:
                        shallow_flag_spans.append((seg[i][1], seg[i][2]))
                    i += 1
                    continue
                if tok in _VALUE_FLAGS:
                    if tok in _SHALLOW_FLAGS and i + 1 < len(seg):
                        shallow_flag_spans.append((seg[i][1], seg[i + 1][2]))
                    elif tok in _SHALLOW_FLAGS:
                        shallow_flag_spans.append((seg[i][1], seg[i][2]))
                    i += 2
                    continue
                i += 1
                continue
            positionals.append(seg[i])
            i += 1
        if not positionals:
            continue
        url = positionals[0][0]
        dest = positionals[1][0] if len(positionals) > 1 else _url_basename(url)
        clone_end = seg[-1][2]

        # Look forward through later segments in this same block for the
        # first `git checkout <ref>`, but stop (treat as "no checkout") if
        # we hit another `git clone` first -- that checkout would belong to
        # a different repo, not this one.
        checkout_ref_span = None
        for later in segments[idx + 1:]:
            later_toks = [t[0] for t in later]
            if len(later_toks) >= 2 and later_toks[0] == "git" and later_toks[1] == "clone":
                break
            if len(later_toks) >= 3 and later_toks[0] == "git" and later_toks[1] == "checkout":
                checkout_ref_span = (later[2][1], later[2][2])
                break
        results.append({
            "url": url,
            "dest": dest,
            "clone_end": clone_end,
            "checkout_ref_span": checkout_ref_span,
            "shallow_flag_spans": shallow_flag_spans,
            "seg_index": idx,
        })
    return results


def _apply_edits(text: str, edits: list[tuple[int, int, str]]) -> str:
    """Apply non-overlapping (start, end, replacement) edits to text.

    Processes rightmost-first so earlier (leftward) edits' offsets stay
    valid throughout -- lets shallow-flag removals and the checkout
    insertion/replacement be combined into one pass over the same block.
    """
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        text = text[:start] + repl + text[end:]
    return text


def patch_dockerfile(content: str, project: str, sha: str, clone_line_regex: str | None):
    """Return (patched_content, meta) with the target clone's checkout pinned to sha."""
    blocks = _find_run_blocks(content)
    if not blocks:
        raise ValueError("no RUN instructions found in Dockerfile")

    candidates = []  # (block_start, block_end, block_text, clone_info)
    for bstart, bend, btext in blocks:
        for info in _analyze_block(btext):
            candidates.append((bstart, bend, btext, info))
    if not candidates:
        raise ValueError("no `git clone` commands found in any RUN instruction")

    chosen = None
    if clone_line_regex:
        pattern = re.compile(clone_line_regex)
        m = pattern.search(content)
        if not m:
            raise ValueError(f"--clone-line-regex {clone_line_regex!r} matched nothing in Dockerfile")
        for bstart, bend, btext, info in candidates:
            if bstart <= m.start() < bend:
                chosen = (bstart, bend, btext, info)
                break
        if chosen is None:
            raise ValueError("--clone-line-regex matched, but not inside any recognized `git clone` command")
    else:
        proj_norm = _normalize(project)
        for bstart, bend, btext, info in candidates:
            if _normalize(info["dest"]) == proj_norm:
                chosen = (bstart, bend, btext, info)
                break
        if chosen is None:
            # Fall back to source order, per spec.
            chosen = candidates[0]

    bstart, bend, btext, info = chosen
    edits = [(s, e, "") for (s, e) in info.get("shallow_flag_spans", [])]
    if info["checkout_ref_span"] is not None:
        rs, re_ = info["checkout_ref_span"]
        edits.append((rs, re_, sha))
        action = "replaced_checkout"
    else:
        insertion = f" && cd {info['dest']} && git checkout {sha}"
        pos = info["clone_end"]
        edits.append((pos, pos, insertion))
        action = "inserted_checkout"

    new_block = _apply_edits(btext, edits)
    new_content = content[:bstart] + new_block + content[bend:]
    meta = {
        "action": action,
        "matched_dest": info["dest"],
        "matched_url": info["url"],
        "stripped_shallow_flags": bool(info.get("shallow_flag_spans")),
    }
    return new_content, meta


# ---------------------------------------------------------------------------
# subprocess helpers


def _run(cmd, cwd, timeout_s):
    """Run cmd, returning (returncode, combined_text, timed_out)."""
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout_s)
        return p.returncode, (p.stdout or "") + (p.stderr or ""), False
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"") if isinstance(e.stdout, (bytes, bytearray)) else (e.stdout or "")
        err = (e.stderr or b"") if isinstance(e.stderr, (bytes, bytearray)) else (e.stderr or "")
        if isinstance(out, (bytes, bytearray)):
            out = out.decode("utf-8", "replace")
        if isinstance(err, (bytes, bytearray)):
            err = err.decode("utf-8", "replace")
        return None, out + err, True


def run_build(oss_fuzz_repo: Path, project: str, timeout_s: int) -> dict:
    cmd = ["python3", "infra/helper.py", "build_fuzzers", "--sanitizer", "address", project]
    rc, text, timed_out = _run(cmd, oss_fuzz_repo, timeout_s)
    return {
        "ok": (rc == 0),
        "returncode": rc,
        "timed_out": timed_out,
        "log_tail": text[-900:],
    }


def run_reproduce(oss_fuzz_repo: Path, project: str, fuzzer: str, testcase: str, timeout_s: int) -> dict:
    cmd = ["python3", "infra/helper.py", "reproduce", project, fuzzer, testcase]
    rc, text, timed_out = _run(cmd, oss_fuzz_repo, timeout_s)
    parsed = onboarding_lib.parse_asan_output(text)
    crashed = bool((rc is not None and rc != 0) or parsed["summary"] is not None)
    return {
        "ok": not timed_out,
        "returncode": rc,
        "timed_out": timed_out,
        "crashed": crashed,
        "asan_summary": parsed["summary"],
        "top_frames": parsed["top_frames"],
        "log_tail": text[-900:],
    }


# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--oss-fuzz-repo", default=None)
    ap.add_argument("--project", required=True)
    ap.add_argument("--fuzzer", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--testcase", required=True)
    ap.add_argument("--build-timeout-s", type=int, default=1800)
    ap.add_argument("--reproduce-timeout-s", type=int, default=120)
    ap.add_argument("--clone-line-regex", default=None)
    args = ap.parse_args()

    oss_fuzz_repo = Path(args.oss_fuzz_repo).resolve() if args.oss_fuzz_repo else onboarding_lib.find_repo_paths().oss_fuzz
    dockerfile_path = oss_fuzz_repo / "projects" / args.project / "Dockerfile"

    result = {
        "project": args.project,
        "sha": args.sha,
        "fuzzer": args.fuzzer,
        "dockerfile_patched": False,
        "dockerfile_restored": False,
        "build": None,
        "reproduce": None,
    }

    try:
        original_text = dockerfile_path.read_text()
    except Exception as e:
        result["error"] = f"failed to read Dockerfile at {dockerfile_path}: {e}"
        onboarding_lib.emit(result)
        return

    try:
        patched_text, patch_meta = patch_dockerfile(original_text, args.project, args.sha, args.clone_line_regex)
    except Exception as e:
        result["error"] = f"failed to patch Dockerfile: {e}"
        onboarding_lib.emit(result)
        return

    # Only touch the file once we know the patch succeeded.
    dockerfile_path.write_text(patched_text)
    result["dockerfile_patched"] = True
    result["patch_meta"] = patch_meta

    try:
        build_result = run_build(oss_fuzz_repo, args.project, args.build_timeout_s)
        result["build"] = build_result
        if build_result["ok"]:
            result["reproduce"] = run_reproduce(
                oss_fuzz_repo, args.project, args.fuzzer, args.testcase, args.reproduce_timeout_s
            )
        else:
            result["reproduce"] = None
    except Exception as e:
        if result["build"] is None:
            result["build"] = {"ok": False, "error": str(e)}
        result["reproduce"] = None
    finally:
        try:
            dockerfile_path.write_text(original_text)
            result["dockerfile_restored"] = True
        except Exception:
            result["dockerfile_restored"] = False

    onboarding_lib.emit(result)


if __name__ == "__main__":
    main()
