#!/usr/bin/env python3
"""Post-build leak/scrub audit against a FINAL BUILT public challenge image.

tools/sealed/build_challenge.py already leak-audits its *pre-build* bundle
(no poc/grader/binaries dirs, no expected.yaml, no fix_commit/fix_patch in
bench.yaml) before it ever calls `docker build`. This script is the
independent, belt-and-suspenders check against the image that actually comes
out the other end -- run `docker run` against the real thing rather than
trusting the build-time context was what actually got COPYed in.
"""
from __future__ import annotations

import argparse
import subprocess

import onboarding_lib as lib

EXPECTED_BENCH_VARS = ["BENCH_BUG_ID", "BENCH_GRADE_URL", "BENCH_BUG_DIR", "BENCH_WORKSPACE"]

# docker-CLI-level failures (daemon unreachable, no such image, exec into a
# container that never started, ...) vs. an in-container command's own
# nonzero exit (e.g. `grep -rl` exiting 1 for "no matches", or `find`
# exiting 1 on a permission error inside the image) -- only the former should
# count as an execution error for `ok`.
DOCKER_CLI_ERROR_MARKERS = (
    "Cannot connect to the Docker daemon",
    "No such image",
    "Unable to find image",
    "docker: Error response from daemon",
    "is not running",
)


def _run(cmd: list[str], timeout: int = 300) -> tuple[str, str, int, bool]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout, stderr, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = (e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return stdout, stderr + "\n[timeout]", -1, True
    is_cli_error = rc == 125 or any(marker in stderr for marker in DOCKER_CLI_ERROR_MARKERS)
    return stdout, stderr, rc, is_cli_error


def docker_bash(image: str, script: str, timeout: int = 300) -> tuple[list[str], bool, str]:
    """Run `bash -c <script>` inside `image`. Returns (nonblank stdout lines, error, stderr)."""
    stdout, stderr, rc, is_cli_error = _run(["docker", "run", "--rm", image, "bash", "-c", script], timeout)
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    return lines, is_cli_error, stderr


def verify(image: str, expected_function: str, src_file_count_before: int | None,
           fresh_pull: bool) -> dict:
    errors: list[str] = []

    if fresh_pull:
        _, stderr, rc, is_cli_error = _run(["docker", "pull", image], timeout=900)
        if rc != 0:
            errors.append(f"docker pull failed: {stderr.strip()[-1000:]}")

    leak_lines, err, stderr = docker_bash(
        image,
        # vuln.yaml is the hidden T2 category answer introduced by the new
        # answers-repo layout — it must never appear in a public image, so it
        # is part of the leak set alongside poc/expected.yaml/grader/binaries.
        # (A bare `-iname build` is deliberately NOT included: upstream source
        # trees legitimately carry build/ dirs and would false-positive.)
        "find /challenge -iname 'poc*' -o -iname 'expected.yaml' -o -iname 'vuln.yaml' -o -iname grader -o -iname binaries",
    )
    if err:
        errors.append(f"leak-find execution error: {stderr.strip()[-500:]}")
    leak_find_empty = not leak_lines

    env_lines, err, stderr = docker_bash(image, "env | grep BENCH")
    if err:
        errors.append(f"env-grep execution error: {stderr.strip()[-500:]}")
    bench_env_vars = sorted({ln.split("=", 1)[0] for ln in env_lines if "=" in ln} & set(EXPECTED_BENCH_VARS))

    changelog_lines, err, stderr = docker_bash(
        image,
        'find /challenge -iname "NEWS*" -o -iname "CHANGELOG*" -o -iname "SECURITY*"',
    )
    if err:
        errors.append(f"changelog-find execution error: {stderr.strip()[-500:]}")
    changelog_files_found = changelog_lines

    grep_lines, err, stderr = docker_bash(image, f"grep -rl '{expected_function}' /challenge")
    if err:
        errors.append(f"function-grep execution error: {stderr.strip()[-500:]}")
    function_grep_hits = grep_lines

    count_lines, err, stderr = docker_bash(
        image, "find /challenge/src -name '*.c' -o -name '*.h' | wc -l",
    )
    if err:
        errors.append(f"src-file-count execution error: {stderr.strip()[-500:]}")
    src_file_count_after = None
    if count_lines:
        try:
            src_file_count_after = int(count_lines[-1].strip())
        except ValueError:
            errors.append(f"src-file-count did not parse an int: {count_lines[-1]!r}")

    src_file_count_matches = None
    if src_file_count_before is not None:
        src_file_count_matches = src_file_count_after == src_file_count_before

    ok = (
        leak_find_empty
        and not changelog_files_found
        and (src_file_count_before is None or src_file_count_matches)
        and not errors
    )

    return {
        "leak_find_empty": leak_find_empty,
        "bench_env_vars": bench_env_vars,
        "changelog_files_found": changelog_files_found,
        "function_grep_hits": function_grep_hits,
        "src_file_count_after": src_file_count_after,
        "src_file_count_matches": src_file_count_matches,
        "errors": errors,
        "ok": ok,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Post-build leak/scrub audit of a FINAL BUILT public challenge image "
                    "(complements build_challenge.py's pre-build bundle audit)."
    )
    ap.add_argument("--image", required=True, help="docker tag of the built challenge image")
    ap.add_argument("--expected-function", required=True,
                     help="vulnerable function name -- grep hits should be confined to source files")
    ap.add_argument("--src-file-count-before", type=int, default=None,
                     help="expected count of .c/.h files under /challenge/src, if known")
    ap.add_argument("--fresh-pull", action="store_true", help="docker pull the image before auditing")
    args = ap.parse_args()

    result = verify(args.image, args.expected_function, args.src_file_count_before, args.fresh_pull)
    lib.emit(result)


if __name__ == "__main__":
    main()
