#!/usr/bin/env python3
"""Structural audit of a FINAL BUILT public challenge image.

One question, deliberately coarse: is anything BIG missing? A challenge
image is only five things -- /challenge/{src,harness,bench.yaml,
description.txt} plus the /usr/local/bin/mcp-server client. Lose any one and
the challenge is unusable: no source to read, no harness to target, no
metadata for the runner, or no way to submit at all. Answered by looking
INSIDE the built image (`docker run`), since a clean build context says
nothing about what the Dockerfile actually COPYed in.

Nothing finer, and nothing else. Earlier revisions also diffed the .c/.h
file count across the changelog scrub, failed on any file merely NAMED
changelog*/NEWS* (which false-positives on upstream test fixtures -- libxml2
ships test/schemas/changelog093_* and test/valid/dtds/NewsMLv1.2.dtd), and
re-ran a leak scan. All dropped: the first two are file-level bookkeeping
rather than "is the bundle intact", and answer-leak coverage already happens
before the build, in tools/sealed/build_challenge.py's own leak_audit() over
the staged bundle.
"""
from __future__ import annotations

import argparse
import subprocess

import onboarding_lib as lib

# docker-CLI-level failures (daemon unreachable, no such image, exec into a
# container that never started, ...) vs. an in-container command's own
# nonzero exit (e.g. `find` exiting 1 on a permission error inside the
# image) -- only the former should count as an execution error.
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


# The five things every challenge image must ship. `kind` picks the test:
# "dir" = exists and holds at least one file; "file" = exists as a file.
REQUIRED = [
    ("/challenge/src", "dir"),
    ("/challenge/harness", "dir"),
    ("/challenge/bench.yaml", "file"),
    ("/challenge/description.txt", "file"),
    ("/usr/local/bin/mcp-server", "file"),
]


def verify(image: str, fresh_pull: bool = False) -> dict:
    errors: list[str] = []

    if fresh_pull:
        _, stderr, rc, _ = _run(["docker", "pull", image], timeout=900)
        if rc != 0:
            errors.append(f"docker pull failed: {stderr.strip()[-1000:]}")

    # One container, one line per required path: "<path>=<file count>".
    # A directory reports how many files it holds; a file reports 1 or 0.
    probe = "; ".join(
        f"printf '%s=%s\\n' {path} "
        + (f"\"$(find {path} -type f 2>/dev/null | wc -l)\"" if kind == "dir"
           else f"\"$([ -f {path} ] && echo 1 || echo 0)\"")
        for path, kind in REQUIRED
    )
    lines, err, stderr = docker_bash(image, probe)
    if err:
        errors.append(f"structure-probe execution error: {stderr.strip()[-500:]}")

    counts: dict[str, int] = {}
    for ln in lines:
        path, _, raw = ln.rpartition("=")
        try:
            counts[path.strip()] = int(raw.strip())
        except ValueError:
            pass

    structure = {path: counts.get(path, 0) for path, _ in REQUIRED}
    missing = [path for path, _ in REQUIRED if counts.get(path, 0) <= 0]

    ok = not missing and not errors
    return {
        "structure": structure,
        "missing": missing,
        "errors": errors,
        "ok": ok,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Structural audit of a FINAL BUILT public challenge image: are the five "
                    "required components present?"
    )
    ap.add_argument("--image", required=True, help="docker tag of the built challenge image")
    ap.add_argument("--fresh-pull", action="store_true", help="docker pull the image before auditing")
    args = ap.parse_args()

    lib.emit(verify(args.image, args.fresh_pull))


if __name__ == "__main__":
    main()
