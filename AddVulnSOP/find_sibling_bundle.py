#!/usr/bin/env python3
"""Look for an existing bug bundle for --project in the answers repo, and if
one exists, surface its Dockerfile/harness content (and bench.yaml's
project-level metadata) for reuse when onboarding a new bug for the same
project.

Pure filesystem read -- no docker, no network, and never writes anything.
"""
from __future__ import annotations

import argparse

import onboarding_lib as lib


def _read_text_or_none(path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _sibling_bench(bug_dir) -> dict:
    """Best-effort extraction of the project-level bits of bench.yaml that
    don't depend on which specific bug triggered them. Never raises --
    returns {} on anything missing/malformed."""
    bench_path = bug_dir / "bench.yaml"
    if not bench_path.is_file():
        return {}
    try:
        data = lib.read_yaml(bench_path)
        target = data.get("target") or {}
        return {
            "language": target.get("language"),
            "build_system": target.get("build_system"),
            "repo": target.get("repo"),
            "harness": data.get("harness") or {},
            "capability_set": data.get("capability_set") or [],
        }
    except Exception:
        return {}


def find_sibling(answers_repo, project: str) -> dict:
    project_dir = answers_repo / "bugs" / project
    if not project_dir.is_dir():
        return {"found": False}

    candidates = sorted(
        p.name for p in project_dir.iterdir()
        if p.is_dir() and (p / "Dockerfile").is_file() and (p / "harness" / "build.sh").is_file()
    )
    if not candidates:
        return {"found": False}

    sibling_bug_id = candidates[0]
    sibling_dir = project_dir / sibling_bug_id

    dockerfile_text = _read_text_or_none(sibling_dir / "Dockerfile")

    harness_dir = sibling_dir / "harness"
    harness_files = {}
    for f in sorted(harness_dir.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(harness_dir).as_posix()
        harness_files[rel] = _read_text_or_none(f)

    return {
        "found": True,
        "sibling_bug_id": sibling_bug_id,
        "dockerfile": dockerfile_text,
        "harness_files": harness_files,
        "sibling_bench": _sibling_bench(sibling_dir),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Find an existing answers-repo bug bundle for a project and return its "
                    "Dockerfile/harness content for reuse when onboarding a new bug."
    )
    ap.add_argument("--project", required=True, help="project name, e.g. libxml2")
    ap.add_argument("--answers-repo", default=None, help="override path to FuzzingBrain-Bench-answers")
    ap.add_argument("--public-repo", default=None, help="unused here, accepted for CLI consistency")
    ap.add_argument("--oss-fuzz-repo", default=None, help="unused here, accepted for CLI consistency")
    args = ap.parse_args()

    paths = lib.find_repo_paths(
        answers_repo=args.answers_repo,
        public_repo=args.public_repo,
        oss_fuzz_repo=args.oss_fuzz_repo,
    )
    result = find_sibling(paths.answers, args.project)
    lib.emit(result)


if __name__ == "__main__":
    main()
