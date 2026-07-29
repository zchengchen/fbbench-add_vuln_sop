#!/usr/bin/env python3
"""Compute the neutral bug id / alias a new bug for --project will get.

Post-refactor the identity is UNIFIED: the directory name == bug_id == public
alias == `<project>-NN`. It is assigned once, at creation, and is stable --
inserting a new bug NEVER renumbers existing siblings (the old positional
`_full_scan_alias` scheme, which sorted siblings and could shift indices, is
gone). A new bug simply takes the next sequential number after the current
maximum among the project's existing `<project>-NN` dirs.

Pure filesystem read -- writes nothing.

Usage:
    compute_alias.py --project <name> [--answers-repo <path>]
"""
from __future__ import annotations

import argparse
import os
import re

import onboarding_lib as lib


def existing_numbers(proj_dir: str, project: str) -> list[int]:
    """Every existing `<project>-NN` sibling that is a real bug dir (has a
    bench.yaml), as a sorted list of the integer NN suffixes."""
    if not os.path.isdir(proj_dir):
        return []
    pat = re.compile(rf"^{re.escape(project)}-(\d+)$")
    nums = []
    for name in os.listdir(proj_dir):
        if not os.path.isfile(os.path.join(proj_dir, name, "bench.yaml")):
            continue
        m = pat.match(name)
        if m:
            nums.append(int(m.group(1)))
    return sorted(nums)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compute the neutral <project>-NN bug id/alias a new bug would get "
                    "(pure read, no filesystem writes). NN is the next sequential number; "
                    "existing siblings are never renumbered."
    )
    ap.add_argument("--project", required=True, help="project name, e.g. libxml2")
    ap.add_argument("--answers-repo", default=None)
    args = ap.parse_args()

    paths = lib.find_repo_paths(answers_repo=args.answers_repo)
    proj_dir = str(paths.answers / "bugs" / args.project)

    nums = existing_numbers(proj_dir, args.project)
    idx = (max(nums) + 1) if nums else 1
    alias = f"{args.project}-{idx:02d}"

    # bug_id == alias == dir name under the unified identity model.
    lib.emit({
        "alias": alias,
        "bug_id": alias,
        "index": idx,
        "existing_numbers": nums,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
