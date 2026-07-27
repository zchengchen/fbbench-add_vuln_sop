#!/usr/bin/env python3
"""Compute the neutral full-scan alias a new bug would get, WITHOUT writing
anything -- a pure filesystem read of the answers repo.

Reimplements fbbench/runner/mcp_client.py's _full_scan_alias() logic exactly
(verbatim algorithm, not imported -- a new bug's directory might not exist
yet at compute time, so this has to work against a hypothetical sibling list):

    def _full_scan_alias(real_bug_dir: str) -> str:
        real = os.path.abspath(real_bug_dir)
        proj_dir = os.path.dirname(real)
        project = os.path.basename(proj_dir)
        me = os.path.basename(real)
        siblings = sorted(n for n in os.listdir(proj_dir)
                          if os.path.isfile(os.path.join(proj_dir, n, "bench.yaml")))
        idx = (siblings.index(me) + 1) if me in siblings else 1
        return f"{project}-{idx:02d}"

siblings is recomputed fresh from a live directory listing every call -- it is
NOT a stored mapping. So inserting a new bug alphabetically before an existing
sibling shifts that sibling's index (and therefore its alias) too. This script
reports that as `would_renumber` rather than silently doing it -- nothing on
disk is touched, callers decide separately whether/when to actually create the
new bug's directory.

Usage:
    compute_alias.py --project <name> --new-bug-id <descriptive-id> [--answers-repo <path>]
"""
from __future__ import annotations

import argparse
import os

import onboarding_lib as lib


def existing_siblings(proj_dir: str) -> list[str]:
    """Mirrors _full_scan_alias's sibling scan: every entry directly under
    proj_dir that is itself a directory containing a bench.yaml FILE."""
    if not os.path.isdir(proj_dir):
        return []
    return sorted(
        n for n in os.listdir(proj_dir)
        if os.path.isfile(os.path.join(proj_dir, n, "bench.yaml"))
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compute the neutral full-scan alias a new bug would get "
                    "(pure read, no filesystem writes)"
    )
    ap.add_argument("--project", required=True, help="project name, e.g. libxml2")
    ap.add_argument("--new-bug-id", required=True, help="descriptive bug_id the new bug dir would use")
    ap.add_argument("--answers-repo", default=None)
    args = ap.parse_args()

    paths = lib.find_repo_paths(answers_repo=args.answers_repo)
    proj_dir = str(paths.answers / "bugs" / args.project)

    siblings_before = existing_siblings(proj_dir)

    # Hypothetical insertion: pretend the new bug's directory already exists
    # alongside its siblings (it need not exist on disk), insert its bug_id
    # into the sorted list exactly where sorted() would place it, and derive
    # the alias the same way _full_scan_alias does: 1-based position + 1.
    siblings_after = sorted(siblings_before + [args.new_bug_id])
    idx = (siblings_after.index(args.new_bug_id) + 1) if args.new_bug_id in siblings_after else 1
    alias = f"{args.project}-{idx:02d}"

    # would_renumber: existing siblings whose 1-based position shifts once the
    # new bug is inserted (i.e. everything sorted after the new bug_id).
    before_index = {name: i + 1 for i, name in enumerate(siblings_before)}
    after_index = {name: i + 1 for i, name in enumerate(siblings_after)}
    would_renumber = [
        name for name in siblings_before
        if before_index[name] != after_index.get(name)
    ]

    lib.emit({
        "alias": alias,
        "index": idx,
        "siblings_before": siblings_before,
        "would_renumber": would_renumber,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
