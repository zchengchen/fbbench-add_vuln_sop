#!/usr/bin/env python3
"""Record the operator-supplied bug id, and note it in the ledger.

Identity is NOT auto-assigned. The operator always supplies the exact
`<project>-NN` (the webapp's required Bug ID field / pipeline.py's
`--bug-id`) and it is used VERBATIM:

  - no smallest-unused-gap scan, no max+1, no scanning either repo's
    bugs/<project>/ to see what's taken;
  - no registry lookup to reuse a previous id for the same url;
  - no project-prefix validation -- whatever you pass is what you get;
  - no refusal when that id already exists. If a bug bundle is already
    sitting at bugs/<project>/<bug_id>/ in either repo, the later stages
    simply overwrite it.

(This replaced an auto-assignment scheme that keyed identity on the report's
upstream url and filled the smallest free number. It was correct but opaque:
the id you got depended on the exact state of two repos' directories AND a
registry file at that instant, so the same url could land on different
numbers across runs, and reconstructing WHY took forensics. An operator who
already knows which id they want should just say so.)

`upstream_registry.yaml` survives only as a LEDGER -- a write-only
`normalize_url(upstream_url) -> bug_id` record, so an operator can still
answer "which report was this id built from?" even for a run that died
before `vuln.yaml` (which carries the same url in `upstream_report`) was
written. It is NEVER read to make an assignment decision. Writing it takes
the same file lock as before so concurrent runs don't clobber each other,
and any OTHER url that previously claimed this bug_id is dropped, keeping
the ledger one-id-to-one-url.

Usage:
    compute_alias.py --bug-id <project>-NN [--upstream-url <url>]
"""
from __future__ import annotations

import argparse
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import onboarding_lib as lib

REGISTRY_PATH = lib.SOP_DIR / "upstream_registry.yaml"


def normalize_url(url: str) -> str:
    """Canonicalize a report/issue url for ledger purposes -- collapses
    differences that don't change WHICH resource it points at (scheme case,
    host case, default port, trailing slash, query-param order, fragment) so
    the same report doesn't accumulate near-duplicate ledger lines."""
    url = (url or "").strip()
    if not url:
        return url
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-len(":80")]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-len(":443")]
    path = parts.path.rstrip("/") or "/"
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, path, query, ""))  # fragment dropped


def record_in_ledger(registry_path, upstream_url: str, bug_id: str) -> dict:
    """Write-only ledger update. Returns what it did, for the state file."""
    key = normalize_url(upstream_url)
    if not key:
        return {"ledger_written": False, "reason": "no upstream url to record"}
    with lib.file_lock(registry_path.with_suffix(".lock")):
        registry = lib.read_yaml(registry_path) if registry_path.is_file() else {}
        # One id <-> one url: drop any other url that used to claim this id.
        replaced = sorted(k for k, v in registry.items() if v == bug_id and k != key)
        for k in replaced:
            del registry[k]
        previous = registry.get(key)
        registry[key] = bug_id
        lib.write_yaml(registry_path, registry)
    return {
        "ledger_written": True,
        "ledger_key": key,
        "replaced_ledger_keys": replaced,
        "previous_bug_id_for_this_url": previous,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Record the operator-supplied bug id verbatim (no auto-assignment, no "
                    "collision check -- an existing bundle at this id gets overwritten by the "
                    "later stages) and note url -> bug_id in the write-only ledger."
    )
    ap.add_argument("--bug-id", required=True,
                     help="the exact bug id to use, e.g. libxml2-03. Used verbatim.")
    ap.add_argument("--upstream-url", default=None,
                     help="report/issue url, recorded in the ledger only; omitting it just "
                          "skips the ledger line")
    # Accepted for CLI consistency with the other AddVulnSOP tools; unused now
    # that nothing is scanned to pick a number.
    ap.add_argument("--project", default=None, help="unused, accepted for CLI consistency")
    ap.add_argument("--answers-repo", default=None, help="unused, accepted for CLI consistency")
    ap.add_argument("--public-repo", default=None, help="unused, accepted for CLI consistency")
    args = ap.parse_args()

    bug_id = args.bug_id.strip()
    result = {"alias": bug_id, "bug_id": bug_id}
    result.update(record_in_ledger(REGISTRY_PATH, args.upstream_url or "", bug_id))
    lib.emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
