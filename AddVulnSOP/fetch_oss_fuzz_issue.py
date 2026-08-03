#!/usr/bin/env python3
"""Pull everything a bug-report bundle needs out of a public OSS-Fuzz issue URL.

    https://issues.oss-fuzz.com/issues/398060138
      -> title, filed date, the raw report text, and the PoC bytes themselves

WHY IT SCRAPES
--------------
issues.oss-fuzz.com is a Google Issue Tracker instance: the visible page is
rendered client-side, so fetching it and reading the DOM text yields a login
wall even for issues that are fully public. The actual issue payload, however,
ships inside the HTML as a JSPB (positional-array protobuf JSON) blob, and for
public issues it is all there without any credentials.

That means this parser is bound to an undocumented internal encoding and WILL
break whenever the tracker's frontend changes. Every extraction below is
therefore anchored on content (a quoted string containing "Crash Type:", a
[seconds, nanos] pair) rather than on array positions, and anything that cannot
be found is reported as a warning with that field left null -- the caller falls
back to the operator typing it in by hand. It never guesses.

The reproducer is a separate, genuinely credential-free endpoint
(oss-fuzz.com/download?testcase_id=N -> signed GCS URL), so the PoC comes down
in the same pass.

Usage:
    fetch_oss_fuzz_issue.py --url <issue-url> [--poc-out <path>] [--no-poc]
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import onboarding_lib as lib

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) fbbench-add-vuln-sop/1.0"
ISSUE_ID_RE = re.compile(r"/issues/(\d+)")
# A JS string literal, honouring backslash escapes so an escaped quote inside
# the report body doesn't cut the match short.
JS_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
# protobuf Timestamp as JSPB renders it: [seconds, nanos]
TIMESTAMP_RE = re.compile(r"\[(1[0-9]{9}),\s*\d{1,9}\]")
TESTCASE_ID_RE = re.compile(r"testcase_id=(\d+)")
DOWNLOAD_URL = "https://oss-fuzz.com/download?testcase_id={}"
# Refuse to inline anything absurd into a JSON response aimed at a browser.
MAX_POC_BYTES = 8 * 1024 * 1024


def _get(url: str, timeout: int = 60) -> tuple[bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(), resp.geturl()


def _unescape_js(s: str) -> str:
    """Decode the \\n / \\u003c escapes a JSPB string literal carries."""
    return json.loads(f'"{s}"')


def extract_report_text(html: str, warnings: list) -> str | None:
    """The report body is the quoted string that carries the ASan summary
    block. The same text also appears HTML-flavoured (\\u003cbr\\u003e instead
    of newlines) for the rendered comment -- prefer the newline one, since that
    is what belongs in report.txt."""
    plain, html_flavoured = [], []
    for m in JS_STRING_RE.finditer(html):
        raw = m.group(1)
        if "Crash Type:" not in raw or "Crash State:" not in raw:
            continue
        (html_flavoured if r"<br" in raw else plain).append(raw)
    for bucket in (plain, html_flavoured):
        if bucket:
            text = _unescape_js(max(bucket, key=len))
            if r"<br" in bucket[0] or "<br>" in text:
                text = re.sub(r"<br\s*/?>", "\n", text)
            return text.strip()
    warnings.append("could not find the report body in the page (private issue, or the "
                    "tracker's page format changed) -- paste it in by hand")
    return None


def extract_title(html: str, issue_id: str, warnings: list) -> str | None:
    """The title is the first string literal after the issue id in the payload
    (`[null,<id>,[<component>,...,"<title>"`)."""
    anchor = html.find(f",{issue_id},[")
    if anchor != -1:
        m = JS_STRING_RE.search(html, anchor)
        if m:
            title = _unescape_js(m.group(1)).strip()
            if title and "\n" not in title:
                return title
    warnings.append("could not find the issue title -- type it in by hand")
    return None


def extract_filed_at(html: str, warnings: list) -> datetime | None:
    """Earliest [seconds, nanos] timestamp in the payload == when the issue was
    filed (later ones are edits, comments, deadlines)."""
    seconds = {int(m.group(1)) for m in TIMESTAMP_RE.finditer(html)}
    if not seconds:
        warnings.append("could not find a filing timestamp -- type the date in by hand")
        return None
    return datetime.fromtimestamp(min(seconds), tz=timezone.utc)


def field_from_report(report_text: str | None, field: str) -> str | None:
    if not report_text:
        return None
    m = re.search(rf"^{re.escape(field)}:[ \t]*(.+)$", report_text, re.MULTILINE)
    return m.group(1).strip() if m else None


def fetch_poc(report_text: str | None, warnings: list) -> dict:
    """Download the reproducer. oss-fuzz.com redirects to a signed GCS blob and
    needs no credentials, so this works for any public issue."""
    testcase_id = None
    if report_text:
        m = TESTCASE_ID_RE.search(report_text)
        testcase_id = m.group(1) if m else None
    if not testcase_id:
        warnings.append("no testcase id in the report -- attach the PoC by hand")
        return {"testcase_id": None, "poc": None}

    url = DOWNLOAD_URL.format(testcase_id)
    try:
        blob, final_url = _get(url, timeout=120)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        warnings.append(f"PoC download failed ({e}) -- attach it by hand from {url}")
        return {"testcase_id": testcase_id, "poc": None}
    if len(blob) > MAX_POC_BYTES:
        warnings.append(f"PoC is {len(blob)} bytes, over the {MAX_POC_BYTES}-byte inline "
                        f"limit -- download it by hand from {url}")
        return {"testcase_id": testcase_id, "poc": None}

    # ClusterFuzz names the file in the signed URL's content-disposition.
    m = re.search(r"filename%3D([^&]+)", final_url) or re.search(r"filename=([^&;]+)", final_url)
    name = urllib.parse.unquote(m.group(1)) if m else f"clusterfuzz-testcase-{testcase_id}"
    return {"testcase_id": testcase_id,
            "poc": {"filename": name, "size": len(blob), "bytes": blob}}


def fetch(url: str, want_poc: bool = True) -> tuple[dict, bytes | None]:
    warnings: list[str] = []
    m = ISSUE_ID_RE.search(url)
    if not m:
        return {"ok": False, "error": f"not an issue URL (expected .../issues/<number>): {url!r}"}, None
    issue_id = m.group(1)

    try:
        raw, _ = _get(url)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return {"ok": False, "error": f"could not fetch {url}: {e}"}, None
    html = raw.decode("utf-8", errors="replace")

    report_text = extract_report_text(html, warnings)
    filed_at = extract_filed_at(html, warnings)
    poc_info = fetch_poc(report_text, warnings) if want_poc else {"testcase_id": None, "poc": None}
    poc = poc_info["poc"]

    return {
        "ok": bool(report_text),
        "url": url,
        "issue_id": issue_id,
        "title": extract_title(html, issue_id, warnings),
        # ISO (UTC) for machines; the display form is rendered in LOCAL time
        # because that is what the tracker's own UI shows an operator, and
        # report.txt's `date:` header is read back by parse_report as-is.
        "filed_at": filed_at.isoformat() if filed_at else None,
        "filed_at_display": (filed_at.astimezone().strftime("%b %d, %Y %I:%M%p")
                             if filed_at else None),
        "report_text": report_text,
        "project": field_from_report(report_text, "Project"),
        "fuzz_target": field_from_report(report_text, "Fuzz Target"),
        "crash_type": field_from_report(report_text, "Crash Type"),
        "testcase_id": poc_info["testcase_id"],
        "poc_filename": poc["filename"] if poc else None,
        "poc_size": poc["size"] if poc else None,
        "warnings": warnings,
    }, (poc["bytes"] if poc else None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="https://issues.oss-fuzz.com/issues/<id>")
    ap.add_argument("--poc-out", default=None, help="write the reproducer here")
    ap.add_argument("--no-poc", action="store_true", help="skip downloading the reproducer")
    args = ap.parse_args()

    result, poc_bytes = fetch(args.url, want_poc=not args.no_poc)
    if poc_bytes and args.poc_out:
        Path(args.poc_out).write_bytes(poc_bytes)
        result["poc_path"] = args.poc_out
    lib.emit(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
