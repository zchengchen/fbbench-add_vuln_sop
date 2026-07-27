#!/usr/bin/env python3
"""Differential corpus-cleanliness scan for the fbbench-add-bug SOP.

Runs a fuzz-target harness binary over an OSS-Fuzz backup corpus (or a local
directory standing in for one), one file per subprocess, and reports which
files still crash and which are clean. This is the "confirm no other bug
survives the fix" step: it must NEVER batch the whole corpus into a single
libFuzzer `-runs=0` invocation, since that stops at the first crash and
hides every crash after it.
"""
from __future__ import annotations

import argparse
import subprocess
import tempfile
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import onboarding_lib

CORPUS_URL_TMPL = (
    "https://storage.googleapis.com/{project}-backup.clusterfuzz-external.appspot.com"
    "/corpus/libFuzzer/{project}_{target}/public.zip"
)


def download_corpus(project: str, target: str) -> tuple[Path, str]:
    """Download the public backup corpus zip and unpack it to a temp dir.

    Returns (corpus_dir, source_url). The bucket is public-read; a generous
    fixed internal timeout (not a CLI knob) is used since the zip can be
    large but this is a one-shot download, not per-file scanning.
    """
    url = CORPUS_URL_TMPL.format(project=project, target=target)
    zip_path = Path(tempfile.mkstemp(suffix=".zip", prefix="corpus_")[1])
    cmd = ["curl", "-sL", "-o", str(zip_path), url]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        raise RuntimeError(f"curl failed downloading {url}: rc={p.returncode} stderr={p.stderr[-500:]}")
    if zip_path.stat().st_size == 0:
        raise RuntimeError(f"downloaded corpus zip from {url} is empty")

    extract_dir = Path(tempfile.mkdtemp(prefix="corpus_extract_"))
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"downloaded corpus from {url} is not a valid zip: {e}") from e
    finally:
        zip_path.unlink(missing_ok=True)
    return extract_dir, url


def list_corpus_files(corpus_dir: Path) -> list[Path]:
    return sorted(p for p in corpus_dir.rglob("*") if p.is_file())


def scan_corpus(harness: Path, files: list[Path], invocation: list[str], timeout_s: int, workers: int):
    crashes = []  # [{"file": name, "summary": ...}]

    def _scan_one(f: Path):
        result = onboarding_lib.run_harness_once(harness, invocation, f, timeout_s=timeout_s)
        return f, result

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_scan_one, f) for f in files]
        for fut in as_completed(futures):
            f, result = fut.result()
            if result["fault"]:
                crashes.append({"file": f.name, "summary": result["summary"]})

    return crashes


def group_summaries(crashes: list[dict]) -> list[dict]:
    groups: dict[str | None, list[str]] = defaultdict(list)
    for c in crashes:
        groups[c["summary"]].append(c["file"])
    out = []
    for summary, filenames in groups.items():
        out.append({
            "summary": summary,
            "count": len(filenames),
            "examples": sorted(filenames)[:5],
        })
    out.sort(key=lambda g: (-g["count"], g["summary"] or ""))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project", required=True)
    ap.add_argument("--target", required=True, help="fuzz target name")
    ap.add_argument("--harness", required=True, help="path to harness binary")
    corpus_group = ap.add_mutually_exclusive_group(required=True)
    corpus_group.add_argument("--download-corpus", action="store_true")
    corpus_group.add_argument("--corpus-dir", default=None)
    ap.add_argument("--invocation-arg", action="append", default=None,
                     help="repeatable; defaults to ['@@'] if not given")
    ap.add_argument("--timeout-s", type=int, default=10)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    invocation = args.invocation_arg if args.invocation_arg else ["@@"]
    harness_path = Path(args.harness).resolve()

    result = {
        "harness": str(harness_path),
        "corpus_source": None,
        "total_files": 0,
        "crashed": 0,
        "clean": 0,
        "summaries": [],
    }

    if args.download_corpus:
        corpus_dir, source = download_corpus(args.project, args.target)
        result["corpus_source"] = source
    else:
        corpus_dir = Path(args.corpus_dir).resolve()
        result["corpus_source"] = str(corpus_dir)
        if not corpus_dir.is_dir():
            result["error"] = f"--corpus-dir {corpus_dir} is not a directory"
            onboarding_lib.emit(result)
            return

    files = list_corpus_files(corpus_dir)
    if args.limit is not None and len(files) > args.limit:
        files = files[: args.limit]
        result["limited_to"] = args.limit

    result["total_files"] = len(files)

    crashes = scan_corpus(harness_path, files, invocation, args.timeout_s, args.workers)
    result["crashed"] = len(crashes)
    result["clean"] = len(files) - len(crashes)
    result["summaries"] = group_summaries(crashes)

    onboarding_lib.emit(result)


if __name__ == "__main__":
    main()
