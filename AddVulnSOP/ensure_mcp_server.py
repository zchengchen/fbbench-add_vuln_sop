#!/usr/bin/env python3
"""Idempotently ensure a FRESH tools/mcp-server binary -- built from this
answers-repo checkout's OWN current source -- is available on disk.

Why this exists: the answers repo commits a prebuilt bin/mcp-server binary,
but nothing rebuilds it when tools/mcp-server/*.go changes, so it silently
goes stale. Confirmed firsthand: the binary committed as of this writing
still expects the pre-f0fb0b7 flat binaries/release-asan/ layout, not the
current binaries/vuln/asan/ one -- and it fails SILENTLY (every capability
just reports not_fired, no error), not loudly. AddVulnSOP's own
regrade_verify should never trust that committed blob; it should grade
against a binary built from the CURRENT source tree, so it survives future
refactors of tools/mcp-server the same way. Cached and keyed by that
source's own content hash, so a rebuild only happens when the source
actually changes -- not on every regrade call.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import onboarding_lib as lib

DEFAULT_IMAGE = "golang:1.22-bookworm"
DEFAULT_CACHE_DIR = Path.home() / ".local" / "mcpserverroot"


def _source_hash(mcp_server_dir: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(mcp_server_dir.rglob("*")):
        if p.is_file() and p.suffix in (".go", ".mod", ".sum"):
            h.update(p.relative_to(mcp_server_dir).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()[:16]


def _cached_path(cache_dir: Path, source_hash: str) -> Path:
    return cache_dir / f"mcp-server-{source_hash}"


def ensure_mcp_server(answers_repo: Path, cache_dir: Path = DEFAULT_CACHE_DIR,
                       image: str = DEFAULT_IMAGE) -> dict:
    mcp_server_dir = answers_repo / "tools" / "mcp-server"
    if not mcp_server_dir.is_dir():
        return {"ok": False, "error": f"no tools/mcp-server dir at {mcp_server_dir}"}

    source_hash = _source_hash(mcp_server_dir)
    dest = _cached_path(cache_dir, source_hash)
    if dest.is_file() and os.access(dest, os.X_OK):
        return {"ok": True, "cached": True, "path": str(dest), "source_hash": source_hash}

    if shutil.which("docker") is None:
        return {"ok": False, "error": "docker not found on PATH and no cached build present "
                                       f"for source_hash={source_hash}"}

    cache_dir.mkdir(parents=True, exist_ok=True)
    building = dest.with_name(dest.name + ".building")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{mcp_server_dir}:/src:ro",
        "-v", f"{cache_dir}:/out",
        "-w", "/src",
        image,
        "go", "build", "-o", f"/out/{building.name}", ".",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        return {"ok": False, "error": f"go build failed: {r.stderr.strip()[-2000:]}"}
    if not building.is_file():
        return {"ok": False, "error": f"go build reported success but {building} is missing"}
    # The container runs as root, so `building` is root-owned on the host --
    # chmod would need ownership we don't have. Go already produces an
    # executable file (verified: comes out 0755), and the rename below only
    # needs write access to cache_dir (ours), not to the file itself, so this
    # is safe to skip rather than fail on an already-satisfied permission.
    if not os.access(building, os.X_OK):
        return {"ok": False, "error": f"{building} was not built executable"}
    building.rename(dest)
    return {"ok": True, "cached": False, "path": str(dest), "source_hash": source_hash}


def main():
    ap = argparse.ArgumentParser(
        description="Idempotently ensure a mcp-server binary built from this answers-repo's "
                    "CURRENT tools/mcp-server source exists on disk, building via a throwaway "
                    "golang docker container if the content-hash-keyed cache is cold."
    )
    ap.add_argument("--answers-repo", required=True)
    ap.add_argument("--image", default=DEFAULT_IMAGE,
                     help=f"golang docker image to build with (default: {DEFAULT_IMAGE})")
    ap.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR),
                     help=f"local build-cache dir (default: {DEFAULT_CACHE_DIR})")
    args = ap.parse_args()

    result = ensure_mcp_server(Path(args.answers_repo), Path(args.cache_dir), args.image)
    lib.emit(result)
    if not result.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
