#!/usr/bin/env python3
"""Build one binaries/<config>/harness for a single answers-repo bug via a
manual `docker build` + extraction. No automated pipeline exists to lean on
(tools/build_fixed.py's delta-bisect dependency is machine-local/gitignored
and often absent), so this is the same manual procedure the SOP describes,
made deterministic and scriptable.

--bug-dir is expected to be an ABSOLUTE path -- the caller (a Workflow script
with no fixed cwd assumption) always passes one; this script never assumes a
particular cwd.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import onboarding_lib as lib

VALID_CONFIGS = ("release-asan", "coverage", "fixed-asan")

# Local destination subpath under a bug's `binaries/` dir for each --config,
# matching the answers repo's grading-oracle convention (tools/mcp-server/grade.go,
# commit f0fb0b7 "move oracle bundle to binaries/vuln/{asan,cov} and fixed/{asan}").
DEST_SUBPATH = {
    "release-asan": Path("vuln") / "asan",
    "coverage": Path("vuln") / "cov",
    "fixed-asan": Path("fixed") / "asan",
}

# Where the harness binary lands INSIDE the built image at /out/, matching
# derive_dockerfile.py's template and the current answers-repo convention.
OUT_PATH = {
    "release-asan": "vuln/asan",
    "coverage": "vuln/cov",
    "fixed-asan": "vuln/asan",  # fixed-asan is a release-asan-equivalent build, just at fix_commit
}


def _find_clone_block(dockerfile_text: str) -> tuple[int, int, str]:
    """Locate the `RUN git clone ... && git ... checkout ...` block in a
    Dockerfile's lines. Returns (start_line_idx, end_line_idx_inclusive,
    repo_dest_dir) so a caller can insert a new layer right after it.

    A "block" is the RUN line plus every following line that is part of the
    same logical shell statement (i.e. the previous line ends with a
    trailing `\\` continuation)."""
    lines = dockerfile_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().startswith("RUN") and "git clone" in line:
            start = i
            break
    if start is None:
        raise ValueError("could not find a 'RUN ... git clone ...' line in Dockerfile")

    end = start
    while lines[end].rstrip().endswith("\\") and end + 1 < len(lines):
        end += 1

    block_text = "\n".join(lines[start:end + 1])
    dest = None
    m = None
    import re
    m = re.search(r"git clone\s+(?:--\S+\s+)*\S+\s+(\S+?)\s*(?:\\|$)", block_text, re.MULTILINE)
    if m:
        dest = m.group(1)
    if not dest:
        # no explicit dest arg -- oss-fuzz-style clone defaults to repo basename in cwd.
        url_m = re.search(r"git clone\s+(?:--\S+\s+)*(\S+)", block_text)
        if url_m:
            base = url_m.group(1).rstrip("/").rsplit("/", 1)[-1]
            dest = base[:-4] if base.endswith(".git") else base
    if not dest:
        raise ValueError("found a git clone line but could not determine the checked-out repo dir")

    return start, end, dest


def _stage_patched_context(bug_dir: Path, fix_commit: str, patch: Path) -> Path:
    """Copy bug_dir into a temp dir and insert a `COPY <patch> ... && RUN git
    apply` layer right after the clone+checkout block, for building
    fixed-asan with a local patch applied on top of fix_commit."""
    tmp_ctx = Path(tempfile.mkdtemp(prefix="fbbench-fixedasan-ctx-"))
    shutil.copytree(bug_dir, tmp_ctx, dirs_exist_ok=True,
                     ignore=shutil.ignore_patterns("binaries", "binaries/*"))

    dockerfile_path = tmp_ctx / "build" / "Dockerfile"
    dockerfile_text = dockerfile_path.read_text(encoding="utf-8")
    start, end, repo_dest = _find_clone_block(dockerfile_text)

    lines = dockerfile_text.splitlines()
    patch_basename = patch.name
    insert = [
        f"COPY {patch_basename} /tmp/patch.diff",
        f"RUN cd {repo_dest} && git apply /tmp/patch.diff",
    ]
    new_lines = lines[:end + 1] + [""] + insert + [""] + lines[end + 1:]
    dockerfile_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    shutil.copy2(patch, tmp_ctx / patch_basename)
    return tmp_ctx


def _rmi(tag: str) -> None:
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, text=True)


def build_config(bug_dir: Path, config: str, vuln_commit: str | None, fix_commit: str | None,
                  patch: Path | None, keep_image: bool) -> dict:
    bug_id = bug_dir.name
    tag = f"fbbench-build-tmp:{bug_id}-{config}"
    tmp_ctx = None

    try:
        if config in ("release-asan", "coverage"):
            build_result = lib.docker_build(bug_dir, tag=tag, build_args={"VULN_COMMIT": vuln_commit},
                                             dockerfile=bug_dir / "build" / "Dockerfile")
            out_config = config
        else:  # fixed-asan
            if patch is not None:
                tmp_ctx = _stage_patched_context(bug_dir, fix_commit, patch)
                context = tmp_ctx
            else:
                context = bug_dir
            build_result = lib.docker_build(context, tag=tag, build_args={"VULN_COMMIT": fix_commit},
                                             dockerfile=context / "build" / "Dockerfile")
            out_config = "release-asan"  # fixed-asan only ever needs the release-asan-equivalent build

        result = {
            "config": config,
            "built": False,
            "image_tag": tag,
            "extracted": [],
            "log_tail": build_result["log_tail"],
        }

        if not build_result["ok"]:
            return result

        dest = bug_dir / "binaries" / DEST_SUBPATH[config] / "harness"
        extract_result = lib.docker_extract(tag, f"/out/{OUT_PATH[out_config]}/harness", dest)
        if not extract_result["ok"]:
            result["log_tail"] += "\n--- docker cp stderr ---\n" + extract_result.get("stderr", "")
            return result

        dest.chmod(0o755)
        result["built"] = True
        result["extracted"] = [str(dest.relative_to(bug_dir))]
        return result
    finally:
        if tmp_ctx is not None:
            shutil.rmtree(tmp_ctx, ignore_errors=True)
        if not keep_image:
            _rmi(tag)


def main():
    ap = argparse.ArgumentParser(
        description="Build one binaries/<config>/harness for an answers-repo bug via manual "
                    "docker build + extraction."
    )
    ap.add_argument("--bug-dir", required=True,
                     help="ABSOLUTE path to bugs/<project>/<bug-id> in the answers repo")
    ap.add_argument("--config", required=True, choices=VALID_CONFIGS)
    ap.add_argument("--vuln-commit", default=None, help="required for release-asan/coverage")
    ap.add_argument("--fix-commit", default=None, help="required for fixed-asan")
    ap.add_argument("--patch", default=None, help="path to a .patch file to apply on top of fix-commit")
    ap.add_argument("--keep-image", action="store_true", help="don't docker rmi the tmp image afterward")
    args = ap.parse_args()

    bug_dir = Path(args.bug_dir)
    if not bug_dir.is_absolute():
        print(f"error: --bug-dir must be an absolute path, got {args.bug_dir!r}", file=sys.stderr)
        raise SystemExit(2)
    if not bug_dir.is_dir():
        print(f"error: no such bug directory: {bug_dir}", file=sys.stderr)
        raise SystemExit(2)
    if not (bug_dir / "build" / "Dockerfile").is_file():
        print(f"error: no Dockerfile at {bug_dir}/build/Dockerfile", file=sys.stderr)
        raise SystemExit(2)

    if args.config in ("release-asan", "coverage") and not args.vuln_commit:
        print(f"error: --vuln-commit is required for --config {args.config}", file=sys.stderr)
        raise SystemExit(2)
    if args.config == "fixed-asan" and not args.fix_commit:
        print("error: --fix-commit is required for --config fixed-asan", file=sys.stderr)
        raise SystemExit(2)

    patch = None
    if args.patch:
        patch = Path(args.patch)
        if not patch.is_file():
            print(f"error: no such patch file: {patch}", file=sys.stderr)
            raise SystemExit(2)
        if args.config != "fixed-asan":
            print("error: --patch is only meaningful with --config fixed-asan", file=sys.stderr)
            raise SystemExit(2)

    result = build_config(
        bug_dir=bug_dir,
        config=args.config,
        vuln_commit=args.vuln_commit,
        fix_commit=args.fix_commit,
        patch=patch,
        keep_image=args.keep_image,
    )
    lib.emit(result)


if __name__ == "__main__":
    main()
