#!/usr/bin/env python3
"""Fallback for the first bug ever added for a project (find_sibling_bundle.py
reported found: false): mechanically derive a bug-bundle build/Dockerfile +
build/build.sh from the oss-fuzz project's own build definition, without
authoring any new harness/fuzz-target source. (The returned `harness_build_sh`
text is written by the caller to the bug's build/build.sh; harness/ holds only
the harness source.)

This is a best-effort translator, not a build-system compiler: oss-fuzz
projects use autoconf/cmake/meson/plain-make/delegated-scripts, and this
script cannot always pin down the exact fuzz-target compile/link command with
confidence. Where it can't, it emits an explicit TODO placeholder and records
why in the "warnings" array rather than silently guessing.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import onboarding_lib as lib

FALLBACK_BASE_IMAGE = "debian:bookworm-slim"
BASE_PKGS = [
    "git", "ca-certificates", "clang", "libclang-rt-14-dev",
    "make", "autoconf", "automake", "libtool", "pkg-config",
]

FROM_RE = re.compile(r"^FROM\s+(\S+)", re.MULTILINE)
FUZZ_SRC_RE = re.compile(r"\$SRC/[\w./+-]*\.(?:c|cc|cpp|cxx)\b")
LIB_FUZZING_LINE_RE = re.compile(r"^.*\$LIB_FUZZING_ENGINE.*$", re.MULTILINE)


def _join_continuations(text: str) -> str:
    """Collapse `\\\n` line continuations so multi-line shell statements
    become single logical lines for easier regex scanning."""
    return re.sub(r"\\\s*\n\s*", " ", text)


def _extract_apt_packages(dockerfile_text: str) -> list[str]:
    """Heuristic scrape of `apt-get install ...` package tokens out of the
    oss-fuzz Dockerfile. Skips flags, shell keywords, and $VAR references --
    good enough as a starting point, not a guarantee of completeness."""
    joined = _join_continuations(dockerfile_text)
    pkgs: list[str] = []
    for m in re.finditer(r"apt(?:-get)?\s+install\b(.*?)(?:&&|$)", joined, re.MULTILINE):
        tail = m.group(1)
        for tok in tail.split():
            if tok.startswith("-"):
                continue
            if tok in ("y", "-y", "--no-install-recommends"):
                continue
            if tok.startswith("$") or tok.startswith("./") or tok.endswith(".deb"):
                continue
            if not re.match(r"^[A-Za-z0-9][A-Za-z0-9+._:-]*$", tok):
                continue
            pkgs.append(tok)
    # de-dupe, keep order
    seen = set()
    out = []
    for p in pkgs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _detect_base_image(dockerfile_text: str, warnings: list[str]) -> str:
    m = FROM_RE.search(dockerfile_text)
    from_line = m.group(1) if m else None
    if from_line and not from_line.startswith("gcr.io/oss-fuzz-base/base-builder"):
        return from_line
    warnings.append(
        f"upstream FROM line ({from_line!r}) is an OSS-Fuzz base-builder image, which isn't "
        f"independently pullable/buildable outside the OSS-Fuzz CI -- falling back to "
        f"{FALLBACK_BASE_IMAGE!r}. Verify the toolchain (clang version, libc, etc.) it provides "
        f"is actually sufficient for this project."
    )
    return FALLBACK_BASE_IMAGE


def _detect_repo_url(project_yaml: dict, warnings: list[str], project: str) -> str:
    repo = project_yaml.get("main_repo")
    if repo:
        return repo
    warnings.append(
        "project.yaml has no main_repo field -- could not determine the upstream clone URL; "
        "left a TODO placeholder in the Dockerfile."
    )
    return f"TODO_REPO_URL_FOR_{project}"


def _detect_build_system(build_sh_text: str, warnings: list[str]) -> str:
    text = build_sh_text or ""
    if re.search(r"\bcmake\b", text):
        return "cmake"
    if re.search(r"\bmeson\b", text):
        return "meson"
    if re.search(r"\./autogen\.sh|\./configure|autoreconf\b", text):
        return "autoconf"
    if re.search(r"\bmake\b", text):
        return "make"
    warnings.append(
        "could not confidently detect the project's build system from build.sh (it may delegate "
        "to a script inside the project's own tree, which this script does not fetch) -- "
        "defaulting to a generic 'make' library-build step; verify manually."
    )
    return "unknown"


LIB_BUILD_CMDS = {
    "autoconf": (
        './autogen.sh --disable-shared >/dev/null 2>&1 '
        '|| ./configure --disable-shared >/dev/null 2>&1\n'
        '    make -j${JOBS} >/dev/null 2>&1'
    ),
    "cmake": (
        'mkdir -p build && cd build\n'
        '    cmake -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" '
        '-DBUILD_SHARED_LIBS=OFF .. >/dev/null\n'
        '    make -j${JOBS} >/dev/null 2>&1\n'
        '    cd ..'
    ),
    "meson": (
        'meson setup build --default-library=static >/dev/null\n'
        '    ninja -C build >/dev/null'
    ),
    "make": 'make -j${JOBS} >/dev/null 2>&1',
    # NB: the "# TODO" must stay on the SAME logical line as (i.e. after) the
    # actual command -- this whole string is appended after a `VAR=val \`
    # backslash-continuation, so a comment placed *before* the command would
    # swallow the command into the comment via line-joining and silently
    # drop the env-var prefix (CFLAGS/CXXFLAGS/LDFLAGS never reaching make).
    "unknown": (
        'make -j${JOBS} >/dev/null 2>&1  '
        '# TODO: build system not confidently detected -- verify this actually builds the library.'
    ),
}


def _detect_fuzz_source(build_sh_text: str, warnings: list[str]) -> str | None:
    text = build_sh_text or ""
    candidates = sorted(set(FUZZ_SRC_RE.findall(text)))
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        warnings.append(
            "no $SRC/*.c(c) fuzz-target source path found in build.sh (project.yaml/build.sh may "
            "delegate the actual fuzzer build to a script inside the project's own repo) -- "
            "left the fuzz-target source as a TODO placeholder in harness/build.sh; find the real "
            "OSS-Fuzz-shipped fuzz target manually (usually fuzz/ or tests/fuzz/ in the checked-out "
            "tree) and fill it in before building."
        )
    else:
        warnings.append(
            f"multiple candidate fuzz-target source paths found in build.sh ({candidates!r}) -- "
            f"ambiguous which one this bug's harness should use; left a TODO placeholder in "
            f"harness/build.sh, pick the right one manually."
        )
    return None


def derive(oss_fuzz_repo: Path, project: str, vuln_commit: str, source_date_epoch: str) -> dict:
    warnings: list[str] = []
    proj_dir = oss_fuzz_repo / "projects" / project
    ossfuzz_dockerfile = (proj_dir / "Dockerfile").read_text(encoding="utf-8", errors="replace") \
        if (proj_dir / "Dockerfile").is_file() else ""
    ossfuzz_build_sh = (proj_dir / "build.sh").read_text(encoding="utf-8", errors="replace") \
        if (proj_dir / "build.sh").is_file() else ""
    project_yaml = {}
    if (proj_dir / "project.yaml").is_file():
        try:
            project_yaml = lib.read_yaml(proj_dir / "project.yaml")
        except Exception as e:
            warnings.append(f"could not parse project.yaml: {e}")

    if not ossfuzz_dockerfile:
        warnings.append(f"no Dockerfile found at {proj_dir}/Dockerfile")
    if not ossfuzz_build_sh:
        warnings.append(f"no build.sh found at {proj_dir}/build.sh")

    base_image = _detect_base_image(ossfuzz_dockerfile, warnings)
    repo_url = _detect_repo_url(project_yaml, warnings, project)
    build_system = _detect_build_system(ossfuzz_build_sh, warnings)
    extra_pkgs = [p for p in _extract_apt_packages(ossfuzz_dockerfile) if p not in BASE_PKGS]
    if build_system == "cmake" and "cmake" not in extra_pkgs and "cmake" not in BASE_PKGS:
        extra_pkgs.append("cmake")
    if build_system == "meson" and "meson" not in extra_pkgs:
        extra_pkgs.append("meson")
        if "ninja-build" not in extra_pkgs:
            extra_pkgs.append("ninja-build")
    all_pkgs = BASE_PKGS + extra_pkgs

    fuzz_src = _detect_fuzz_source(ossfuzz_build_sh, warnings)
    fuzz_src_placeholder = fuzz_src or "TODO_FUZZ_TARGET_SOURCE.c  # unresolved -- see warnings"

    pkgs_block = " \\\n        ".join(all_pkgs)

    dockerfile = f"""# syntax=docker/dockerfile:1.6
FROM {base_image}
ARG VULN_COMMIT={vuln_commit}
ARG SOURCE_DATE_EPOCH={source_date_epoch}
ENV SOURCE_DATE_EPOCH=${{SOURCE_DATE_EPOCH}}
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \\
        {pkgs_block} \\
    && rm -rf /var/lib/apt/lists/*

RUN git clone {repo_url} /src/{project} \\
 && git -C /src/{project} checkout ${{VULN_COMMIT}}

COPY harness/ /src/harness/
COPY build/build.sh /src/build/build.sh
RUN chmod +x /src/build/build.sh

RUN /src/build/build.sh build-libs

RUN mkdir -p /out \\
 && /src/build/build.sh harness debug \\
 && /src/build/build.sh harness debug-asan \\
 && /src/build/build.sh harness release-asan \\
 && /src/build/build.sh harness coverage

RUN ls -la /out/*/harness
"""

    lib_build_cmd = LIB_BUILD_CMDS.get(build_system, LIB_BUILD_CMDS["unknown"])

    harness_build_sh = f"""#!/bin/bash
# Auto-derived build script for {project} -- mechanically translated from
# oss-fuzz/projects/{project}/build.sh (detected build system: {build_system}).
# This is a best-effort translation; check the warnings this generator
# printed and verify the library-build and fuzz-target link commands below
# actually match oss-fuzz/projects/{project}/build.sh before trusting a build.
set -euo pipefail
cmd="${{1:?usage: build.sh build-libs | harness <config>}}"
JOBS=$(nproc)
SRC_ROOT=/src/{project}

if [ "${{cmd}}" = "build-libs" ]; then
    cp -r "${{SRC_ROOT}}" "${{SRC_ROOT}}-asan"
    cp -r "${{SRC_ROOT}}" "${{SRC_ROOT}}-cov"

    pushd "${{SRC_ROOT}}-asan" >/dev/null
    CC=clang CXX=clang++ \\
        CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \\
        CXXFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer" \\
        LDFLAGS="-fsanitize=address" \\
        {lib_build_cmd}
    popd >/dev/null

    pushd "${{SRC_ROOT}}-cov" >/dev/null
    CC=clang CXX=clang++ \\
        CFLAGS="-fprofile-instr-generate -fcoverage-mapping -g -O0" \\
        CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping -g -O0" \\
        LDFLAGS="-fprofile-instr-generate -fcoverage-mapping" \\
        {lib_build_cmd}
    popd >/dev/null

    echo "{project} built (asan + coverage)"
    exit 0
fi

if [ "${{cmd}}" = "harness" ]; then
    CONFIG="${{2:?harness needs <config>}}"
    OUT=/out/${{CONFIG}}
    mkdir -p "${{OUT}}"

    case "${{CONFIG}}" in
        debug|debug-asan|release-asan)
            CFLAGS_H="$([ "${{CONFIG}}" = "release-asan" ] && echo "-O2 -g" || echo "-g -O0")"
            BUILD="${{SRC_ROOT}}-asan"
            SAN="-fsanitize=fuzzer,address"
            ;;
        coverage)
            CFLAGS_H="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
            BUILD="${{SRC_ROOT}}-cov"
            SAN="-fsanitize=fuzzer"
            ;;
        *) echo "unknown config: ${{CONFIG}}" >&2; exit 2 ;;
    esac

    # TODO: verify this fuzz-target source path and link-library discovery
    # against oss-fuzz/projects/{project}/build.sh -- see generator warnings.
    FUZZ_SRC="{fuzz_src_placeholder}"
    LIBS=$(find "${{BUILD}}" -maxdepth 3 -name '*.a' 2>/dev/null | tr '\\n' ' ')

    clang \\
        ${{CFLAGS_H}} \\
        ${{SAN}} \\
        -fmacro-prefix-map=/src/= \\
        -I "${{BUILD}}/include" -I "${{BUILD}}" \\
        -c "${{FUZZ_SRC}}" -o "${{OUT}}/target.o"

    clang \\
        ${{CFLAGS_H}} \\
        ${{SAN}} \\
        "${{OUT}}/target.o" \\
        ${{LIBS}} \\
        -o "${{OUT}}/harness"

    rm -f "${{OUT}}/target.o"
    echo "built ${{OUT}}/harness ($(stat -c %s "${{OUT}}/harness") bytes)"
    exit 0
fi
exit 2
"""

    return {
        "project": project,
        "dockerfile": dockerfile,
        "harness_build_sh": harness_build_sh,
        "base_image": base_image,
        "warnings": warnings,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Mechanically derive a bug-bundle build/Dockerfile + build/build.sh from an "
                    "oss-fuzz project's own build definition (no new harness code authored)."
    )
    ap.add_argument("--oss-fuzz-repo", default=None, help="override path to google/oss-fuzz checkout")
    ap.add_argument("--project", required=True, help="oss-fuzz project name, e.g. libxml2")
    ap.add_argument("--vuln-commit", required=True, help="sha to bake into ARG VULN_COMMIT")
    ap.add_argument("--source-date-epoch", default="1735689600")
    ap.add_argument("--answers-repo", default=None, help="unused here, accepted for CLI consistency")
    ap.add_argument("--public-repo", default=None, help="unused here, accepted for CLI consistency")
    args = ap.parse_args()

    paths = lib.find_repo_paths(
        answers_repo=args.answers_repo,
        public_repo=args.public_repo,
        oss_fuzz_repo=args.oss_fuzz_repo,
    )
    proj_dir = paths.oss_fuzz / "projects" / args.project
    if not proj_dir.is_dir():
        raise SystemExit(f"error: no such oss-fuzz project directory: {proj_dir}")

    result = derive(paths.oss_fuzz, args.project, args.vuln_commit, args.source_date_epoch)
    lib.emit(result)


if __name__ == "__main__":
    main()
