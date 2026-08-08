#!/usr/bin/env python3
"""The bundle's correctness gate, for a benchmark scored on distinct crashes.

Replaces regrade_verify.py's five-rung ladder check. That gate asked "does this
bundle reproduce the ONE fault we wrote down in expected.yaml" -- a question
with no consequence once scoring stopped comparing against an answer key.

What has consequence now is narrower and is checked nowhere else:

  1. the shipped binary crashes on the shipped PoC
  2. the crash can be NAMED by the signature rules
  3. the name is the SAME every round

(1) alone is already covered by build_release_asan. (2) and (3) are not, and
both are silent:

  Unnameable. gradelocal.go files a crash the rules cannot name under the
  single identity "<unsigned>" -- deliberately, because inventing a find is
  worse than undercounting. But every unnameable crash in the pool collapses
  onto that one string, so a bug whose crash cannot be named contributes
  essentially nothing to a distinct-crash score while looking perfectly
  healthy from the outside: it crashes, the tool answers, nothing errors.

  Unstable. A signature that varies between identical runs inflates the
  distinct count -- one fault, several identities, all of them "new". That is
  worse than undercounting: it manufactures score out of noise, and it does it
  for every run that touches the bug, not just this one.

The rules used are the PUBLIC repo's fbbench/grading/signature.py -- the same
file build_challenge.py copies into the image (as /opt/fbbench/signature.py)
and the same one the backend scores with. Importing it by path rather than
reimplementing it is the point: two implementations of "are these the same
crash?" that drift apart produce numbers nobody can compare.

Usage:
  python3 verify_signature.py --bug-id libxml2-01 [--rounds 3]
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
import tempfile
from pathlib import Path

import native_grader as ng
import onboarding_lib as lib

DEFAULT_ROUNDS = 3

# The one identity the pool cannot tell apart from any other unnameable crash.
# gradelocal.go writes this exact string; keep them in lockstep.
UNSIGNED = "<unsigned>"

# Mirrors gradelocal.go's flakeAttempts. Keep the two the same: a gate stricter
# than the grader fails bundles the grader would have accepted.
FLAKE_ATTEMPTS = 3


def is_pre_init_flake(r) -> bool:
    """A signal-killed run that produced NO output at all.

    Not a property of the input: the harness died before it could print
    anything, so ASan never even started. On hosts with too much mmap
    randomisation (WSL2 ships `vm.mmap_rnd_bits` higher than ASan can place its
    shadow mapping under) this hits a fraction of runs at random, and the same
    PoC that segfaults bare on one attempt reproduces perfectly on the next.

    Exact mirror of gradelocal.go's isPreInitFlake -- these two MUST stay in
    lockstep, or this gate rejects bundles the real grader retries and accepts.
    """
    if not r.signal or r.timed_out:
        return False
    return not r.stdout.strip() and not r.stderr.strip()


def run_harness_retrying_flakes(harness, invocation, poc, run_dir, timeout_s, detect_leaks):
    """Retry ONLY the pre-init flake. Every other outcome -- a crash, a clean
    run, a timeout -- is an answer about the input and is returned as-is;
    re-running those would re-roll a verdict already in hand."""
    r = None
    for attempt in range(1, FLAKE_ATTEMPTS + 1):
        r = ng.run_harness(harness, invocation, poc, run_dir, timeout_s, detect_leaks)
        if not is_pre_init_flake(r):
            return r, attempt - 1
        print(f"[verify_signature] harness died before producing output "
              f"(attempt {attempt}/{FLAKE_ATTEMPTS}, signal {r.signal}) — retrying; "
              f"if this repeats, check vm.mmap_rnd_bits on the host", file=sys.stderr)
    return r, FLAKE_ATTEMPTS


def load_signature_module(public_repo: Path):
    """Import the PUBLIC repo's signature.py by path.

    Not `from fbbench.grading import signature`: this script runs from the SOP
    repo, whose sys.path has no fbbench package, and the answers repo ships a
    same-named module that is NOT the one the image bakes.
    """
    src = public_repo / "fbbench" / "grading" / "signature.py"
    if not src.is_file():
        raise SystemExit(f"error: signature rules not found at {src}\n"
                         f"       pass --public-repo, or set FBBENCH_PUBLIC_REPO")
    name = "_fbbench_signature"
    spec = importlib.util.spec_from_file_location(name, src)
    mod = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec: signature.py declares an @dataclass, and
    # dataclasses resolves the decorated class's own module out of sys.modules.
    # A module executed without being registered there fails on that lookup.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def verify(bug_dir: Path, public_repo: Path, rounds: int) -> dict:
    sig_mod = load_signature_module(public_repo)

    bench = lib.read_yaml(bug_dir / "bench.yaml")
    harness_meta = bench.get("harness") or {}
    invocation = harness_meta.get("invocation") or ["@@"]
    timeout_s = harness_meta.get("timeout_s") or 30

    harness = bug_dir / "binaries" / "vuln" / "asan" / "harness"
    if not harness.is_file():
        return {"ok": False, "reason": "no_harness",
                "detail": f"{harness} does not exist -- build_release_asan did not run or did not land"}

    poc = bug_dir / "poc" / "poc.bin"
    if not poc.is_file():
        return {"ok": False, "reason": "no_poc", "detail": f"{poc} does not exist"}

    # A leak is a fault the pool can name like any other, so detect_leaks
    # follows the bug's own declaration rather than being forced off.
    detect_leaks = bool(bench.get("detect_leaks", False))

    observed: list[str] = []
    rounds_out: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="fbbench-sigverify-") as tmp:
        run_dir = Path(tmp)
        for i in range(rounds):
            r, retries = run_harness_retrying_flakes(
                harness, invocation, poc, run_dir, timeout_s, detect_leaks)
            fired = ng.crash_fired(r)
            sig = sig_mod.signature({
                "stdout": r.stdout, "stderr": r.stderr,
                "exit_code": r.exit_code, "signal": r.signal,
            })
            canon = sig.canon_sig if sig is not None else UNSIGNED
            observed.append(canon if fired else "")
            rounds_out.append({
                "round": i + 1, "crashed": fired, "signature": canon,
                "class": (sig.klass if sig is not None else None),
                "exit_code": r.exit_code, "signal": r.signal, "timed_out": r.timed_out,
                "flake_retries": retries,
            })

    # Checked in the order a failure is cheapest to act on: no crash at all is
    # a build problem, an unnameable crash is a harness/symbolizer problem, and
    # instability is a bug property that needs a human.
    if not all(x["crashed"] for x in rounds_out):
        return {"ok": False, "reason": "did_not_crash", "rounds": rounds_out,
                "detail": "the shipped binary did not crash on the shipped PoC in every round "
                          "(pre-init flakes were already retried, so this is the input's verdict)"}

    if any(x["signature"] == UNSIGNED for x in rounds_out):
        return {"ok": False, "reason": "unsigned", "rounds": rounds_out,
                "detail": "the crash carries no marker the signature rules can name it by. "
                          "Most often an unsymbolized trace -- check llvm-symbolizer is on PATH "
                          "-- since bare module offsets give the rules no frames to key on."}

    uniq = sorted(set(observed))
    if len(uniq) != 1:
        return {"ok": False, "reason": "unstable_signature", "rounds": rounds_out,
                "signatures": uniq,
                "detail": f"{len(uniq)} different signatures across {rounds} identical runs; "
                          f"one fault scoring as several inflates a distinct-crash count"}

    return {"ok": True, "signature": uniq[0], "rounds_run": rounds,
            "class": rounds_out[0]["class"], "rounds": rounds_out}


def main():
    ap = argparse.ArgumentParser(
        description="Verify a bug bundle crashes, signs, and signs stably.")
    ap.add_argument("--bug-id", required=True)
    ap.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS,
                    help=f"identical runs used for the stability check (default {DEFAULT_ROUNDS}; "
                         f"1 disables it)")
    ap.add_argument("--answers-repo", default=None)
    ap.add_argument("--public-repo", default=None,
                    help="where the signature rules come from (default: sibling FuzzingBrain-Bench)")
    ap.add_argument("--oss-fuzz-repo", default=None, help="unused here, accepted for CLI consistency")
    a = ap.parse_args()

    paths = lib.find_repo_paths(answers_repo=a.answers_repo, public_repo=a.public_repo,
                                oss_fuzz_repo=a.oss_fuzz_repo)
    hits = list((paths.answers / "bugs").glob(f"*/{a.bug_id}"))
    if not hits:
        lib.emit({"ok": False, "reason": "no_bug_dir",
                  "detail": f"no bugs/*/{a.bug_id} under {paths.answers}"})
        raise SystemExit(2)

    result = verify(hits[0], paths.public, max(1, a.rounds))
    result["bug_id"] = a.bug_id
    lib.emit(result)
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
