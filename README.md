# FuzzingBrain-Benchmark-add_vuln_sop

A standalone Python pipeline that turns an OSS-Fuzz bug report into a new
FuzzingBrain-Bench challenge (a bug bundle in the private answers repo, plus a
scrubbed challenge entry in the public bench repo). Plain Python, no Claude
Code Workflow tool involved — deterministic steps (git/docker/curl/YAML edits)
run as ordinary subprocess calls, and steps that genuinely need judgment call
out to **Claude** via a headless `claude -p` subprocess (`agent.py`).

- `AddVulnSOP/pipeline.py` — the orchestrator. Runs the stages below in order
  and persists state to `<report-dir>/.pipeline_state.json`, so a long run
  (many Docker builds) can be killed and resumed without redoing finished
  stages.
- `AddVulnSOP/agent.py` — thin wrapper around headless `claude -p
  --output-format json`, used only where a stage needs judgment.
- `AddVulnSOP/*.py` (everything else) — deterministic helper modules the
  orchestrator calls (git/docker/corpus-scan/YAML-generation logic). Each is
  also a standalone CLI (`argparse` + JSON on the last line of stdout).
- Standalone: not a submodule of either bench repo, not itself a git repo
  dependency of them — it only touches them via explicit
  `--answers-repo`/`--public-repo`/`--oss-fuzz-repo` paths (default: sibling
  directories next to wherever this repo is checked out).
- Never pushes to any git remote or Docker Hub, and never edits the public
  repo's `README.md` / `tools/sealed/CHALLENGES.md` — both are shared,
  cross-bug documentation the user updates by hand.

## Usage

Clone this repo as a sibling of `FuzzingBrain-Bench`, `FuzzingBrain-Bench-answers`,
and a `google/oss-fuzz` checkout. Drop a bug report bundle (typically
`report.txt` + a PoC file) into any directory, then run:

```
python3 AddVulnSOP/pipeline.py run --report-dir /path/to/report
```

Useful flags:

- `--from-stage <name>` / `--only-stage <name>` — resume or re-run a specific stage.
- `--force` — re-run a stage even if already marked done in the state file.
- `--model <model>` — override the model used for every agent call.
- `--answers-repo` / `--public-repo` / `--oss-fuzz-repo` — override the sibling-directory defaults.

```
python3 AddVulnSOP/pipeline.py list-stages     # list all stages in order
python3 AddVulnSOP/pipeline.py show --report-dir /path/to/report   # per-stage status
```

## Stages

Run in this order. **Bold** stages call Claude for a judgment step; the rest
are plain deterministic code.

1. **`parse_report`** — reads the report bundle and extracts structured facts
   (project, fuzz target, crash type/state, regression window, report-filed
   date, a descriptive bug id).
2. `clone_upstream` — resolves the upstream repo URL from oss-fuzz's
   `project.yaml` and does a full (non-shallow) clone.
3. **`find_fix_commit`** — searches upstream git history for the commit that
   *fixes* the bug (never the commit that introduced it).
4. **`resolve_vuln_commit`** — resolves `vuln_commit`. Prefers the report's
   filed/discovered date as the cheapest strong hypothesis (a commit from
   around then is very likely to already reproduce the bug), falling back to
   `fix_commit^` and then a guided bisection, verifying every candidate by
   actually building and reproducing — never trusting a date/commit-message
   guess alone. (Deterministic if the bug is still unfixed upstream — vuln
   commit is just `HEAD`.)
5. `compute_alias` — computes the public neutral alias (`<project>-NN`) and
   creates the bug's directory skeleton in the answers repo.
6. **`scaffold_harness`** — writes `Dockerfile` + `harness/build.sh`, adapting
   an existing sibling bug's template (or a mechanically-derived draft if
   this is the project's first bug) to this bug's specific fuzz target.
7. `build_release_asan` — Docker-builds the vulnerable binary and confirms
   the PoC crashes with the expected signature.
8. `build_fixed_asan` — Docker-builds the fixed binary and confirms the PoC
   does *not* crash.
9. `corpus_scan` — downloads the real historical ClusterFuzz corpus and scans
   it file-by-file against both binaries.
10. **`handle_corpus_anomaly`** — only does real work if the fixed binary
    still crashes on some corpus file. Diagnoses the root cause and either
    writes a minimal local patch (applied only to the fixed build) or fixes
    `harness/build.sh` itself (if the gap affects both builds equally). The
    fix only needs to stop unrelated crashes from being discoverable — it
    does not need to be upstream/maintainer-quality.
11. `rebuild_fixed_asan_with_patch` — rebuilds whichever binaries the
    previous stage's fix affects, and rescans the corpus to confirm clean.
12. `build_coverage` — Docker-builds the coverage-instrumented binary.
13. `gen_expected_yaml` — runs the harness against the PoC and derives
    `reach`/`class`/`site` from the real, symbolized ASan trace.
14. **`finalize_expected_yaml`** — writes `grader/expected.yaml` from that
    derived data (may fix formatting, must not invent new values).
15. **`write_answers_docs`** — writes `bench.yaml` (templated, deterministic)
    plus `description.txt` and `PROVENANCE.md` (prose, written by Claude from
    the actual collected facts/trace).
16. `curate_and_generate` — curates the ASan category when ambiguous, then
    runs the answers repo's own `gen_vuln_yaml.py` / `diffscan_freeze.py`.
17. `scaffold_public_repo` — writes the scrubbed public `bench.yaml` (no
    answer fields) and copies `harness/build.sh` for reference.
18. `regrade_verify` — runs the real grading oracle end-to-end and confirms
    every capability in `capability_set` fires.
19. **`build_challenge_image`** — builds the public Docker image. Claude is
    only involved in deciding which swept changelog/history files to delete
    (leak vs. decoy vs. harmless namesake); the deletion, build, and tagging
    themselves are deterministic.
20. `verify_challenge_image` — leak/scrub audit against the actual built
    image (not just the pre-build context).
21. `commit_locally` — commits both repos locally. Never pushes.
