# FuzzingBrain-Benchmark-add_vuln_sop

A standalone Python pipeline that turns an OSS-Fuzz bug report into a new FuzzingBrain-Bench challenge (a bug bundle in the private answers repo, plus a scrubbed challenge entry in the public bench repo).

## Quick start

**1. Check the environment**

```
pip install -r requirements.txt
python3 AddVulnSOP/check_env.py
```

Exits 1 and tells you what to install if anything is missing. `pipeline.py run` re-checks this itself and refuses to start otherwise. Details: [Setup](#setup).

**2. Directory layout** — four siblings under one parent, auto-detected:

```
workspace/
├── FuzzingBrain-Bench/          # public repo — scrubbed challenges
├── FuzzingBrain-Bench-answers/  # answers repo — bug bundles + answer keys
├── fbbench-add_vuln_sop/        # this repo
└── oss-fuzz/                    # google/oss-fuzz checkout
```

**3. Run the web UI**

```
python3 AddVulnSOP/webapp/app.py                    # http://127.0.0.1:5000
python3 AddVulnSOP/webapp/app.py --max-parallel 3   # concurrency cap (default 5)
```

Paste an OSS-Fuzz issue URL, hit **Fetch** (fills in title, date, report and PoC), pick a bug ID → the pipeline starts in the background. Every field can also be typed by hand. Runs past `--max-parallel` are queued, not rejected. Details: [Web UI](#web-ui).

**4. Where the output lands**

| what | where |
|---|---|
| bug bundle (PoC, binaries, `vuln.yaml`, `expected.yaml`) | `FuzzingBrain-Bench-answers/bugs/<project>/<bug-id>/` |
| public challenge (scrubbed `bench.yaml`, harness) | `FuzzingBrain-Bench/bugs/<project>/<bug-id>/` |
| the commits | branch `newbug/<bug-id>` in **both** repos (never pushed; both repos left on `main`) |
| challenge image | `docker.io/osanzas/fbbench-challenge-<bug-id>:latest`, local only |
| per-run log + stage state | `AddVulnSOP/webapp/submissions/<timestamp>-<bug-id>/{run.log,.pipeline_state.json}` |

## What's in this repo

- `AddVulnSOP/pipeline.py` — the orchestrator. Runs the stages below in order and persists state to `<report-dir>/.pipeline_state.json`, so a long run (many Docker builds) can be killed and resumed without redoing finished stages.
- `AddVulnSOP/agent.py` — thin wrapper around headless `claude -p --output-format json`, used only where a stage needs judgment. Retries transient failures (cyber-safeguard flags, 429/5xx, network blips) up to 3 times with exponential backoff — they say nothing about whether the task is doable, and letting one kill a stage throws away a run that may already be hours and many dollars deep. Every other failure raises immediately.
- `AddVulnSOP/*.py` (everything else) — deterministic helper modules the orchestrator calls (git/docker/corpus-scan/YAML-generation logic). Each is also a standalone CLI (`argparse` + JSON on the last line of stdout).
- `report.example/` — a real worked example (`report.txt` + PoC) of a bug report bundle, showing the expected input format.
- `AddVulnSOP/harness_vintage.py` — pins the two source trees a harness may come from to the bug's own era, and afterwards verifies the harness actually came from them. See [Source vintage](#source-vintage).
- `AddVulnSOP/fetch_oss_fuzz_issue.py` — turns a public OSS-Fuzz issue URL into title + date + report text + PoC bytes. Backs the web UI's **Fetch** button; also a standalone CLI.
- `AddVulnSOP/check_env.py` — preflight dependency check; also run automatically by `pipeline.py run`.
- `requirements.txt` — this repo's own Python dependencies (PyYAML, plus Flask for the web UI).
- Standalone: not a submodule of either bench repo, not itself a git repo dependency of them — it only touches them via explicit `--answers-repo`/`--public-repo`/`--oss-fuzz-repo` paths (default: sibling directories next to wherever this repo is checked out).
- Never pushes to any git remote or Docker Hub, and never edits the public repo's `README.md` / `tools/sealed/CHALLENGES.md` — both are shared, cross-bug documentation the user updates by hand.

## Setup

```
pip install -r requirements.txt
```

Also needs on `PATH`: `git`, `docker` (logged in if you intend to push images), `curl`, the `claude` CLI (logged in — used headlessly via `claude -p`), and the LLVM tools below.

To check everything at once:

```
python3 AddVulnSOP/check_env.py          # readable report; exit 1 if anything required is missing
python3 AddVulnSOP/check_env.py --json   # machine-readable, JSON on the last stdout line
```

`pipeline.py run` runs the same check before stage 0 and **refuses to start** if anything required is missing (`--skip-env-check` bypasses it, for re-running a late stage that doesn't need the missing tool). Two seconds up front beats discovering it an hour and several dollars in.

The checks that matter most are the quiet ones — these don't error, they just make a capability never fire, so the bug grades unsolved for no visible reason:

| tool | what breaks without it |
|---|---|
| `llvm-symbolizer` | ASan frames carry no `file:line` → **`site` and `reach` never fire** |
| `llvm-profdata-14`, `llvm-cov-14` | the coverage binaries are clang-14 builds (profile format v8); a newer host LLVM can't read them → **`reach` never fires**. `python3 AddVulnSOP/ensure_llvm14.py` installs matching ones via Docker |

Not needed, despite appearances: **Go** (`ensure_mcp_server.py` compiles inside a `golang` container) and **git-lfs** (the answers repo's `.gitattributes` has LFS rules, but `binaries/` is gitignored, so no LFS objects are actually tracked).

## Usage

Drop a bug report bundle (typically `report.txt` + a PoC file, see `report.example/`) into any directory. `report.txt` should lead with `upstream: <issue-url>`, `date: <report-filed-date>` and `title: <issue-summary>` header lines (before the raw OSS-Fuzz report text) — the `date` in particular lets `resolve_vuln_commit` resolve `vuln_commit` directly from the report's filed date instead of falling back to a much more expensive bisection. Then run:

```
python3 AddVulnSOP/pipeline.py run --report-dir /path/to/report
```

Useful flags:

- `--from-stage <name>` / `--only-stage <name>` — resume or re-run a specific stage.
- `--force` — re-run a stage even if already marked done in the state file.
- `--model <model>` — model used for every agent call. Defaults to `claude-sonnet-5` (pinned in `agent.py:DEFAULT_MODEL`, not inherited from the CLI's account default).
- `--answers-repo` / `--public-repo` / `--oss-fuzz-repo` — override the sibling-directory defaults.

```
python3 AddVulnSOP/pipeline.py list-stages     # list all stages in order
python3 AddVulnSOP/pipeline.py show --report-dir /path/to/report   # per-stage status
```

## Web UI

`AddVulnSOP/webapp/` is a small local Flask app so you don't have to hand-assemble a report-dir on disk. It has 6 required fields, in form order — **upstream URL** (the report/issue tracker link, carried through to `vuln.yaml`'s `upstream_report`), **title** (the issue's own one-line summary, e.g. `libxml2:html: Heap-buffer-overflow in xmlSAX2Text`), **date**, **Bug ID** (the exact `<project>-NN` to build this as; an existing bundle under that id is overwritten), **report** (the raw OSS-Fuzz report text), and a **PoC file upload** (must not be `.txt`).

**Fetch (auto-fill).** Next to the upstream URL is a **Fetch** button: paste a public OSS-Fuzz issue URL and it fills in title, date, report text and the PoC file in one shot, leaving only the Bug ID for you (identity is never auto-assigned — see stage 5). Everything it fills stays editable, and you can ignore the button entirely and type all six fields by hand. It is backed by `AddVulnSOP/fetch_oss_fuzz_issue.py`, also usable standalone:

```
python3 AddVulnSOP/fetch_oss_fuzz_issue.py --url https://issues.oss-fuzz.com/issues/398060138 --poc-out poc.bin
```

Two things worth knowing about it. `issues.oss-fuzz.com` renders client-side, so fetching the page and reading its text yields a login wall even for fully public issues — the parser instead reads the JSPB payload embedded in the HTML, which means it is bound to an **undocumented internal format and will break when that frontend changes**. Every field is anchored on content rather than array position, and anything it can't find comes back as a warning with the field left blank for you to type, never a guess. The reproducer download (`oss-fuzz.com/download?testcase_id=N`) is a genuinely credential-free redirect to signed storage, so the PoC comes down in the same pass. Private (pre-disclosure) issues can't be read at all — fill the form in by hand.

Bugs are listed and titled as `<title> (<bug-id>)`. Each bug gets its own page (`/bugs/<id>`) with a progress view over the same 21 stages, grouped into the 4 phases from `list-stages`/this README. A submission is stored (and displayed) as `<timestamp>-<bug-id>`, so re-running the same bug keeps a separate run directory and `run.log` while still overwriting the same bundle in the repos.

```
pip install -r requirements.txt
python3 AddVulnSOP/webapp/app.py                    # http://127.0.0.1:5000, localhost-only, no auth
python3 AddVulnSOP/webapp/app.py --max-parallel 3   # …with a smaller concurrency cap
```

At most `--max-parallel` pipelines run at once (**default 5**; `--port` and `--host` are also available). Each one drives Docker builds, a corpus scan and billed agent calls, so an unbounded fan-out will saturate the machine. Submissions past the cap are **queued, not rejected**: they sit as `queued` and a background scheduler starts them the moment a slot frees. The Bugs tab shows `N of M running · K queued`. Cancelling a queued run drops it from the queue instead of killing a process, and a queue left over from a previous webapp process is picked up on startup.

A failed or cancelled run gets a **Restart** button on its page: it resumes at the first stage that isn't `done`, so the failed stage and everything after it re-run while all the finished (expensive) work is skipped. The previous attempt's `run.log` is kept and the new attempt is appended after a marker line. If the run died before `compute_alias` ever recorded a bug id, the button asks for one.

Submitting the form **immediately spawns a real `pipeline.py run`** in the background against a fresh `AddVulnSOP/webapp/submissions/<id>/` directory — this is the actual pipeline (Docker builds, billed `claude -p` calls, can run for hours), not a preview. Cancel a running submission from its detail view.

Repo auto-discovery (`--answers-repo`/`--public-repo`/`--oss-fuzz-repo` and their `FBBENCH_*_REPO` env var overrides) walks upward from this repo's own location looking for a directory that has `FuzzingBrain-Bench` and `FuzzingBrain-Bench-answers` as siblings — this works whether the SOP repo is itself cloned directly as a sibling of the bench repos, or nested one level deeper (e.g. as `fbbench-add_vuln_sop/` with `AddVulnSOP/` inside it).

## Stages

Run in this order. **Bold** stages call Claude for a judgment step; the rest are plain deterministic code.

1. **`parse_report`** — reads the report bundle and extracts structured facts (project, fuzz target, crash type/state, regression window, report-filed date, a descriptive bug id).
2. `clone_upstream` — resolves the upstream repo URL from oss-fuzz's `project.yaml` and does a full (non-shallow) clone, into a directory keyed on this run's own report-dir name (not just the project name, and not bug_id — not assigned yet at this point) — so two concurrent onboarding runs for the same project never share a clone directory (which would race on `git fetch` and risk a stray `git checkout` from stage 3's agent yanking the HEAD from under a sibling run).
3. **`find_fix_commit`** — searches upstream git history for the commit that *fixes* the bug (never the commit that introduced it).
4. **`resolve_vuln_commit`** — resolves `vuln_commit`. Prefers the report's filed/discovered date as the cheapest strong hypothesis (a commit from around then is very likely to already reproduce the bug), falling back to `fix_commit^` and then a guided bisection, verifying every candidate by actually building and reproducing — never trusting a date/commit-message guess alone. (Deterministic if the bug is still unfixed upstream — vuln commit is just `HEAD`.) It then **pins the two source trees to this bug's era** (`harness_vintage.py pin`, see [Source vintage](#source-vintage)) and records them as `vuln_src_dir` / `ossfuzz_src_dir`.
5. `compute_alias` — takes the **required** `--bug-id` (webapp: the Bug ID field) and creates the bug's directory skeleton in the answers repo under it. The id is used **verbatim**: nothing is auto-assigned, no repo is scanned for free numbers, no project-prefix is validated, and an existing bundle at `bugs/<project>/<bug-id>/` in either repo is simply **overwritten** by the stages that follow. `AddVulnSOP/upstream_registry.yaml` is kept only as a write-only ledger (`upstream URL -> bug_id`), so you can still answer "which report was this id built from?" for a run that died before `vuln.yaml` was written; it is never read to decide an id. (This replaced a url-keyed auto-assignment scheme that filled the smallest free number — correct, but the id you got depended on the exact state of two repos plus a registry file at that instant, which made it hard to predict and hard to explain after the fact.)
6. **`scaffold_harness`** — writes `build/Dockerfile` + `build/build.sh` (with the harness SOURCE under `harness/`), adapting an existing sibling bug's template (or a mechanically-derived draft if this is the project's first bug) to this bug's specific fuzz target, and reports a `harness_meta` descriptor used to generate the bench.yaml / vuln.yaml. The agent may only read the two **era-pinned** trees from stage 4, and the harness it writes is checked against them before the stage passes — see [Source vintage](#source-vintage). Two rules make this stage expensive but trustworthy:
    - **Call the existing recipe, don't rewrite it.** OSS-Fuzz already ships `projects/<project>/build.sh` (usually delegating again into the project's own tree), and that recipe is what produced the crash upstream. `build/build.sh` should invoke it under an emulated base-builder environment and just remap the output into this bundle's `/out/vuln/<config>/harness` layout; hand-written compile/link lines are a last resort, recorded as `harness_meta.build_route`. Re-deriving them silently drops what base-builder sets for every project — `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` alone changes real parsing/encoding behaviour in libxml2 and many others, and a build missing it compiles, links and runs fine while no longer reproducing the bug.
    - **Prove it reproduces before the stage passes.** The agent must `docker build` the bundle, run the release-asan binary against this bug's actual PoC, and report the ASan summary and top frames it observed; the stage fails unless the PoC actually crashed. So "it built and ran on a sample input" can no longer be mistaken for verification, and a non-reproducing bundle dies here instead of at stage 7 (or, worse, surviving to be shipped). The observed summary/frames are recorded for review but deliberately **not** matched against the report's `Crash State` — that block is not a plain crash-stack function list (its lines can be file names, and for use-after-free the later ones name the free site, which never appears in the crash stack), so matching on it rejects correct builds. `resolve_vuln_commit` already confirmed the signature at this commit.
7. `build_release_asan` — Docker-builds the vulnerable binary and confirms the PoC crashes with the expected signature.
8. `build_fixed_asan` — Docker-builds the fixed binary and confirms the PoC does *not* crash.
9. `corpus_scan` — downloads the real historical ClusterFuzz corpus and scans it file-by-file against both binaries.
10. **`handle_corpus_anomaly`** — only does real work if the fixed binary still crashes on some corpus file. Diagnoses the root cause and either writes a minimal local patch (`patch/patch.diff`, applied only to the fixed build) or fixes `build/build.sh` itself (if the gap affects both builds equally). The fix only needs to stop unrelated crashes from being discoverable — it does not need to be upstream/maintainer-quality.
11. `rebuild_fixed_asan_with_patch` — rebuilds whichever binaries the previous stage's fix affects, and rescans the corpus to confirm clean.
12. `build_coverage` — Docker-builds the coverage-instrumented binary.
13. `gen_expected_yaml` — runs the harness against the PoC and derives `reach`/`class`/`site` from the real, symbolized ASan trace. `reach` and `site` are anchored on **different** frames on purpose: `reach` asks "did execution get here", so harness code counts; `site` must use the first frame the grading oracle would actually consider, which means skipping harness frames the way `grade.go`'s `isHarnessFrame` does (`is_harness_frame()` is an exact mirror of it — **keep the two in lockstep**). If *every* frame is harness code the stage fails here, because no gradeable `site` exists for that bug at all: either the crashing logic has to move out of the harness, or `site` has to come out of its `capability_set`.
14. **`finalize_expected_yaml`** — writes `grader/expected.yaml` from that derived data (may fix formatting, must not invent new values).
15. **`write_answers_docs`** — writes the MINIMAL answers `bench.yaml` (5 public fields, templated) plus `description.txt` and an optional `NOTES.md` (human-only provenance; `PROVENANCE.md` is gone).
16. `curate_and_generate` — derives the ASan `category` (T2 answer) and writes the hidden `vuln.yaml` DIRECTLY in the current on-disk format. It no longer calls the answers repo's `gen_vuln_yaml.py` / `diffscan_freeze.py`: that generator is stale w.r.t. the post-refactor vuln.yaml layout, and per-bug `diffscan.yaml` was removed repo-wide.
17. `scaffold_public_repo` — writes the scrubbed public `bench.yaml` (still the stable "fat" runner-facing shape, no answer fields, no `image:` field) and copies the harness source + `build.sh` for reference.
18. `regrade_verify` — confirms every capability in `capability_set` fires, using `native_grader.py`: a self-contained Python port of the grading algorithm (`tools/mcp-server`'s `grade.go` + `reach.go`) that computes reach/crash/differential/class/site directly against the bug's own `binaries/`/`grader/expected.yaml`. No Docker, no Go toolchain, and no dependency on the answers/public repos' *code* at all anymore — only their bug *data*, which can't be avoided since that's what's being graded. (Superseded two earlier approaches, in order: `tools/regrade.py`/ `fbbench.grading.grader`, which called an MCP tool renamed to `run_poc_on_harness` and made remote-only, so it only worked by accident against whichever stale `bin/mcp-server` happened to be committed; then a freshly-built `-grade-server` binary via `ensure_mcp_server.py`, which fixed the staleness but still needed Docker/Go and trusted that repo's `tools/mcp-server` source not to drift again — both repos' source has changed enough times in one week that avoiding the dependency entirely was worth it. Verified against the Go implementation on a real bug: identical result once `ASAN_SYMBOLIZER_PATH` is set for both — which `native_grader.py` does defensively and `grade.go`'s own `runHarness()` does not, so this port is arguably *more* reliable on that one point.)
19. **`build_challenge_image`** — builds the public Docker image. Claude is only involved in deciding which swept changelog/history files to delete (leak vs. decoy vs. harmless namesake); the deletion, build, and tagging themselves are deterministic.
20. `verify_challenge_image` — coarse structural audit, run INSIDE the built image (a clean build context says nothing about what the Dockerfile actually `COPY`ed in). One question: is anything big missing? A challenge image is only five things, and losing any one makes it unusable:

    | path | why it matters |
    |---|---|
    | `/challenge/src/` | the source the solver reads to find the bug |
    | `/challenge/harness/` | the fuzz target's source — defines the input shape |
    | `/challenge/bench.yaml` | public metadata the runner boots from |
    | `/challenge/description.txt` | the task prompt |
    | `/usr/local/bin/mcp-server` | the only channel for submitting a PoC |

    Nothing finer. Earlier revisions also ran an agent over `bench.yaml` (judging field completeness, language consistency, entrypoint-vs-harness agreement), diffed the `.c`/`.h` count across the changelog scrub, and re-scanned for answer leaks. All dropped: the first two are file/field bookkeeping rather than "is the bundle intact", and answer-leak coverage already happens pre-build in `build_challenge.py`'s own `leak_audit()`.
21. `commit_locally` — commits both repos locally on a per-bug branch, `newbug/<bug_id>`, cut from each repo's default branch (main/master) latest HEAD — never committed directly to main. Reruns reuse the branch if it already exists. Both repos are left back on their original branch (normally main) once the commit lands, ready for review/PR. Never pushes. Parallel-safe: the whole checkout→add→commit→checkout-back sequence is wrapped in a per-repo file lock (`<repo>/.git/fbbench-commit.lock`), so two bugs reaching this stage at the same time queue briefly instead of racing on the shared working tree; `git add` is also scoped to just this bug's own `bugs/<project>/<bug_id>` subdirectory, not the whole project directory, so a same-project sibling bug's still-uncommitted files can never get swept into the wrong commit.

## Source vintage

The Dockerfile pins the code **under test** (`ARG VULN_COMMIT` + `git checkout`). Everything the pipeline *reads* to author that bundle has to be pinned to the same era too, or the bundle is quietly built from a mix of two timelines. `AddVulnSOP/harness_vintage.py` handles both halves.

**Two trees, because a harness can live in either place.** Roughly a fifth of oss-fuzz projects (304 of 1369 at the time of writing) ship their harness as `projects/<project>/*.c` in the oss-fuzz repo rather than upstream, so pinning only the project's own repo would miss them:

| tree | pinned to | holds |
| --- | --- | --- |
| `vuln_src_dir` | upstream @ `vuln_commit` | the project's own `fuzz/` or `tests/fuzz/` harness |
| `ossfuzz_src_dir` | oss-fuzz @ its tip when the bug was **reported** | `projects/<project>/*.c` harnesses |

Both are `git worktree add --detach`, never `git checkout`: the upstream clone's master tree is still needed by `find_fix_commit` and `reproduce_at_commit.py`, and the oss-fuzz repo is a **shared** path that every concurrent run reads — checking out there would corrupt every other pipeline in flight. The oss-fuzz anchor date falls back `report_filed_at` → `regression_window_end` → none (in which case the tool reports that it pinned to HEAD instead of pretending otherwise).

**Consumers.** `scaffold_harness` gets these two paths and nothing else (`--add-dir`), and `gen_expected_yaml` resolves the ASan trace's line numbers against `vuln_src_dir` — its brace-matching walks the source to name the enclosing function, so pointing it at today's tree can silently name the wrong one.

**The check.** After `scaffold_harness` writes `harness/`, every file is classified against both trees:

- **pinned** — byte-identical to that file at the pinned commit. Correct.
- **stale** — byte-identical to the repo's *current tip* but not to the pinned commit. **Hard failure**, at stage 6 rather than several minutes later in the stage-7 Docker build.
- **authored** — matches neither. Warning only: hand-written and adapted harnesses are legitimate (`provenance: fuzzingbrain`), and content alone can't tell "carefully adapted" from "wrong".

The failure this prevents, concretely: libxml2's `fuzz/fuzz.c` at master calls `xmlParserInputFlags`, an enum introduced 2025-03-13 — three weeks *after* a Feb-2025 bug's `vuln_commit`. Copied from an unpinned tree, it compiled against year-old headers and died with `unknown type name 'xmlParserInputFlags'`.
