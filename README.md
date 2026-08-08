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
| `llvm-symbolizer` | ASan frames carry no `file:line`, so the signature rules have no frames to name the crash by → every crash lands in the pool as **`<unsigned>`** and stops counting as a distinct find |

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

Bugs are listed and titled as `<title> (<bug-id>)`. Each bug gets its own page (`/bugs/<id>`) with a progress view over the same 14 stages, grouped into the 4 phases from `list-stages`/this README. A submission is stored (and displayed) as `<timestamp>-<bug-id>`, so re-running the same bug keeps a separate run directory and `run.log` while still overwriting the same bundle in the repos.

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
2. `clone_upstream` — resolves the upstream repo URL from oss-fuzz's `project.yaml` and does a full (non-shallow) clone, into a directory keyed on this run's own report-dir name (not just the project name) — so two concurrent onboarding runs for the same project never share a clone directory (which would race on `git fetch` and risk a stray `git checkout` from stage 3's agent yanking the HEAD from under a sibling run).
3. **`resolve_vuln_commit`** — resolves `vuln_commit`: some commit that empirically reproduces the crash. Prefers the report's filed/discovered date as the cheapest strong hypothesis, then the default-branch tip (HEAD, correct whenever the bug is still unfixed upstream), then a guided `git log` search — verifying every candidate by actually building and reproducing, never trusting a date/commit-message guess. It then **pins the two source trees to this bug's era** (`harness_vintage.py pin`, see [Source vintage](#source-vintage)) and records them as `vuln_src_dir` / `ossfuzz_src_dir`. There is no `find_fix_commit` stage any more: nothing builds at the fix, so `vuln.yaml`'s `fix_commit` is written as the literal placeholder `HEAD` (see `PLACEHOLDER_FIX_COMMIT` in `pipeline.py`, which also documents why `null` would be the more honest value).
4. **`scaffold_harness`** — writes `build/Dockerfile` + `build/build.sh` (with the harness SOURCE under `harness/`), adapting an existing sibling bug's template (or a mechanically-derived draft if this is the project's first bug) to this bug's specific fuzz target, and reports a `harness_meta` descriptor used to generate the bench.yaml / vuln.yaml. The agent may only read the two **era-pinned** trees from stage 3, and the harness it writes is checked against them before the stage passes — see [Source vintage](#source-vintage). Two rules make this stage expensive but trustworthy:
    - **Call the existing recipe, don't rewrite it.** OSS-Fuzz already ships `projects/<project>/build.sh` (usually delegating again into the project's own tree), and that recipe is what produced the crash upstream. `build/build.sh` should invoke it under an emulated base-builder environment and just remap the output into this bundle's `/out/vuln/<config>/harness` layout; hand-written compile/link lines are a last resort, recorded as `harness_meta.build_route`. Re-deriving them silently drops what base-builder sets for every project — `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` alone changes real parsing/encoding behaviour in libxml2 and many others, and a build missing it compiles, links and runs fine while no longer reproducing the bug.
    - **Prove it reproduces before the stage passes.** The agent must `docker build` the bundle, run the release-asan binary against this bug's actual PoC, and report the ASan summary and top frames it observed; the stage fails unless the PoC actually crashed. So "it built and ran on a sample input" can no longer be mistaken for verification, and a non-reproducing bundle dies here instead of later.
5. `build_release_asan` — Docker-builds the vulnerable binary and confirms the PoC crashes. This is now the **only** binary the pipeline produces: `build_fixed_asan`, `corpus_scan`, `handle_corpus_anomaly`, `rebuild_fixed_asan_with_patch` and `build_coverage` are gone, because the fixed build fed `differential` and the coverage build fed `reach`, and both rungs are retired.
6. `gen_expected_yaml` — runs the harness against the PoC and derives `reach`/`class`/`site` from the real, symbolized ASan trace. **Archival only now** — nothing scores against `expected.yaml` — so a trace it cannot anchor (e.g. every frame is harness code) is a warning rather than a fatal.
7. **`finalize_expected_yaml`** — writes `grader/expected.yaml` from that derived data (may fix formatting, must not invent new values).
8. **`write_answers_docs`** — writes the MINIMAL answers `bench.yaml` (5 public fields, templated) plus `description.txt` and an optional `NOTES.md` (human-only provenance).
9. `curate_and_generate` — derives the ASan `category` and writes the hidden `vuln.yaml` DIRECTLY in the current on-disk format. It no longer appends to the answers repo's `tools/fix_commits.yaml`: the only consumer of that registry is `tools/build_fixed.py`, which builds at the fix commit for `differential`, and a placeholder row asserting a fix commit this pipeline never looked for is worse than an absent one.
10. `scaffold_public_repo` — writes the scrubbed public `bench.yaml` (still the stable "fat" runner-facing shape, no answer fields, no `image:` field) and copies the harness source + `build.sh` for reference.
11. `verify_signature` — the bundle's correctness gate, and the replacement for `regrade_verify`'s five-rung ladder check. Runs the shipped binary against the shipped PoC N times (default 3) through the **public repo's own `fbbench/grading/signature.py`** — the same file baked into the challenge image — and requires all three of: it crashes, the crash can be **named** by the signature rules, and the name is **identical** across rounds. The last two are what a distinct-crash score actually depends on and nothing else checks: an unnameable crash collapses onto the single `<unsigned>` identity (contributing nothing while looking healthy), and an unstable one scores one fault as several. Reusing the real rules rather than reimplementing them is deliberate — two implementations of "are these the same crash?" that drift apart produce numbers nobody can compare.
12. **`build_challenge_image`** — builds the public Docker image. Claude is only involved in deciding which swept changelog/history files to delete (leak vs. decoy vs. harmless namesake); the deletion, build, and tagging themselves are deterministic. The stage first asserts `binaries/vuln/asan/harness` exists: without it `build_challenge.py` silently produces a **remote-graded** image instead of a self-contained one, and refusing to pass `--grade-url` is not enough to prevent that (it fills an absent one from the public repo's `DEFAULT_GRADE_URL`).
13. `verify_challenge_image` — structural audit, run INSIDE the built image (a clean build context says nothing about what the Dockerfile actually `COPY`ed in). A challenge image is only these things, and losing any one makes it unusable:

    | path | why it matters |
    |---|---|
    | `/challenge/src/` | the source the solver reads to find the bug |
    | `/challenge/harness/` | the fuzz target's source — defines the input shape |
    | `/challenge/bench.yaml` | public metadata the runner boots from |
    | `/challenge/description.txt` | the task prompt |
    | `/usr/local/bin/mcp-server` | the only channel for submitting a PoC |
    | `/opt/fbbench/oracle/binaries/vuln/asan/harness` | the in-image oracle — **its absence changes the image rather than breaking it** |

    The oracle harness is checked alongside `BENCH_ORACLE_DIR` being set, `fbbench.grading` being `local`, and `BENCH_GRADE_URL` being **absent**. Those four are the only outward difference between a self-contained image and a remote-graded one; without them a silently-remote image passes a structural audit unchanged.
14. `commit_locally` — commits both repos locally on a per-bug branch, `newbug/<bug_id>`, cut from each repo's default branch (main/master) latest HEAD — never committed directly to main. Reruns reuse the branch if it already exists. Both repos are left back on their original branch (normally main) once the commit lands, ready for review/PR. Never pushes. Parallel-safe: the whole checkout→add→commit→checkout-back sequence is wrapped in a per-repo file lock (`<repo>/.git/fbbench-commit.lock`), so two bugs reaching this stage at the same time queue briefly instead of racing on the shared working tree; `git add` is also scoped to just this bug's own `bugs/<project>/<bug_id>` subdirectory, not the whole project directory, so a same-project sibling bug's still-uncommitted files can never get swept into the wrong commit.

## Source vintage

The Dockerfile pins the code **under test** (`ARG VULN_COMMIT` + `git checkout`). Everything the pipeline *reads* to author that bundle has to be pinned to the same era too, or the bundle is quietly built from a mix of two timelines. `AddVulnSOP/harness_vintage.py` handles both halves.

**Two trees, because a harness can live in either place.** Roughly a fifth of oss-fuzz projects (304 of 1369 at the time of writing) ship their harness as `projects/<project>/*.c` in the oss-fuzz repo rather than upstream, so pinning only the project's own repo would miss them:

| tree | pinned to | holds |
| --- | --- | --- |
| `vuln_src_dir` | upstream @ `vuln_commit` | the project's own `fuzz/` or `tests/fuzz/` harness |
| `ossfuzz_src_dir` | oss-fuzz @ its tip when the bug was **reported** | `projects/<project>/*.c` harnesses |

Both are `git worktree add --detach`, never `git checkout`: the upstream clone's master tree is still needed by `reproduce_at_commit.py`, and the oss-fuzz repo is a **shared** path that every concurrent run reads — checking out there would corrupt every other pipeline in flight. The oss-fuzz anchor date falls back `report_filed_at` → `regression_window_end` → none (in which case the tool reports that it pinned to HEAD instead of pretending otherwise).

**Consumers.** `scaffold_harness` gets these two paths and nothing else (`--add-dir`), and `gen_expected_yaml` resolves the ASan trace's line numbers against `vuln_src_dir` — its brace-matching walks the source to name the enclosing function, so pointing it at today's tree can silently name the wrong one.

**The check.** After `scaffold_harness` writes `harness/`, every file is classified against both trees:

- **pinned** — byte-identical to that file at the pinned commit. Correct.
- **stale** — byte-identical to the repo's *current tip* but not to the pinned commit. **Hard failure**, at stage 6 rather than several minutes later in the stage-7 Docker build.
- **authored** — matches neither. Warning only: hand-written and adapted harnesses are legitimate (`provenance: fuzzingbrain`), and content alone can't tell "carefully adapted" from "wrong".

The failure this prevents, concretely: libxml2's `fuzz/fuzz.c` at master calls `xmlParserInputFlags`, an enum introduced 2025-03-13 — three weeks *after* a Feb-2025 bug's `vuln_commit`. Copied from an unpinned tree, it compiled against year-old headers and died with `unknown type name 'xmlParserInputFlags'`.
