# FuzzingBrain-Benchmark-add_vuln_sop

Deterministic Claude Code Workflow for turning an OSS-Fuzz bug report into a new
FuzzingBrain-Bench challenge (private answers repo + public bench repo).

- `.claude/workflows/fbbench-add-bug.js` — the Workflow orchestration script.
- `AddVulnSOP/` — the Python tooling it calls. Standalone (not a submodule of
  either bench repo), only ever touches them via explicit
  `--answers-repo`/`--public-repo`/`--oss-fuzz-repo` paths.

## Usage

Clone this repo as a sibling of `FuzzingBrain-Bench`, `FuzzingBrain-Bench-answers`,
and a `google/oss-fuzz` checkout, then run the workflow with:

```
Workflow({ scriptPath: '.claude/workflows/fbbench-add-bug.js' },
  { report: '<path-to-report.txt>', pocPath: '<path-to-poc-file>', upstream: '<path-to-upstream.txt>' })
```

`answersRepo`/`publicRepo`/`ossFuzzRepo`/`sopDir` default to sibling
directories next to this repo; override via `args` if your layout differs.
