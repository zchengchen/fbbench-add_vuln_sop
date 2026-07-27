export const meta = {
  name: 'fbbench-add-bug',
  description: 'Turn one OSS-Fuzz bug report into a new FuzzingBrain-Bench challenge (private + public repos), deterministic scripts everywhere except the handful of judgment points',
  whenToUse: 'Given a bug report (e.g. report/report.txt), a PoC/testcase file, and optionally an upstream provenance note (report/upstream.txt), reproduce the bug and add it as a new challenge. Replaces the fully-manual fbbench-add-bug SKILL.md walkthrough.',
  phases: [
    { title: 'Parse report' },
    { title: 'Select commit' },
    { title: 'Scaffold bundle' },
    { title: 'Corpus scan' },
    { title: 'Metadata' },
    { title: 'Public scaffold' },
    { title: 'Narrative' },
    { title: 'Verify' },
    { title: 'Public image' },
    { title: 'Commit local' },
  ],
}

// -----------------------------------------------------------------------
// args (all paths absolute; Workflow scripts have no filesystem access of
// their own, so every real read/write happens through an agent() call):
//   report        (required) path to the bug report text file
//   pocPath       (required) path to the crash-reproducing PoC/testcase file
//   upstream      (optional) path to a human-written upstream provenance note
//                 (fix commit / advisory / CVE reference) -- when given, the
//                 commit-selection step confirms it instead of searching
//   answersRepo, publicRepo, ossFuzzRepo  (optional overrides)
//   sopDir        (optional override for the AddVulnSOP tooling folder itself)
//   disclosedDate (optional 'YYYY-MM-DD' -- Date() is unavailable in workflow
//                 scripts, so this can't be stamped automatically)
//   gradeUrl      (optional override for tools/sealed/build_challenge.py --grade-url)
// -----------------------------------------------------------------------

// Root cause of a real production bug: `args` sometimes arrives as the raw,
// unparsed JSON *string* rather than an object (the exact pitfall the
// Workflow tool's own docs warn about -- "a stringified list reaches the
// script as one string"). When that happened, `args.report`/`args.pocPath`
// were silently `undefined` for the rest of the run: `args.report` LOOKED
// like it worked because the parse-report subagent, told to read a file at
// literally "undefined", resourcefully searched the workspace and found the
// real report.txt on its own -- but reproduce_at_commit.py needs an exact
// exact path spliced into a shell command with no room for an agent to
// compensate, so it silently ran with the literal string "undefined" as its
// --testcase argument every time. Normalize defensively before anything else.
if (typeof args === 'string') {
  try {
    args = JSON.parse(args)
  } catch (e) {
    throw new Error(`args arrived as an unparsed JSON string and failed to JSON.parse: ${e.message}. First 500 chars: ${String(args).slice(0, 500)}`)
  }
}

// Fail loudly, immediately, if a required arg is missing -- observed in
// production: a missing arg silently evaluates to the JS string "undefined"
// inside template literals, which then propagates into shell commands
// (`--testcase undefined`) and docker mount paths, masquerading as a
// legitimate-looking value instead of an obvious error. Never again: check
// every required arg up front before any agent() call is made.
for (const key of ['report', 'pocPath']) {
  if (!args || args[key] == null || args[key] === '') {
    throw new Error(`Missing required arg "${key}" (got: ${JSON.stringify(args && args[key])}). Full args received: ${JSON.stringify(args)}`)
  }
}

const ANSWERS_REPO = args.answersRepo || '/home/zhicheng/benchmark/FuzzingBrain-Bench-answers'
const PUBLIC_REPO = args.publicRepo || '/home/zhicheng/benchmark/FuzzingBrain-Bench'
const OSSFUZZ_REPO = args.ossFuzzRepo || '/home/zhicheng/benchmark/oss-fuzz'
// The onboarding scripts live in a standalone folder, NOT inside either bench
// repo and NOT itself a git repo -- so a `git clone` reset of either bench
// repo (which has already happened once mid-project) can never wipe this
// tooling again. It only ever touches the bench repos via explicit
// --answers-repo/--public-repo/--oss-fuzz-repo args or absolute paths.
const SOP_DIR = args.sopDir || '/home/zhicheng/benchmark/AddVulnSOP'
const MAX_COMMIT_ATTEMPTS = 3
const MAX_CORPUS_FIX_ATTEMPTS = 2
const MAX_REGRADE_ATTEMPTS = 2

// -----------------------------------------------------------------------
// Generic helpers: every real command/file-write goes through a narrow
// "executor" agent() call. runScript() is for our AddVulnSOP/*.py scripts,
// which all print one JSON object as the LAST line of stdout.
// -----------------------------------------------------------------------

function requireAgentResult(result, label) {
  // agent() returns null if the user skipped it mid-run, or the subagent
  // died on a terminal API error after retries (e.g. a safety-classifier
  // false-positive on legitimate vulnerability-triage language). Every
  // executor/judgment call in this workflow is load-bearing -- fail loudly
  // and by name rather than let `null` silently propagate into a `.foo`
  // access a few lines later as an opaque TypeError.
  if (result == null) {
    throw new Error(`agent() call "${label}" returned null (skipped, or the subagent errored out after retries). Re-run the workflow (resumeFromRunId) once the underlying issue is understood -- see /workflows or the run's journal.jsonl for the specific failure.`)
  }
  return result
}

function parseLastJson(text, label) {
  const lines = String(text).trim().split('\n').map(l => l.trim()).filter(Boolean)
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(lines[i])
      // Our onboarding scripts always print a JSON *object* as their last
      // line -- a bare `null`/number/string here means the "output" we
      // captured wasn't really the script's stdout (e.g. the underlying
      // agent() call itself failed and we're looking at a stringified
      // null), not a legitimate empty result.
      if (parsed !== null && typeof parsed === 'object') return parsed
    } catch (e) { /* keep scanning upward */ }
  }
  throw new Error(`no JSON object found in agent output for "${label}" (first 800 chars): ` + String(text).slice(0, 800))
}

const MAX_RUNSCRIPT_ATTEMPTS = 3

async function runScript(cmd, label, phaseName) {
  // Some of our onboarding scripts' JSON output (log_tail/raw fields
  // especially) can run to several KB on one line. Relaying that "verbatim"
  // through an LLM's own generation is usually fine but occasionally drops
  // or mangles a character (observed in production: a `": "` silently
  // became `="` mid-relay, breaking JSON.parse) -- purely a transcription
  // slip, not a real script failure, since the underlying command is
  // deterministic. Retry the whole call a couple of times before giving up,
  // same spirit as the null-result retries elsewhere in this workflow.
  let lastErr = null
  for (let attempt = 1; attempt <= MAX_RUNSCRIPT_ATTEMPTS; attempt++) {
    const text = requireAgentResult(await agent(
      `Run this exact command with your working directory set to ${SOP_DIR}, then return ONLY the LAST line of its stdout verbatim (the single JSON object it prints) -- no explanation, no markdown code fences, nothing before or after it. This line must be reproduced EXACTLY character-for-character, however long it is -- do not summarize, reformat, or paraphrase any part of it:\n\n${cmd}`,
      { label: attempt === 1 ? label : `${label}-retry${attempt}`, phase: phaseName, agentType: 'general-purpose' }
    ), label)
    try {
      return parseLastJson(text, label)
    } catch (e) {
      lastErr = e
      log(`runScript "${label}" attempt ${attempt}/${MAX_RUNSCRIPT_ATTEMPTS}: relayed output didn't parse as JSON (likely a transcription slip on a long line), retrying: ${e.message.slice(0, 200)}`)
    }
  }
  throw lastErr
}

// For pre-existing tools/*.py scripts (gen_vuln_yaml.py, diffscan_freeze.py)
// that print plain human-readable text, not JSON, and that rely on the
// repo's own editable-installed venv rather than a self-contained sys.path
// fixup -- always invoke them via .venv/bin/python3.
async function runVenvScriptText(cmd, label, phaseName) {
  return requireAgentResult(await agent(
    `Run this exact command with your working directory set to ${ANSWERS_REPO}, using the repo's own venv interpreter (.venv/bin/python3, NOT the bare "python3"/"python" on PATH) so the editable-installed "fbbench" package resolves. Return its combined stdout+stderr verbatim, nothing else added:\n\n${cmd}`,
    { label, phase: phaseName, agentType: 'general-purpose' }
  ), label)
}

async function writeFile(path, content, label, phaseName) {
  requireAgentResult(await agent(
    `Write EXACTLY the following content to the file at ${path} (create parent directories first if they don't exist; overwrite if the file already exists). Do not alter, reformat, or add to the content in any way. After writing, respond with only the word OK.\n\n----BEGIN FILE CONTENT----\n${content}\n----END FILE CONTENT----`,
    { label, phase: phaseName, agentType: 'general-purpose' }
  ), label)
}

async function execCmd(cmd, label, phaseName) {
  return requireAgentResult(await agent(
    `Run this exact shell command with your working directory set to ${ANSWERS_REPO} (unless the command itself changes directory) and report back its combined stdout+stderr verbatim:\n\n${cmd}`,
    { label, phase: phaseName, agentType: 'general-purpose' }
  ), label)
}

// -----------------------------------------------------------------------
// JSON Schemas for judgment agent() calls
// -----------------------------------------------------------------------

const REPORT_SCHEMA = {
  type: 'object',
  required: ['project', 'fuzz_target', 'crash_type', 'crash_state', 'severity', 'title', 'descriptive_bug_id'],
  properties: {
    project: { type: 'string' },
    fuzz_target: { type: 'string' },
    engine: { type: ['string', 'null'] },
    crash_type: { type: 'string' },
    crash_state: { type: 'array', items: { type: 'string' } },
    regression_start: { type: ['string', 'null'] },
    regression_end: { type: ['string', 'null'] },
    severity: { type: 'string' },
    upstream_report_url: { type: ['string', 'null'] },
    title: { type: 'string' },
    // The exact upstream commit sha that fixes this bug, IF the report or
    // upstream note already names one (e.g. "Fixed commit: A:B" -- take B,
    // the later/fixed side) -- null if genuinely not named anywhere.
    // Downstream commit resolution is then fully mechanical: no searching.
    fix_commit_hint: { type: ['string', 'null'] },
    descriptive_bug_id: { type: 'string' },
  },
}

const HARNESS_META_SCHEMA = {
  type: 'object',
  required: ['language', 'build_system', 'harness'],
  properties: {
    language: { type: 'string' },
    build_system: { type: 'string' },
    repo: { type: ['string', 'null'] },
    harness: {
      type: 'object',
      properties: {
        type: { type: 'string' },
        entrypoint: { type: 'string' },
        invocation: { type: 'array', items: { type: 'string' } },
        rss_limit_mb: { type: 'number' },
        timeout_s: { type: 'number' },
        provenance: { type: 'string' },
      },
    },
    capability_set: { type: 'array', items: { type: 'string' } },
  },
}

const PATCH_SCHEMA = {
  type: 'object',
  required: ['root_cause', 'patch_path', 'patch_content', 'provenance_writeup'],
  properties: {
    root_cause: { type: 'string' },
    patch_path: { type: 'string' },
    patch_content: { type: 'string' },
    provenance_writeup: { type: 'string' },
  },
}

const EXPECTED_REVIEW_SCHEMA = {
  type: 'object',
  required: ['reach', 'class', 'site', 'yaml_final'],
  properties: {
    reach: {
      type: 'object',
      properties: {
        expected_file: { type: 'string' },
        expected_function: { type: 'string' },
        expected_line_range: { type: 'array', items: { type: 'number' } },
      },
    },
    class: {
      type: 'object',
      properties: { expected: { type: 'string' }, sanitizer: { type: 'string' } },
    },
    site: {
      type: 'object',
      properties: {
        expected_file: { type: 'string' },
        expected_line: { type: 'number' },
        line_tolerance: { type: 'number' },
        max_frame_distance: { type: 'number' },
      },
    },
    yaml_final: { type: 'string' },
  },
}

const NARRATIVE_SCHEMA = {
  type: 'object',
  required: ['description_txt', 'provenance_md'],
  properties: {
    description_txt: { type: 'string' },
    provenance_md: { type: 'string' },
  },
}

const REGRADE_FALLBACK_SCHEMA = {
  type: 'object',
  required: ['diagnosis', 'action'],
  properties: {
    diagnosis: { type: 'string' },
    action: { type: 'string', enum: ['regen_expected_yaml', 'rebuild_binaries', 'manual_edit'] },
    edit: { type: ['object', 'null'] },
  },
}

const CHANGELOG_DECISION_SCHEMA = {
  type: 'object',
  required: ['delete', 'keep'],
  properties: {
    delete: { type: 'array', items: { type: 'string' } },
    keep: { type: 'array', items: { type: 'string' } },
    keep_rationale: { type: 'object' },
  },
}

const ADAPT_HARNESS_SCHEMA = {
  type: 'object',
  required: ['harness_build_sh'],
  properties: {
    harness_build_sh: { type: 'string' },
    notes: { type: 'string' },
  },
}

const VULN_TIME_SCHEMA = {
  type: 'object',
  required: ['vuln_commit', 'reasoning'],
  properties: {
    vuln_commit: { type: 'string' },
    commit_date: { type: ['string', 'null'] },
    reasoning: { type: 'string' },
  },
}

// -----------------------------------------------------------------------
// Small pure-JS helpers (no filesystem/network -- just string work over
// data already returned by prior agent() calls)
// -----------------------------------------------------------------------

function reproMatchesReport(repro, reportJson) {
  if (!repro || !repro.build || !repro.build.ok) return false
  if (!repro.reproduce || !repro.reproduce.crashed) return false
  const frames = (repro.reproduce.top_frames || []).map(f => f.function)
  const top = reportJson.crash_state && reportJson.crash_state[0]
  return !top || frames.includes(top)
}

function classifyFromAsanSummary(summaryText) {
  const m = /\b(READ|WRITE)\b/.exec(summaryText || '')
  if (!m) return null
  return { op: m[1], category: m[1] === 'READ' ? 'out-of-bounds-read' : 'out-of-bounds-write' }
}

function yamlQuote(v) {
  return `"${String(v).replace(/"/g, '\\"')}"`
}

function renderPrivateBenchYaml(f) {
  const invocation = (f.harness.invocation || ['@@']).map(a => `"${a}"`).join(', ')
  const capset = (f.capability_set || []).join(', ')
  const lines = [
    `bug_id: ${f.bug_id}`,
    `project: ${f.project}`,
    `title: ${yamlQuote(f.title)}`,
    f.upstream_report ? `upstream_report: ${f.upstream_report}` : `upstream_report: null`,
    ``,
    `target:`,
    `  repo: ${f.repo}`,
    `  vuln_commit: ${f.vuln_commit}`,
    `  fix_commit: ${f.fix_commit || 'null'}`,
  ]
  if (f.fix_patch) lines.push(`  fix_patch: ${f.fix_patch}`)
  lines.push(
    `  language: ${f.language}`,
    `  build_system: ${f.build_system}`,
    ``,
    `harness:`,
    `  type: ${f.harness.type || 'libfuzzer'}`,
    `  entrypoint: ${f.harness.entrypoint || 'LLVMFuzzerTestOneInput'}`,
    `  invocation: [${invocation}]`,
    `  rss_limit_mb: ${f.harness.rss_limit_mb || 2560}`,
    `  timeout_s: ${f.harness.timeout_s || 30}`,
    `  provenance: ${f.harness.provenance || 'oss-fuzz'}`,
    ``,
    `capability_set: [${capset}]`,
    ``,
    `reproducibility:`,
    `  base_image_digest: ""`,
    `  snapshot_debian_date: "20260101T000000Z"`,
    `  source_date_epoch: 1735689600`,
    ``,
    `status: fixed`,
    `cve: null`,
    `disclosed: ${f.disclosed || 'null'}`,
    ``,
  )
  return lines.join('\n')
}

function renderPublicBenchYaml(f) {
  return [
    `bug_id: ${f.alias}`,
    `project: ${f.project}`,
    `image: docker.io/chenzc2001/fbbench-challenge-${f.alias}:latest`,
    `target:`,
    `  language: ${f.language}`,
    `  build_system: ${f.build_system}`,
    `harness:`,
    `  type: ${f.harness.type || 'libfuzzer'}`,
    `  entrypoint: ${f.harness.entrypoint || 'LLVMFuzzerTestOneInput'}`,
    `  invocation: ["@@"]`,
    `  rss_limit_mb: ${f.harness.rss_limit_mb || 2560}`,
    `  timeout_s: ${f.harness.timeout_s || 30}`,
    `  provenance: ${f.harness.provenance || 'oss-fuzz'}`,
    `  sanitizer: asan`,
    `reproducibility:`,
    `  base_image_digest: ''`,
    `  snapshot_debian_date: '20260101T000000Z'`,
    `  source_date_epoch: 1735689600`,
    ``,
  ].join('\n')
}

// =========================================================================
// Phase: Parse report  --  [J] judgment: report formats vary, don't regex
// =========================================================================
phase('Parse report')

const reportJson = await agent(
  `Read the bug report at ${args.report} and the crash testcase/PoC file at ${args.pocPath} (just confirm it exists and note its size/type -- you don't need to understand its bytes).` +
  (args.upstream ? ` Also read the upstream provenance note at ${args.upstream}.` : '') +
  ` Bug reports vary in format -- this may be a ClusterFuzz/OSS-Fuzz-style report or something else entirely. Extract these fields exactly as they appear in the report (do not invent or guess values you don't actually find): project name, fuzz target name, fuzzing engine, crash type, crash_state (the list of function names from the report's crash-state/stack section, top frame first), the regression window start/end if present, severity, and the upstream report URL if present. Also write a short one-line human-readable "title" summarizing the bug, e.g. "Heap-buffer-overflow READ in <top function> (<short context>)". Use null (or [] for crash_state) for any field genuinely absent from the report -- do not guess.` +
  ` IMPORTANT: also look (in both the report and the upstream note, if given) for an explicit fix-commit reference -- e.g. a line like "Fixed commit: <sha-A>:<sha-B>" (this is an oss-fuzz bisection range; take the LATER/second sha, sha-B, as fix_commit_hint -- that's the first commit confirmed to contain the fix) or a plain "fix commit: <sha>"/advisory link naming one directly. Set fix_commit_hint to that sha if you find one, else null -- do not guess or search for one yourself, only report what's explicitly written in these two files.` +
  ` Also propose descriptive_bug_id: a short kebab-case id combining the project and a terse description of the defect (e.g. "libxml2-posgroup-oob-read") -- check ${ANSWERS_REPO}/bugs/<project>/ (substituting the actual project name) for existing sibling ids to match their naming style and avoid a collision, if any exist.`,
  { schema: REPORT_SCHEMA, label: 'parse-report', phase: 'Parse report', agentType: 'general-purpose' }
)
if (!reportJson) {
  throw new Error('parse-report agent call returned null (skipped, or the subagent errored out after retries -- e.g. an API-side safety classifier false-positive). Cannot continue without a parsed report; re-run the workflow (resumeFromRunId) once the underlying issue is understood.')
}
log(`Parsed report: project=${reportJson.project} fuzz_target=${reportJson.fuzz_target} crash_type=${reportJson.crash_type}`)

// =========================================================================
// Phase: Select commit  --  repo/clone prep is fully mechanical (no
// judgment). vuln_commit selection, when a fix_commit is given, is inferred
// by an agent using ONLY the report's regression TIME WINDOW (`git log
// --before=<timestamp> -1`-style reasoning) -- explicitly NOT by assuming
// vuln_commit = fix_commit's immediate git parent, and NOT by commit-message
// keyword search. Both of those were tried in production and both broke:
// git-parent-of-fix assumed no unrelated commits ever land between the real
// regression and the eventual fix (they can, and did -- a real case had two
// unrelated commits sitting exactly in that gap, three commits away from the
// true vuln_commit); keyword search twice converged on a chronologically
// wrong but textually-similar historical commit, and once burned 480+ tool
// calls building its own throwaway docker images to "verify" a guess.
// Every candidate is still independently VERIFIED against the real oss-fuzz
// build+reproduce pipeline (reproduce_at_commit.py) -- inference only picks
// a candidate, it never confirms one on its own.
// =========================================================================
phase('Select commit')

const fixCommitFlag = reportJson.fix_commit_hint ? `--fix-commit ${reportJson.fix_commit_hint}` : ''
const commitInfo = await runScript(
  `python3 resolve_vuln_fix_commits.py --project ${reportJson.project} --oss-fuzz-repo ${OSSFUZZ_REPO} ${fixCommitFlag}`,
  'resolve-commits', 'Select commit'
)
if (commitInfo.error) {
  throw new Error(`resolve_vuln_fix_commits.py failed to resolve repo/clone info: ${commitInfo.error}`)
}

const fixCommit = commitInfo.fix_commit
let reproFix = null
if (fixCommit) {
  log(`fix_commit=${fixCommit} (${commitInfo.fix_commit_date}). Verifying it does NOT crash (real oss-fuzz build+reproduce)...`)
  reproFix = await runScript(
    `python3 reproduce_at_commit.py --oss-fuzz-repo ${OSSFUZZ_REPO} --project ${reportJson.project} --fuzzer ${reportJson.fuzz_target} --sha ${fixCommit} --testcase ${args.pocPath}`,
    'reproduce-fix', 'Select commit'
  )
}
const fixClean = !reproFix || !(reproFix.reproduce && reproFix.reproduce.crashed)

let commitJson = null
const rejectedVulnCandidates = []

for (let attempt = 1; attempt <= MAX_COMMIT_ATTEMPTS && !commitJson; attempt++) {
  let vulnCandidate, candidateReasoning

  if (commitInfo.branch === 'unfixed') {
    // HEAD is unambiguous -- no time-inference needed, and only one attempt
    // makes sense (retrying HEAD against itself would be pointless).
    vulnCandidate = commitInfo.vuln_commit
    candidateReasoning = 'no fix_commit named anywhere -- presumed unfixed, using current HEAD'
    if (attempt > 1) break
  } else {
    const timeChoice = await agent(
      `Find vuln_commit for a bug in project "${reportJson.project}" (upstream repo already fully cloned at ${commitInfo.clone_dir} -- do NOT re-clone, just read its history).` +
      ` Use ONLY time-based reasoning: \`git log --before="<timestamp>" -1 --format='%H %aI %s'\` to find the commit that was HEAD at a given moment, and \`git log --since="<date>" --until="<date>" --format='%H %aI %s'\` to browse a short window of candidates. Do NOT search by commit message keywords or crash function names, and do NOT run any docker/build commands yourself -- verification happens separately, your only job is to name one candidate sha.` +
      ` Anchors: report's regression window (when ClusterFuzz's bisection first found this reproducing) is ${reportJson.regression_start || 'unknown'} to ${reportJson.regression_end || 'unknown'}. The confirmed fix_commit is ${fixCommit}, dated ${commitInfo.fix_commit_date} -- the true vuln_commit must be chronologically BEFORE this, but do NOT assume it is fix_commit's immediate git parent; unrelated commits can and do land in the gap between the real regression and the eventual fix.` +
      ` Default strategy (use unless you have a specific reason not to): \`git log --before="<regression window end, or the report's filing time if the window is unknown>" -1\` -- the commit that was HEAD at that moment is normally exactly the build ClusterFuzz's own bisection confirmed as first-reproducing.` +
      (rejectedVulnCandidates.length ? ` These candidate(s) were already tried and did NOT reproduce the crash when actually built+run -- do not pick them again; try a commit a bit earlier or later in time instead: ${JSON.stringify(rejectedVulnCandidates)}.` : '') +
      ` Return the sha, its date, and the exact git command / timestamp reasoning you used to pick it.`,
      { schema: VULN_TIME_SCHEMA, label: `infer-vuln-commit-${attempt}`, phase: 'Select commit', agentType: 'general-purpose' }
    )
    if (!timeChoice) {
      log(`Attempt ${attempt}/${MAX_COMMIT_ATTEMPTS}: infer-vuln-commit agent call returned null (skipped or errored), retrying`)
      continue
    }
    vulnCandidate = timeChoice.vuln_commit
    candidateReasoning = timeChoice.reasoning
    log(`Time-based candidate ${attempt}/${MAX_COMMIT_ATTEMPTS}: ${vulnCandidate} (${timeChoice.commit_date || 'date unknown'}) -- ${candidateReasoning}`)
  }

  const reproVuln = await runScript(
    `python3 reproduce_at_commit.py --oss-fuzz-repo ${OSSFUZZ_REPO} --project ${reportJson.project} --fuzzer ${reportJson.fuzz_target} --sha ${vulnCandidate} --testcase ${args.pocPath}`,
    `reproduce-vuln-${attempt}`, 'Select commit'
  )
  const vulnMatches = reproMatchesReport(reproVuln, reportJson)

  if (vulnMatches) {
    commitJson = {
      branch: commitInfo.branch,
      vuln_commit: vulnCandidate,
      fix_commit: fixCommit,
      repo_url: commitInfo.repo_url,
      fix_patch_needed: false,
      unusable_reason: commitInfo.branch === 'unfixed' ? `unfixed upstream as of ${commitInfo.vuln_commit_date}` : null,
      descriptive_bug_id: reportJson.descriptive_bug_id,
      repro_vuln: reproVuln,
      repro_fix: reproFix,
    }
    log(`Commit verified: vuln_commit=${vulnCandidate} (crashes, signature matches) fix_commit=${fixCommit || 'null'} (fixClean=${fixClean}) branch=${commitInfo.branch}`)
  } else {
    rejectedVulnCandidates.push(vulnCandidate)
    log(`Attempt ${attempt}/${MAX_COMMIT_ATTEMPTS}: candidate ${vulnCandidate} rejected (did not reproduce the crash signature)`)
  }
}

if (!commitJson) {
  throw new Error(`Could not find a vuln_commit that reproduces the crash after ${MAX_COMMIT_ATTEMPTS} time-based attempts. Rejected candidates: ${JSON.stringify(rejectedVulnCandidates)}. fix_commit=${fixCommit || 'null'} (fixClean=${fixClean}). Stopping for human review.`)
}
if (fixCommit && !fixClean) {
  throw new Error(`vuln_commit=${commitJson.vuln_commit} verified, but the given fix_commit=${fixCommit} still crashes (fixClean=false) -- it does not actually fix this bug, or reproduce_at_commit.py's build for it is unreliable. Stopping for human review rather than shipping an unstable differential oracle. reproduce_at_commit.py fix result: ${JSON.stringify(reproFix)}`)
}

const bugId = commitJson.descriptive_bug_id
const bugDirRel = `bugs/${reportJson.project}/${bugId}`
const bugDir = `${ANSWERS_REPO}/${bugDirRel}`

// =========================================================================
// Phase: Scaffold bundle  --  Dockerfile/harness always REUSED, never
// authored from scratch (every bug here is triggered via an already-
// existing OSS-Fuzz harness) -- fully mechanical, [E]/[S] only, except the
// rare first-bug-for-a-project fallback which needs a small [J] to fill in
// language/build_system metadata derive_dockerfile.py can't infer on its own.
// =========================================================================
phase('Scaffold bundle')

const sibling = await runScript(
  `python3 find_sibling_bundle.py --project ${reportJson.project} --answers-repo ${ANSWERS_REPO}`,
  'find-sibling', 'Scaffold bundle'
)

let dockerfileText, harnessFiles, harnessMeta
if (sibling.found) {
  dockerfileText = sibling.dockerfile.replace(/ARG VULN_COMMIT=\S+/, `ARG VULN_COMMIT=${commitJson.vuln_commit}`)
  harnessMeta = sibling.sibling_bench
  const buildSh = (sibling.harness_files && sibling.harness_files['build.sh']) || ''
  // Same project doesn't mean same fuzz target -- e.g. libxml2 ships both a
  // "regexp" and a "reader" OSS-Fuzz harness, each compiling a different
  // upstream fuzz/*.c file. Verbatim reuse is only safe when the sibling's
  // build.sh actually targets the SAME fuzzer this bug's report names.
  const siblingTargetsSameFuzzer = buildSh.includes(`/${reportJson.fuzz_target}.c`) || buildSh.includes(`fuzz/${reportJson.fuzz_target}`) || buildSh.includes(`${reportJson.fuzz_target}.o`)
  if (siblingTargetsSameFuzzer) {
    harnessFiles = sibling.harness_files
    log(`Reusing sibling bundle from ${sibling.sibling_bug_id} verbatim -- same fuzz target (${reportJson.fuzz_target}), harness never re-authored`)
  } else {
    log(`Sibling bundle ${sibling.sibling_bug_id} builds a DIFFERENT fuzz target than this bug's report ("${reportJson.fuzz_target}") -- adapting harness/build.sh to compile the right upstream target rather than reusing verbatim`)
    const adapted = await agent(
      `Project "${reportJson.project}" already has a sibling bug bundle (${sibling.sibling_bug_id}) in this benchmark, but its harness/build.sh builds a DIFFERENT OSS-Fuzz fuzz target than this new bug needs. This new bug's fuzz target (per its report): "${reportJson.fuzz_target}".\n\nSibling's harness/build.sh (builds a different target -- do not reuse verbatim):\n${buildSh}\n\nAdapt this build.sh so its "harness <config>" subcommand compiles/links the "${reportJson.fuzz_target}" target instead. The fuzz target source ALREADY EXISTS upstream, unmodified, inside the checked-out repo -- this project ships multiple official OSS-Fuzz fuzz targets side by side (check ${OSSFUZZ_REPO}/projects/${reportJson.project}/build.sh and the upstream repo's own fuzz/ or similarly-named directory for the exact source path convention this project uses for "${reportJson.fuzz_target}"). You are ONLY changing which upstream-provided file gets compiled and linked -- never authoring new harness/fuzzer code from scratch. Keep the "build-libs" subcommand and the overall two-tree (asan/coverage) structure byte-for-byte identical to the sibling's; only the "harness <config>" subcommand's compile/link source file(s) and output names should change.`,
      { schema: ADAPT_HARNESS_SCHEMA, label: 'adapt-harness-build-sh', phase: 'Scaffold bundle', agentType: 'general-purpose' }
    )
    if (!adapted) {
      throw new Error('adapt-harness-build-sh agent call returned null (skipped or errored) -- cannot safely scaffold this bug bundle without an adapted harness build script. Re-run the workflow (resumeFromRunId) once the underlying issue is understood.')
    }
    if (adapted.notes) log(`Harness adaptation notes: ${adapted.notes}`)
    harnessFiles = { ...(sibling.harness_files || {}), 'build.sh': adapted.harness_build_sh }
  }
} else {
  const derived = await runScript(
    `python3 derive_dockerfile.py --oss-fuzz-repo ${OSSFUZZ_REPO} --project ${reportJson.project} --vuln-commit ${commitJson.vuln_commit}`,
    'derive-dockerfile', 'Scaffold bundle'
  )
  if (derived.warnings && derived.warnings.length) log(`derive_dockerfile.py warnings: ${JSON.stringify(derived.warnings)}`)
  dockerfileText = derived.dockerfile
  harnessFiles = { 'build.sh': derived.harness_build_sh }
  harnessMeta = await agent(
    `This is the first bug ever added for project "${reportJson.project}" in this benchmark, so there's no sibling bug bundle to copy metadata from. Look at ${OSSFUZZ_REPO}/projects/${reportJson.project}/{project.yaml,Dockerfile,build.sh} and determine: target language (c/cpp/jvm/etc), build_system (autoconf/cmake/meson/make/etc), and the harness contract fields -- type is virtually always "libfuzzer", entrypoint is virtually always "LLVMFuzzerTestOneInput", invocation is virtually always ["@@"], rss_limit_mb and timeout_s should match what the oss-fuzz project.yaml specifies if present (else use sane defaults 2560 / 30), provenance="oss-fuzz" (the harness is reused unmodified from upstream, never authored fresh), sanitizer="asan". Also default capability_set to the full ladder: ["reach","crash","differential","class","site"].`,
    { schema: HARNESS_META_SCHEMA, label: 'infer-harness-meta', phase: 'Scaffold bundle', agentType: 'general-purpose' }
  )
  if (!harnessMeta) {
    throw new Error('infer-harness-meta agent call returned null (skipped or errored) -- cannot safely scaffold this bug bundle without target language/build_system/harness metadata. Re-run the workflow (resumeFromRunId) once the underlying issue is understood.')
  }
}

await writeFile(`${bugDir}/Dockerfile`, dockerfileText, 'write-dockerfile', 'Scaffold bundle')
for (const relPath of Object.keys(harnessFiles)) {
  const content = harnessFiles[relPath]
  if (content == null) continue // non-text file the sibling bundle skipped reading; nothing to mechanically reproduce
  await writeFile(`${bugDir}/harness/${relPath}`, content, `write-harness-${relPath}`, 'Scaffold bundle')
}
await execCmd(`mkdir -p ${bugDir}/poc && cp ${args.pocPath} ${bugDir}/poc/poc.bin`, 'stage-poc', 'Scaffold bundle')

// =========================================================================
// Phase: Corpus scan  --  [E] builds + scans, [J] only when the FIXED build
// turns out not to be clean (a real code-level root-cause+patch job)
// =========================================================================
phase('Corpus scan')

await runScript(`python3 build_binaries.py --bug-dir ${bugDir} --config release-asan --vuln-commit ${commitJson.vuln_commit}`, 'build-release-asan', 'Corpus scan')
await runScript(`python3 build_binaries.py --bug-dir ${bugDir} --config coverage --vuln-commit ${commitJson.vuln_commit}`, 'build-coverage', 'Corpus scan')

let patchPath = null
let fixedClean = false
let vulnScanInfo = null
let corpusAttempt = 0

while (!fixedClean && corpusAttempt < MAX_CORPUS_FIX_ATTEMPTS) {
  corpusAttempt++
  const fixArgs = [`--config fixed-asan`, `--fix-commit ${commitJson.fix_commit || commitJson.vuln_commit}`]
  if (patchPath) fixArgs.push(`--patch ${patchPath}`)
  await runScript(`python3 build_binaries.py --bug-dir ${bugDir} ${fixArgs.join(' ')}`, `build-fixed-asan-${corpusAttempt}`, 'Corpus scan')

  const [vulnScan, fixedScan] = await parallel([
    () => runScript(`python3 corpus_scan.py --project ${reportJson.project} --target ${reportJson.fuzz_target} --harness ${bugDir}/binaries/release-asan/harness --download-corpus`, `scan-vuln-${corpusAttempt}`, 'Corpus scan'),
    () => runScript(`python3 corpus_scan.py --project ${reportJson.project} --target ${reportJson.fuzz_target} --harness ${bugDir}/binaries/fixed-asan/harness --download-corpus`, `scan-fixed-${corpusAttempt}`, 'Corpus scan'),
  ])
  vulnScanInfo = vulnScan
  log(`Corpus scan ${corpusAttempt}: vuln crashed=${vulnScan.crashed}/${vulnScan.total_files}, fixed crashed=${fixedScan.crashed}/${fixedScan.total_files}`)

  if (fixedScan.crashed === 0) {
    fixedClean = true
    break
  }

  const patchJudgment = await agent(
    `Corpus scan found ${fixedScan.crashed} crashing input(s) on the FIXED build (fix_commit=${commitJson.fix_commit}) that should have been clean -- this benchmark requires the differential oracle (vuln crashes, fixed doesn't) to be stable. Crash summaries: ${JSON.stringify(fixedScan.summaries)}. This means the fix commit itself likely introduced or left behind a separate, unrelated bug (there's a documented real precedent for exactly this in this benchmark's PROVENANCE.md files). Investigate the root cause by reading the source at the scratch clone /tmp/fbbench-src-${reportJson.project} checked out at commit ${commitJson.fix_commit}, then write the SMALLEST correct patch that fixes just this regression (a plain unified diff). This patch is LOCAL-ONLY -- never apply it to vuln_commit or upstream, it is only ever spliced into this bug's own fixed-asan oracle build. Save it as tools/fixes/${bugId}-<short-desc>.patch (relative to ${ANSWERS_REPO}) and return that relative path as patch_path.`,
    { schema: PATCH_SCHEMA, label: `patch-fixed-asan-${corpusAttempt}`, phase: 'Corpus scan', agentType: 'general-purpose' }
  )
  if (!patchJudgment) {
    log(`patch-fixed-asan-${corpusAttempt} agent call returned null (skipped or errored) -- no patch applied this round, will retry if attempts remain`)
    continue
  }
  await writeFile(`${ANSWERS_REPO}/${patchJudgment.patch_path}`, patchJudgment.patch_content, `write-patch-${corpusAttempt}`, 'Corpus scan')
  patchPath = patchJudgment.patch_path
  commitJson.provenance_extra = (commitJson.provenance_extra || []).concat([patchJudgment.provenance_writeup])
}

if (!fixedClean) {
  throw new Error(`fixed-asan corpus scan still not clean after ${MAX_CORPUS_FIX_ATTEMPTS} patch attempts -- escalating to a human rather than shipping an unstable differential oracle.`)
}

// =========================================================================
// Phase: Metadata  --  [E] mechanical generation, [J] only a cheap review
// of the auto-drafted grading oracle (expected.yaml is the actual answer
// key, so an error here silently breaks the whole bug)
// =========================================================================
phase('Metadata')

const expectedDraft = await runScript(
  `python3 gen_expected_yaml.py --harness ${bugDir}/binaries/release-asan/harness --poc ${bugDir}/poc/poc.bin --src-dir /tmp/fbbench-src-${reportJson.project}`,
  'gen-expected-draft', 'Metadata'
)

const expectedReview = await agent(
  `Review this auto-drafted grading-oracle answer key before it's written to disk. grader/expected.yaml is the actual answer used to grade agents on this challenge -- an error here silently breaks the whole bug, so check it carefully. Draft: ${JSON.stringify(expectedDraft)}. Confirm the reach/site anchor points at the REAL buggy function/line (not the fuzzer harness entrypoint, not an unrelated helper), and that line_tolerance/max_frame_distance are reasonable for this benchmark's convention (tolerance roughly 5-10, max_frame_distance roughly 3). If the draft's yaml_draft field already looks correct, return it as yaml_final unchanged along with its reach/class/site fields; otherwise correct the fields and produce a corrected yaml_final (same shape/style as the draft, just with fixed values).`,
  { schema: EXPECTED_REVIEW_SCHEMA, label: 'review-expected-yaml', phase: 'Metadata', agentType: 'general-purpose' }
)
if (!expectedReview) {
  throw new Error('review-expected-yaml agent call returned null (skipped or errored) -- refusing to write an unreviewed grading oracle. Re-run the workflow (resumeFromRunId) once the underlying issue is understood.')
}
await writeFile(`${bugDir}/grader/expected.yaml`, expectedReview.yaml_final, 'write-expected-yaml', 'Metadata')

const opInfo = classifyFromAsanSummary(commitJson.repro_vuln.reproduce && commitJson.repro_vuln.reproduce.asan_summary)
if (opInfo) {
  await runScript(
    `python3 add_curated_category.py --answers-repo ${ANSWERS_REPO} --bug-id ${bugId} --category ${opInfo.category} --reason "auto-derived from ASan ${opInfo.op} op by fbbench-add-bug workflow"`,
    'add-curated-category', 'Metadata'
  )
} else {
  log(`Crash op is not a simple ASan READ/WRITE spatial overflow -- vuln.yaml category will come out "unclassified" and needs a human _CURATED entry later.`)
}

await runVenvScriptText(`.venv/bin/python3 tools/gen_vuln_yaml.py --bug ${bugId}`, 'gen-vuln-yaml-1', 'Metadata')
await runVenvScriptText(`.venv/bin/python3 tools/gen_vuln_yaml.py --bug ${bugId}`, 'gen-vuln-yaml-2', 'Metadata') // re-run per SOP: picks up the just-added curated category
await runVenvScriptText(`.venv/bin/python3 tools/diffscan_freeze.py --bug ${bugId}`, 'diffscan-freeze', 'Metadata')

const capabilitySet = harnessMeta.capability_set || ['reach', 'crash', 'differential', 'class', 'site']
const privateBenchYaml = renderPrivateBenchYaml({
  bug_id: bugId,
  project: reportJson.project,
  title: reportJson.title,
  upstream_report: reportJson.upstream_report_url,
  repo: harnessMeta.repo || commitJson.repo_url,
  vuln_commit: commitJson.vuln_commit,
  fix_commit: commitJson.fix_commit,
  fix_patch: commitJson.fix_patch_needed ? patchPath : null,
  language: harnessMeta.language,
  build_system: harnessMeta.build_system,
  harness: harnessMeta.harness,
  capability_set: capabilitySet,
  disclosed: args.disclosedDate || null,
})
await writeFile(`${bugDir}/bench.yaml`, privateBenchYaml, 'write-private-bench-yaml', 'Metadata')

// =========================================================================
// Phase: Public scaffold  --  fully mechanical: alias + field-filtered
// bench.yaml. No README.md / CHALLENGES.md updates (out of scope).
// =========================================================================
phase('Public scaffold')

const aliasInfo = await runScript(
  `python3 compute_alias.py --project ${reportJson.project} --new-bug-id ${bugId} --answers-repo ${ANSWERS_REPO}`,
  'compute-alias', 'Public scaffold'
)
if (aliasInfo.would_renumber && aliasInfo.would_renumber.length) {
  throw new Error(`Adding ${bugId} would renumber already-shipped public aliases: ${JSON.stringify(aliasInfo.would_renumber)}. Stopping for a human decision rather than silently reshuffling published Docker tags.`)
}
const alias = aliasInfo.alias
log(`Public alias: ${alias}`)

const publicBenchYaml = renderPublicBenchYaml({
  alias,
  project: reportJson.project,
  language: harnessMeta.language,
  build_system: harnessMeta.build_system,
  harness: harnessMeta.harness,
})
await writeFile(`${PUBLIC_REPO}/bugs/${reportJson.project}/${alias}/bench.yaml`, publicBenchYaml, 'write-public-bench-yaml', 'Public scaffold')
if (!sibling.found) {
  // Only copy harness/build.sh into the public repo when it isn't already
  // covered by an existing sibling's public entry for this project.
  for (const relPath of Object.keys(harnessFiles)) {
    const content = harnessFiles[relPath]
    if (content == null) continue
    await writeFile(`${PUBLIC_REPO}/bugs/${reportJson.project}/${alias}/harness/${relPath}`, content, `write-public-harness-${relPath}`, 'Public scaffold')
  }
}

// =========================================================================
// Phase: Narrative  --  [J] the one genuinely prose-writing judgment point
// =========================================================================
phase('Narrative')

const narrative = await agent(
  `Write the two human-readable writeups for this new bug bundle at ${bugDir}.\n` +
  `Report: ${JSON.stringify(reportJson)}\n` +
  `Commit choice: ${JSON.stringify({ branch: commitJson.branch, vuln_commit: commitJson.vuln_commit, fix_commit: commitJson.fix_commit, unusable_reason: commitJson.unusable_reason })}\n` +
  `Confirmed symbolized trace (from the real release-asan build): ${JSON.stringify(expectedReview)}\n` +
  `Corpus scan summary: vuln build crashed=${vulnScanInfo.crashed}/${vulnScanInfo.total_files}, other-summary crashes noted (non-blocking): ${JSON.stringify((vulnScanInfo.summaries || []).filter(s => !s.summary || !s.summary.includes(expectedReview.class.expected)))}\n` +
  (commitJson.provenance_extra ? `Unrelated regression found+patched in the fixed build (include this in PROVENANCE.md as its own section): ${JSON.stringify(commitJson.provenance_extra)}\n` : '') +
  (args.upstream ? `Upstream provenance note (source this section directly, don't invent it): read ${args.upstream}\n` : '') +
  `Write description.txt as a root-cause writeup: summary, the exact buggy file:line, the call chain from the confirmed ASan trace, an explanation of the harness (which upstream fuzz target it is and why it reaches this code), and a reference to the upstream fix. Write PROVENANCE.md as: upstream report link, regression window, introducing/vuln/fix commits with how they were verified, CVE status if known, discovery method, root cause section, harness FP-screen section, and (if applicable) the unrelated-regression-in-fixed-build section describing the local patch.`,
  { schema: NARRATIVE_SCHEMA, label: 'write-narrative', phase: 'Narrative', agentType: 'general-purpose' }
)
if (!narrative) {
  throw new Error('write-narrative agent call returned null (skipped or errored). Re-run the workflow (resumeFromRunId) once the underlying issue is understood.')
}
await writeFile(`${bugDir}/description.txt`, narrative.description_txt, 'write-description', 'Narrative')
await writeFile(`${bugDir}/PROVENANCE.md`, narrative.provenance_md, 'write-provenance', 'Narrative')

// =========================================================================
// Phase: Verify  --  [E] regrade with auto-remediation, [J] only as a
// last-resort fallback once both known gotchas are already ruled out
// =========================================================================
phase('Verify')

const llvm14 = await runScript(`python3 ensure_llvm14.py`, 'ensure-llvm14', 'Verify')
const symbolizerText = await execCmd(`which llvm-symbolizer || which llvm-symbolizer-14 || echo NONE`, 'find-symbolizer', 'Verify')
const symbolizerPath = symbolizerText.trim().split('\n').pop().trim()

let regradeResult = null
let regradeAttempt = 0
while (regradeAttempt < MAX_REGRADE_ATTEMPTS) {
  regradeAttempt++
  const flags = []
  if (llvm14 && llvm14.cached && llvm14.path) flags.push(`--llvm14-path ${llvm14.path}`)
  if (symbolizerPath && symbolizerPath !== 'NONE') flags.push(`--asan-symbolizer ${symbolizerPath}`)
  regradeResult = await runScript(
    `python3 regrade_verify.py --bug-id ${bugId} --poc ${bugDir}/poc/poc.bin --answers-repo ${ANSWERS_REPO} ${flags.join(' ')}`,
    `regrade-verify-${regradeAttempt}`, 'Verify'
  )
  log(`Regrade attempt ${regradeAttempt}: solved=${regradeResult.solved} fired=${JSON.stringify(regradeResult.fired)} missing=${JSON.stringify(regradeResult.missing)}`)
  if (regradeResult.solved) break

  if (regradeAttempt < MAX_REGRADE_ATTEMPTS) {
    // Both known gotchas (llvm14 path, ASAN_SYMBOLIZER_PATH) are already
    // applied above every attempt -- a repeat failure means something else
    // is wrong, worth a judgment pass before trying again.
    const fallback = await agent(
      `regrade_verify.py reports the new bug ${bugId} did NOT solve: ${JSON.stringify(regradeResult)}. Both known silent-failure gotchas (llvm-profdata/llvm-cov version mismatch, missing ASAN_SYMBOLIZER_PATH) were already applied to this run, so this is something else. Diagnose why (read ${bugDir}/grader/expected.yaml, ${bugDir}/bench.yaml, and the raw_stdout in the result above) and decide the next action.`,
      { schema: REGRADE_FALLBACK_SCHEMA, label: `regrade-fallback-${regradeAttempt}`, phase: 'Verify', agentType: 'general-purpose' }
    )
    if (!fallback) {
      log(`regrade-fallback-${regradeAttempt} agent call returned null (skipped or errored) -- no remediation applied this round, will retry if attempts remain`)
    } else {
      log(`Regrade fallback diagnosis: ${fallback.diagnosis} -> action=${fallback.action}`)
      if (fallback.action === 'regen_expected_yaml') {
        const redraft = await runScript(
          `python3 gen_expected_yaml.py --harness ${bugDir}/binaries/release-asan/harness --poc ${bugDir}/poc/poc.bin --src-dir /tmp/fbbench-src-${reportJson.project}`,
          `regen-expected-${regradeAttempt}`, 'Verify'
        )
        await writeFile(`${bugDir}/grader/expected.yaml`, redraft.yaml_draft, `write-expected-retry-${regradeAttempt}`, 'Verify')
      } else if (fallback.action === 'rebuild_binaries') {
        await runScript(`python3 build_binaries.py --bug-dir ${bugDir} --config release-asan --vuln-commit ${commitJson.vuln_commit} --keep-image`, `rebuild-release-${regradeAttempt}`, 'Verify')
      } else if (fallback.action === 'manual_edit' && fallback.edit) {
        log(`Manual edit suggested but not auto-applied (needs human review): ${JSON.stringify(fallback.edit)}`)
        break
      }
    }
  }
}

if (!regradeResult || !regradeResult.solved) {
  throw new Error(`Bug ${bugId} did not reach SOLVED=True after ${MAX_REGRADE_ATTEMPTS} regrade attempts. Missing: ${JSON.stringify(regradeResult && regradeResult.missing)}. Stopping before building/committing an unverified bug.`)
}

// =========================================================================
// Phase: Public image  --  [E] build + leak-audit, [J] only the changelog
// scrub decision (SOP documents real false positives/negatives here)
// =========================================================================
phase('Public image')

const gradeUrlFlag = args.gradeUrl ? `--grade-url ${args.gradeUrl}` : ''
const ctxText = await runVenvScriptText(`.venv/bin/python3 tools/sealed/build_challenge.py ${bugId} --no-build ${gradeUrlFlag}`, 'build-challenge-noBuild', 'Public image')
const ctxMatch = /context ready at (\S+)/.exec(ctxText)
if (!ctxMatch) throw new Error(`Could not find "context ready at ..." in build_challenge.py --no-build output: ${ctxText.slice(0, 500)}`)
const ctxDir = ctxMatch[1]

const scrubCandidates = await runScript(`python3 scrub_changelog.py --context-dir ${ctxDir}/bundle/src`, 'scrub-candidates', 'Public image')
let deletedFiles = []
if ((scrubCandidates.name_sweep && scrubCandidates.name_sweep.length) || (scrubCandidates.content_sweep && scrubCandidates.content_sweep.length)) {
  const scrubDecision = await agent(
    `Decide which of these candidate files should be DELETED from the public challenge image's source bundle because they document this project's OWN past bug/security history (which would leak the answer or hint at similar bugs), vs. KEPT because they're generic (e.g. a security-policy README section that isn't about a specific past defect). Candidates with excerpts: ${JSON.stringify(scrubCandidates)}. Known false-positive pattern to watch for: test fixtures that just happen to have "changelog" in their name/path are NOT real changelogs -- keep those. Known false-negative risk: don't just check the name sweep, a real NEWS/CHANGELOG file that got caught by the name sweep should virtually always be deleted.`,
    { schema: CHANGELOG_DECISION_SCHEMA, label: 'changelog-scrub-decision', phase: 'Public image', agentType: 'general-purpose' }
  )
  if (!scrubDecision) {
    throw new Error('changelog-scrub-decision agent call returned null (skipped or errored) -- refusing to build the public image without a scrub decision, since candidates were found that could leak project history. Re-run the workflow (resumeFromRunId) once the underlying issue is understood.')
  }
  if (scrubDecision.delete && scrubDecision.delete.length) {
    const applied = await runScript(`python3 scrub_changelog.py --context-dir ${ctxDir}/bundle/src --apply ${scrubDecision.delete.join(',')}`, 'scrub-apply', 'Public image')
    deletedFiles = applied.deleted || []
    log(`Scrubbed from public image: ${JSON.stringify(deletedFiles)}`)
  }
}

const buildTag = `fbbench-challenge/${alias}:latest`
const pushTag = `docker.io/chenzc2001/fbbench-challenge-${alias}:latest`
await execCmd(`docker build -t ${buildTag} ${ctxDir}`, 'docker-build-final', 'Public image')
await execCmd(`docker tag ${buildTag} ${pushTag}`, 'docker-tag-pushname', 'Public image')

const srcCountText = await execCmd(`find ${bugDir}/../*/src -name '*.c' -o -name '*.h' 2>/dev/null | wc -l || echo 0`, 'src-count-before', 'Public image')
const verify = await runScript(
  `python3 verify_public_image.py --image ${buildTag} --expected-function "${expectedReview.reach.expected_function}"`,
  'verify-public-image', 'Public image'
)
if (!verify.ok) {
  throw new Error(`verify_public_image.py reported problems, stopping before commit: ${JSON.stringify(verify)}`)
}
log(`Public image ${buildTag} verified clean (tagged for push as ${pushTag}, NOT pushed).`)

// =========================================================================
// Phase: Commit local  --  git commit BOTH repos, never push
// =========================================================================
phase('Commit local')

const commitMsgAnswers = `Add ${bugId} challenge (${reportJson.title})`
const commitMsgPublic = `Add ${alias} challenge (${reportJson.crash_type} in ${reportJson.project})`

await execCmd(`cd ${ANSWERS_REPO} && git add ${bugDirRel} ${patchPath ? patchPath : ''} && git commit -m ${JSON.stringify(commitMsgAnswers)}`, 'git-commit-answers', 'Commit local')
await execCmd(`cd ${PUBLIC_REPO} && git add bugs/${reportJson.project}/${alias} && git commit -m ${JSON.stringify(commitMsgPublic)}`, 'git-commit-public', 'Commit local')

log(`Definition of done: vuln_commit/fix_commit chosen (${commitJson.branch}); crash reproduced and confirmed against report; corpus differential-cleanliness scan clean (${MAX_CORPUS_FIX_ATTEMPTS - (fixedClean ? MAX_CORPUS_FIX_ATTEMPTS - corpusAttempt : 0)} attempt(s)); regrade_verify SOLVED=True with all capabilities fired; public image built, leak-audited, changelog-scrubbed, tagged (NOT pushed); both repos committed LOCALLY only -- no git push, no docker push. Awaiting explicit human confirmation before either.`)

return {
  bug_id: bugId,
  alias,
  project: reportJson.project,
  vuln_commit: commitJson.vuln_commit,
  fix_commit: commitJson.fix_commit,
  regrade: regradeResult,
  public_image_tag: pushTag,
  deleted_changelog_files: deletedFiles,
  answers_bug_dir: bugDir,
  public_bug_dir: `${PUBLIC_REPO}/bugs/${reportJson.project}/${alias}`,
  pushed: false,
}
