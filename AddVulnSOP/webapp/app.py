#!/usr/bin/env python3
"""Local web UI for the fbbench add_vuln SOP.

Lets an operator submit a new bug (date + report text + PoC upload) and
watch it move through the same pipeline.py stages, instead of hand-
crafting a report-dir and running the CLI. Submitting a bug auto-starts the
real `pipeline.py run` as a background subprocess -- this WILL shell out to
docker/git/claude and can run for hours and incur billed API usage.

Local, single-operator tool only: binds to 127.0.0.1, no auth.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

WEBAPP_DIR = Path(__file__).resolve().parent
ADDVULNSOP_DIR = WEBAPP_DIR.parent
SOP_DIR = ADDVULNSOP_DIR.parent
SUBMISSIONS_DIR = WEBAPP_DIR / "submissions"
PIPELINE_SCRIPT = ADDVULNSOP_DIR / "pipeline.py"

sys.path.insert(0, str(ADDVULNSOP_DIR))
from pipeline import STAGE_NAMES  # noqa: E402  (reuse the real stage list, never re-list it here)
import fetch_oss_fuzz_issue  # noqa: E402  (backs the Fetch button; see /api/fetch-upstream)

# The 4 documented phases (see fbbench-add_vuln_sop/README.md), each named by
# the stage it STARTS at.
#
# These were index ranges once -- ("A", 0, 4), ("B", 5, 11) and so on. Index
# ranges are only correct for one particular stage list: removing a stage
# shifts every later index and silently reassigns the phases (a build stage
# starts rendering under "verify"), with nothing to fail. Anchoring on names
# means a removed boundary stage is a loud KeyError here instead.
PHASE_STARTS = [
    ("A", "parse_report",       "Parse the report & locate the vulnerable commit"),
    ("B", "scaffold_harness",   "Harness and the ASan build"),
    ("C", "gen_expected_yaml",  "Generate the answer & challenge files"),
    ("D", "verify_signature",   "Verify, ship the image, commit"),
]


def _phase_bounds() -> list[tuple[str, int, int, str]]:
    starts = []
    for letter, stage, title in PHASE_STARTS:
        if stage not in STAGE_NAMES:
            raise KeyError(
                f"phase {letter} starts at stage {stage!r}, which is not in the pipeline's "
                f"stage list -- update PHASE_STARTS to match pipeline.STAGES")
        starts.append((letter, STAGE_NAMES.index(stage), title))
    bounds = []
    for i, (letter, lo, title) in enumerate(starts):
        hi = starts[i + 1][1] - 1 if i + 1 < len(starts) else len(STAGE_NAMES) - 1
        bounds.append((letter, lo, hi, title))
    return bounds


PHASES = _phase_bounds()


def phase_for(index: int) -> str:
    """Phase letter for a ZERO-based stage index (the position in STAGE_NAMES).

    Display numbering is 1-based and applied at the API boundary only -- see
    phases_payload() and stage_status_list(). Keeping the internal index
    0-based means it still lines up with STAGE_NAMES, so the two numbering
    schemes can't drift into each other.
    """
    for letter, lo, hi, _title in PHASES:
        if lo <= index <= hi:
            return letter
    return "?"


def phases_payload() -> list[dict]:
    """Phase bounds for the UI, renumbered 1-based.

    Served rather than duplicated in JS: the page used to carry its own copy of
    these bounds, which silently went stale the moment a stage was added or
    removed -- it kept rendering "stage 17-20" for a pipeline that no longer
    had 21 stages. Derived here, there is one definition and it cannot drift.
    """
    return [{"letter": letter, "lo": lo + 1, "hi": hi + 1, "title": title}
            for letter, lo, hi, title in PHASES]


app = Flask(__name__, static_folder=str(WEBAPP_DIR / "static"), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB PoC upload cap

SUBMISSIONS_DIR.mkdir(parents=True, exist_ok=True)

# How many pipelines may run at once (--max-parallel). Each one drives Docker
# builds, a full corpus scan and billed agent calls, so an unbounded fan-out
# will happily saturate the machine. Submissions past the limit are QUEUED,
# not rejected: they sit with meta["pending"] set and the scheduler starts
# them as slots free up.
MAX_PARALLEL = 5
_SCHED_LOCK = threading.Lock()
SCHEDULER_TICK_S = 3.0


@app.after_request
def _no_store_api(resp):
    # The detail/list pages poll these every few seconds -- a browser (or an
    # intermediary) caching a GET response here means the poll fires but
    # silently keeps re-rendering stale data, which looks exactly like "it
    # doesn't auto-update." Belt-and-suspenders alongside fetch(..., {cache:
    # "no-store"}) on the client side.
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------------------
# submission storage helpers


def sub_dir(sub_id: str) -> Path:
    return SUBMISSIONS_DIR / sub_id


def read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=False))


# In-memory handle to each spawned subprocess, keyed by sub_id. Holding the
# Popen object (rather than just the bare pid) is what lets us reap it via
# poll()/wait() as it finishes -- without this, a Popen whose object is
# garbage-collected before its child exits can never be reaped by this
# process, and the pid lingers as a zombie that os.kill(pid, 0) reports as
# "alive" forever.
_PROCS: dict[str, subprocess.Popen] = {}


def pid_alive(sub_id: str, pid: int | None) -> bool:
    if not pid:
        return False
    proc = _PROCS.get(sub_id)
    if proc is not None:
        return proc.poll() is None
    # No in-memory handle (e.g. this webapp process was restarted since the
    # pipeline was launched). Its old parent is gone, so if it's still
    # running the OS has already re-parented it to init, which reaps it on
    # exit -- a plain existence check is safe here.
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def resume_stage(state: dict | None) -> str | None:
    """Which stage a restart should resume AT: the first one that isn't done.
    pipeline.py's own runner skips `done` stages, so resuming here re-runs the
    failed stage itself and everything after it, and never redoes finished
    (expensive) work."""
    stages = (state or {}).get("stages", {})
    for name in STAGE_NAMES:
        if stages.get(name, {}).get("status") != "done":
            return name
    return None  # every stage done, nothing to resume


def resolve_bug_id(meta: dict, state: dict | None) -> str | None:
    """meta is authoritative for anything submitted through this form.

    The fallback reads a stage that no longer exists: `compute_alias` recorded
    the id it derived, back when ids were derived. It is kept because old
    submissions on disk still have that stage in their state file, and this is
    the only place their bug id survives -- for runs since, --bug-id is
    required and meta always carries it, so the fallback never fires.
    """
    if meta.get("bug_id"):
        return meta["bug_id"]
    ca = ((state or {}).get("stages", {}).get("compute_alias") or {}).get("data") or {}
    return ca.get("bug_id")


# ---------------------------------------------------------------------------
# scheduler -- at most MAX_PARALLEL pipelines in flight, rest queued


def _spawn(sub_id: str, d: Path, meta: dict) -> None:
    """Actually launch the queued run described by meta["pending"]."""
    pending = meta.get("pending") or {}
    bug_id = pending.get("bug_id")
    from_stage = pending.get("from_stage")

    cmd = [sys.executable, str(PIPELINE_SCRIPT), "run", "--report-dir", str(d), "--bug-id", bug_id]
    if from_stage:
        cmd += ["--from-stage", from_stage]

    log_path = d / "run.log"
    # A first run truncates; a restart appends after a marker so the previous
    # attempt's log (the reason you're restarting) survives.
    mode = "w" if pending.get("fresh_log") else "a"
    with open(log_path, mode) as log_f:
        if mode == "a":
            log_f.write(f"\n\n===== restart at {time.strftime('%Y-%m-%d %H:%M:%S')} "
                        f"— resuming from `{from_stage}` as {bug_id} =====\n")
            log_f.flush()
        proc = subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT, cwd=str(SOP_DIR))

    meta["pid"] = proc.pid
    meta["bug_id"] = bug_id
    meta["pending"] = None
    meta["started_at"] = time.time()
    write_json(d / "meta.json", meta)
    _PROCS[sub_id] = proc


def _scan_submissions() -> tuple[int, list[tuple[float, str, Path, dict]]]:
    """(live pipeline count, queued entries sorted oldest-first)."""
    live = 0
    queued: list[tuple[float, str, Path, dict]] = []
    for d in SUBMISSIONS_DIR.iterdir():
        if not d.is_dir():
            continue
        meta = read_json(d / "meta.json")
        if meta is None:
            continue
        if pid_alive(meta["sub_id"], meta.get("pid")):
            live += 1
        elif meta.get("pending"):
            queued.append((meta["pending"].get("queued_at") or meta.get("submitted_at") or 0.0,
                            meta["sub_id"], d, meta))
    queued.sort(key=lambda t: t[0])
    return live, queued


def pump_queue() -> None:
    """Start queued runs while there is capacity. Safe to call from anywhere;
    the lock keeps two callers from handing out the same slot twice."""
    with _SCHED_LOCK:
        live, queued = _scan_submissions()
        for _, sub_id, d, meta in queued:
            if live >= MAX_PARALLEL:
                break
            _spawn(sub_id, d, meta)
            live += 1


def capacity() -> dict:
    live, queued = _scan_submissions()
    return {"running": live, "queued": len(queued), "max_parallel": MAX_PARALLEL}


def _scheduler_loop() -> None:
    while True:
        time.sleep(SCHEDULER_TICK_S)
        try:
            pump_queue()
        except Exception as e:  # a scheduler that dies silently strands the queue
            print(f"[scheduler] {type(e).__name__}: {e}", file=sys.stderr, flush=True)


def stage_status_list(state: dict, running_process_alive: bool) -> list[dict]:
    stages = state.get("stages", {})
    result = []
    first_incomplete_seen = False
    for i, name in enumerate(STAGE_NAMES):
        entry = stages.get(name)
        if entry and entry.get("status") in ("done", "failed"):
            status = entry["status"]
        else:
            if not first_incomplete_seen:
                first_incomplete_seen = True
                status = "running" if running_process_alive else "pending"
            else:
                status = "pending"
        # index is 1-based for display; phase_for() takes the 0-based position.
        result.append({"index": i + 1, "name": name, "phase": phase_for(i), "status": status})
    return result


def overall_status(meta: dict, state: dict | None, alive: bool) -> str:
    if meta.get("cancelled") and not alive:
        return "stopped"
    if alive:
        return "running"
    if meta.get("pending"):
        return "queued"
    stages = (state or {}).get("stages", {})
    if stages and all(stages.get(n, {}).get("status") == "done" for n in STAGE_NAMES):
        return "done"
    if any(v.get("status") == "failed" for v in stages.values()):
        return "failed"
    if stages:
        return "stopped"
    return "pending"


def tail_lines(path: Path, n: int = 200) -> str:
    if not path.is_file():
        return ""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-n:])


# ---------------------------------------------------------------------------
# routes


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/bugs/<sub_id>")
def bug_page(sub_id: str):
    # A real, bookmarkable/refreshable page (not a JS-only in-page toggle).
    # Existence of sub_id isn't checked here -- the page's own JS fetches
    # /api/bugs/<id> and renders a "not found" state if it 404s.
    return send_from_directory(app.static_folder, "bug.html")


@app.post("/api/fetch-upstream")
def fetch_upstream():
    """Back the Submit form's Fetch button: one URL in, every other field out.

    Runs server-side because the browser cannot read issues.oss-fuzz.com
    cross-origin, and because the PoC download is a redirect chain that is far
    easier to follow here. Purely read-only -- it creates no submission, so a
    fetch that returns something wrong costs the operator nothing but a retry,
    and every field it fills stays editable by hand.
    """
    payload = request.get_json(silent=True) or {}
    url = (request.form.get("upstream") or payload.get("upstream") or "").strip()
    if not url:
        return jsonify({"errors": ["upstream URL is required"]}), 400
    try:
        result, poc_bytes = fetch_oss_fuzz_issue.fetch(url)
    except Exception as e:  # a scraper bound to an undocumented format: never 500 the UI
        return jsonify({"errors": [f"fetch failed: {e}"]}), 502
    if not result.get("ok"):
        return jsonify({"errors": [result.get("error") or
                                   "could not read that issue -- it may be private, or the "
                                   "tracker's page format changed"],
                        "warnings": result.get("warnings") or []}), 502
    if poc_bytes:
        result["poc_b64"] = base64.b64encode(poc_bytes).decode("ascii")
    return jsonify(result)


@app.post("/api/bugs")
def create_bug():
    date = (request.form.get("date") or "").strip()
    upstream = (request.form.get("upstream") or "").strip()
    report = (request.form.get("report") or "").strip()
    bug_id = (request.form.get("bug_id") or "").strip()
    title = (request.form.get("title") or "").strip()
    poc = request.files.get("poc")

    errors = []
    if not date:
        errors.append("date is required")
    if not upstream:
        errors.append("upstream URL is required")
    if not title:
        errors.append("title is required")
    if not report:
        errors.append("report is required")
    if not bug_id:
        errors.append("bug id is required")
    elif not re.fullmatch(r"[A-Za-z0-9_.-]+", bug_id):
        errors.append("bug id may only contain letters, digits, '-', '_', '.'")
    if poc is None or not poc.filename:
        errors.append("poc file is required")
    else:
        poc_name = secure_filename(poc.filename)
        if not poc_name:
            errors.append("poc filename is invalid")
        elif poc_name.lower().endswith(".txt") or poc_name.lower() == "report.txt":
            errors.append("poc must not be a .txt file (report text goes in the report field)")
    if errors:
        return jsonify({"errors": errors}), 400

    # Submission id carries the bug id rather than a random suffix, so the
    # directory, the /bugs/<id> URL and everything on screen say what this
    # run actually is. Timestamp-prefixed so re-running the same bug id keeps
    # its own dir + run.log instead of colliding (the OVERWRITE happens in
    # the repos, not here).
    sub_id = time.strftime("%Y%m%d-%H%M%S") + "-" + bug_id
    d = sub_dir(sub_id)
    if d.exists():
        sub_id = f"{sub_id}-{uuid.uuid4().hex[:4]}"
        d = sub_dir(sub_id)
    d.mkdir(parents=True)

    # `title:` joins the existing upstream/date header lines: parse_report reads
    # the whole bundle, so the issue's own one-line summary travels with the
    # report instead of living only in the web UI's metadata.
    (d / "report.txt").write_text(
        f"upstream: {upstream}\ndate: {date}\ntitle: {title}\n\n{report}\n")

    poc_name = secure_filename(poc.filename)
    poc.save(str(d / poc_name))

    now = time.time()
    meta = {
        "sub_id": sub_id,
        "bug_id": bug_id,
        "title": title,
        "date": date,
        "upstream": upstream,
        "submitted_at": now,
        "poc_filename": poc_name,
        "pid": None,
        "cancelled": False,
        # Enqueued rather than launched: the scheduler starts it as soon as
        # one of the MAX_PARALLEL slots is free (immediately, if under load).
        "pending": {"bug_id": bug_id, "from_stage": None, "fresh_log": True, "queued_at": now},
    }
    write_json(d / "meta.json", meta)

    pump_queue()
    return jsonify({"id": sub_id}), 201


@app.get("/api/bugs")
def list_bugs():
    out = []
    for d in sorted(SUBMISSIONS_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        meta = read_json(d / "meta.json")
        if meta is None:
            continue
        state = read_json(d / ".pipeline_state.json")
        alive = pid_alive(meta["sub_id"], meta.get("pid"))
        stages = (state or {}).get("stages", {})
        done_count = sum(1 for n in STAGE_NAMES if stages.get(n, {}).get("status") == "done")
        out.append({
            "id": meta["sub_id"],
            "bug_id": meta.get("bug_id"),
            "title": meta.get("title"),
            "date": meta["date"],
            "submitted_at": meta["submitted_at"],
            "poc_filename": meta.get("poc_filename"),
            "done_count": done_count,
            "total_stages": len(STAGE_NAMES),
            "overall_status": overall_status(meta, state, alive),
        })
    out.sort(key=lambda b: b["submitted_at"], reverse=True)
    return jsonify(out)


@app.get("/api/bugs/<sub_id>")
def get_bug(sub_id: str):
    d = sub_dir(secure_filename(sub_id))
    meta = read_json(d / "meta.json")
    if meta is None:
        return jsonify({"errors": ["not found"]}), 404
    state = read_json(d / ".pipeline_state.json")
    alive = pid_alive(meta["sub_id"], meta.get("pid"))
    return jsonify({
        "id": sub_id,
        "bug_id": meta.get("bug_id"),
        "title": meta.get("title"),
        "date": meta["date"],
        "upstream": meta.get("upstream"),
        "submitted_at": meta["submitted_at"],
        "poc_filename": meta.get("poc_filename"),
        "pid_alive": alive,
        "overall_status": overall_status(meta, state, alive),
        "stages": stage_status_list(state or {"stages": {}}, alive),
        "phases": phases_payload(),
        "log_tail": tail_lines(d / "run.log"),
        # What a Restart would do, computed here so the page doesn't have to
        # reimplement it. resume_bug_id is null for an old run that died
        # before its id was ever recorded -- the UI asks for it in that case.
        "resume_stage": resume_stage(state),
        "resume_bug_id": resolve_bug_id(meta, state),
        # A queued run is already going to start on its own -- offering
        # "Restart" for it would just double-enqueue.
        "can_restart": (not alive) and (not meta.get("pending"))
                        and resume_stage(state) is not None,
    })


@app.post("/api/bugs/<sub_id>/restart")
def restart_bug(sub_id: str):
    """Resume a stopped/failed run at its first not-done stage.

    Everything already marked `done` in .pipeline_state.json is skipped by
    pipeline.py itself, so this picks up exactly where it left off rather
    than redoing hours of Docker builds and billed agent calls.
    """
    sub_id = secure_filename(sub_id)
    d = sub_dir(sub_id)
    meta = read_json(d / "meta.json")
    if meta is None:
        return jsonify({"errors": ["not found"]}), 404

    if pid_alive(sub_id, meta.get("pid")):
        return jsonify({"errors": ["this run is still going -- cancel it first"]}), 409

    state = read_json(d / ".pipeline_state.json")
    stage = resume_stage(state)
    if stage is None:
        return jsonify({"errors": ["every stage is already done -- nothing to resume"]}), 400

    bug_id = (request.form.get("bug_id") or "").strip() or resolve_bug_id(meta, state)
    if not bug_id:
        return jsonify({"errors": ["bug id is required (this run never got far enough to "
                                    "record one) -- supply it to restart"]}), 400
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", bug_id):
        return jsonify({"errors": ["bug id may only contain letters, digits, '-', '_', '.'"]}), 400

    meta["cancelled"] = False
    meta["restarts"] = (meta.get("restarts") or 0) + 1
    # fresh_log=False -> _spawn appends after a marker instead of truncating.
    meta["pending"] = {"bug_id": bug_id, "from_stage": stage,
                        "fresh_log": False, "queued_at": time.time()}
    write_json(d / "meta.json", meta)

    pump_queue()
    return jsonify({"ok": True, "resumed_from": stage, "bug_id": bug_id})


@app.post("/api/bugs/<sub_id>/cancel")
def cancel_bug(sub_id: str):
    d = sub_dir(secure_filename(sub_id))
    meta = read_json(d / "meta.json")
    if meta is None:
        return jsonify({"errors": ["not found"]}), 404

    pid = meta.get("pid")
    proc = _PROCS.get(sub_id)
    if pid_alive(sub_id, pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        if proc is not None:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        else:
            for _ in range(20):  # ~2s grace period
                if not pid_alive(sub_id, pid):
                    break
                time.sleep(0.1)
        if pid_alive(sub_id, pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            if proc is not None:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    meta["cancelled"] = True
    # Also drop it from the queue -- cancelling something that hasn't started
    # yet must actually cancel it, not let the scheduler launch it seconds later.
    meta["pending"] = None
    write_json(d / "meta.json", meta)

    # Killing a run frees a slot; let whatever is queued take it right away
    # instead of waiting for the next scheduler tick.
    pump_queue()
    return jsonify({"ok": True})


@app.get("/api/capacity")
def get_capacity():
    return jsonify(capacity())


def main() -> None:
    global MAX_PARALLEL
    ap = argparse.ArgumentParser(
        description="Local web UI for the fbbench add_vuln SOP. Submissions beyond "
                    "--max-parallel are queued and started as slots free up."
    )
    ap.add_argument("--max-parallel", type=int, default=MAX_PARALLEL,
                     help=f"how many pipelines may run at once (default: {MAX_PARALLEL}). "
                          "Each drives Docker builds and billed agent calls.")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="127.0.0.1",
                     help="default 127.0.0.1 -- this tool has no auth, don't expose it")
    args = ap.parse_args()

    if args.max_parallel < 1:
        ap.error("--max-parallel must be at least 1")
    MAX_PARALLEL = args.max_parallel

    threading.Thread(target=_scheduler_loop, daemon=True).start()
    # Anything left `pending` by a previous process (webapp restarted while a
    # queue was waiting) gets picked up on this first pass.
    pump_queue()

    print(f" * max parallel pipelines: {MAX_PARALLEL}", flush=True)
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
