const PHASES = [
  { letter: "A", lo: 0, hi: 4, title: "Parse & locate the commits" },
  { letter: "B", lo: 5, hi: 11, title: "Harness, both builds, corpus cleanliness" },
  { letter: "C", lo: 12, hi: 16, title: "Generate the answer & challenge files" },
  { letter: "D", lo: 17, hi: 20, title: "Verify, ship the image, commit" },
];

let pollTimer = null;

function $(sel, root = document) {
  return root.querySelector(sel);
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function statusBadgeClass(status) {
  return "badge badge-" + status;
}

function stageCellClass(status) {
  return "stage-cell stage-" + status;
}

function bugIdFromPath() {
  const parts = location.pathname.split("/").filter(Boolean);
  return decodeURIComponent(parts[parts.length - 1] || "");
}

function captureLogState(root) {
  const box = $("details.log-box", root);
  if (!box) return null;
  const pre = $("pre", box);
  // Whether the view is pinned to the bottom has to be decided before the
  // swap, so a live tail keeps following new lines instead of freezing at an
  // offset that is stale the moment more output arrives.
  const atBottom = !pre || pre.scrollHeight - pre.scrollTop - pre.clientHeight < 8;
  return { open: box.open, scrollTop: pre ? pre.scrollTop : 0, atBottom };
}

function restoreLogState(root, prev) {
  if (!prev || !prev.open) return;
  const pre = $("details.log-box pre", root);
  if (!pre) return;
  pre.scrollTop = prev.atBottom ? pre.scrollHeight : prev.scrollTop;
}

function renderDetail(d) {
  const detail = $("#bug-detail");
  const label = d.bug_id || d.id;
  document.title = `${label} · add_vuln SOP`;
  // Same headline as the bug list: the issue's own summary, with the id after
  // it. Older runs carry no title and keep showing just the id.
  $("#page-title").textContent = d.title ? `${d.title} (${label})` : label;

  const stagesByPhase = PHASES.map((ph) => ({
    ...ph,
    stages: d.stages.filter((s) => s.phase === ph.letter),
  }));

  // The stage list already carries each stage's index, so the restart label
  // can name the position as well as the stage.
  const resumeIdx = (d.stages.find((s) => s.name === d.resume_stage) || {}).index;

  // The 4s poll re-renders this whole pane, which would otherwise slam the log
  // box shut and jump it back to the top on every tick -- exactly while a run
  // is live and the log is the thing worth reading. Carry the reader's own
  // open/scroll state across the swap; the failed-run default below only
  // applies on the first render, when there is no prior state to carry.
  const prevLog = captureLogState(detail);
  const logOpen = prevLog ? prevLog.open : d.overall_status === "failed";

  detail.innerHTML = `
    <div class="detail-head">
      <span class="${statusBadgeClass(d.overall_status)}">${escapeHtml(d.overall_status)}</span>
      ${d.pid_alive || d.overall_status === "queued"
        ? `<button id="cancel-btn" class="danger-btn">${d.pid_alive ? "Cancel run" : "Remove from queue"}</button>`
        : ""}
    </div>
    <dl class="meta-grid">
      <div class="meta-item">
        <dt>Date</dt>
        <dd>${escapeHtml(d.date)}</dd>
      </div>
      <div class="meta-item meta-wide">
        <dt>Upstream</dt>
        <dd><a href="${escapeHtml(d.upstream)}" target="_blank" rel="noopener noreferrer"
               title="${escapeHtml(d.upstream)}">${escapeHtml(d.upstream)}</a></dd>
      </div>
      <div class="meta-item meta-wide">
        <dt>PoC</dt>
        <dd><code title="${escapeHtml(d.poc_filename)}">${escapeHtml(d.poc_filename)}</code></dd>
      </div>
      <div class="meta-item">
        <dt>Run</dt>
        <dd><code>${escapeHtml(d.id)}</code></dd>
      </div>
    </dl>

    ${d.can_restart ? `
      <div class="restart-box">
        <div class="restart-line">
          <button id="restart-btn">Restart from Stage ${resumeIdx ?? "?"}: <code>${escapeHtml(d.resume_stage)}</code></button>
        </div>
        <p class="hint">Picks up at the first stage that isn't done &mdash; everything already
        finished is skipped, not rebuilt.</p>
        <div id="restart-error" class="errors" hidden></div>
      </div>
    ` : ""}

    ${stagesByPhase.map((ph) => `
      <div class="phase-block">
        <div class="phase-head">
          <span class="phase-letter">${ph.letter}</span>
          <span class="phase-title">${escapeHtml(ph.title)}</span>
          <span class="phase-range">stage ${ph.lo}&ndash;${ph.hi}</span>
        </div>
        <div class="phase-row">
          ${ph.stages.map((s) => `
            <div class="${stageCellClass(s.status)}" title="${escapeHtml(s.name)}: ${escapeHtml(s.status)}">
              <span class="stage-idx">${s.index}</span>
              <span class="stage-name">${escapeHtml(s.name)}</span>
            </div>
          `).join("")}
        </div>
      </div>
    `).join("")}

    <details class="log-box" ${logOpen ? "open" : ""}>
      <summary>run.log (tail)</summary>
      <pre>${escapeHtml(d.log_tail || "(empty)")}</pre>
    </details>
  `;

  restoreLogState(detail, prevLog);

  const cancelBtn = $("#cancel-btn");
  if (cancelBtn) {
    cancelBtn.addEventListener("click", async () => {
      cancelBtn.disabled = true;
      cancelBtn.textContent = "Cancelling...";
      await fetch(`/api/bugs/${encodeURIComponent(d.id)}/cancel`, { method: "POST" });
      load();
    });
  }

  const restartBtn = $("#restart-btn");
  if (restartBtn) {
    restartBtn.addEventListener("click", async () => {
      const errBox = $("#restart-error");
      errBox.hidden = true;
      restartBtn.disabled = true;
      restartBtn.textContent = "Restarting...";
      // No bug id sent: the run already has one (meta.json, or whatever
      // compute_alias recorded) and the backend reuses it. Restarting is
      // about resuming this bug, not renaming it.
      const res = await fetch(`/api/bugs/${encodeURIComponent(d.id)}/restart`,
                              { method: "POST" });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        errBox.hidden = false;
        errBox.textContent = (body.errors || ["restart failed"]).join("; ");
        restartBtn.disabled = false;
        restartBtn.textContent = "Restart";
        return;
      }
      load();  // re-renders and resumes polling
    });
  }
}

async function load() {
  const id = bugIdFromPath();
  const detail = $("#bug-detail");
  if (!id) {
    detail.innerHTML = "<p>No bug id in URL.</p>";
    return;
  }
  const res = await fetch(`/api/bugs/${encodeURIComponent(id)}`, { cache: "no-store" });
  if (!res.ok) {
    $("#page-title").textContent = id;
    detail.innerHTML = "<p>Not found.</p>";
    stopPolling();
    return;
  }
  const d = await res.json();
  renderDetail(d);

  // `queued` is watched too: it becomes `running` on its own once a slot
  // frees, with nothing on this page to trigger a reload.
  const isLive = (s) => s === "running" || s === "queued";
  stopPolling();
  if (isLive(d.overall_status)) {
    pollTimer = setInterval(async () => {
      const r = await fetch(`/api/bugs/${encodeURIComponent(id)}`, { cache: "no-store" });
      if (!r.ok) { stopPolling(); return; }
      const nd = await r.json();
      renderDetail(nd);
      if (!isLive(nd.overall_status)) stopPolling();
    }, 4000);
  }
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

load();
