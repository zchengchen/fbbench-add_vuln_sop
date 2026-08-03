let listPollTimer = null;

function $(sel, root = document) {
  return root.querySelector(sel);
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// --- tabs ---------------------------------------------------------------

function showTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
  if (name === "bugs") {
    loadBugList();
    startListPolling();
  } else {
    stopListPolling();
  }
}

function initTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      location.hash = btn.dataset.tab === "bugs" ? "#bugs" : "";
      showTab(btn.dataset.tab);
    });
  });
  // A bug page's back link is /#bugs, so landing here with that hash should
  // open the list it came from rather than dumping you on the submit form.
  if (location.hash === "#bugs") showTab("bugs");
}

// --- submit form ----------------------------------------------------------

// Static files are served straight off disk, so the browser can be running a
// NEWER page than the Python process that answers its API calls -- an endpoint
// added since the webapp started 405s with an HTML body, and blindly calling
// res.json() on that reports it as an unreadable SyntaxError. Name the actual
// problem instead.
async function readJson(res) {
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return await res.json();
  throw new Error(
    `server returned ${res.status} ${res.statusText} as ${ct || "an unknown type"}, not JSON. ` +
    `The webapp process is probably older than this page -- restart it ` +
    `(python3 AddVulnSOP/webapp/app.py) and reload.`
  );
}

// Drop bytes fetched from the tracker into the file input, so an auto-filled
// PoC and a hand-picked one are the same thing by the time Submit runs -- the
// operator can still see it, and still replace it.
function setPocFile(name, b64) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  const dt = new DataTransfer();
  dt.items.add(new File([buf], name, { type: "application/octet-stream" }));
  $("#f-poc").files = dt.files;
}

function initFetch() {
  const btn = $("#fetch-btn");
  const urlInput = $("#f-upstream");
  const status = $("#fetch-status");

  const say = (cls, html) => {
    status.hidden = false;
    status.className = "fetch-status " + cls;
    status.innerHTML = html;
  };

  btn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (!url) {
      say("err", "Enter the issue URL first.");
      return;
    }
    btn.disabled = true;
    btn.textContent = "Fetching...";
    say("busy", "Reading the issue...");
    try {
      const fd = new FormData();
      fd.append("upstream", url);
      const res = await fetch("/api/fetch-upstream", { method: "POST", body: fd });
      const d = await readJson(res);
      if (!res.ok) {
        say("err", (d.errors || ["fetch failed"]).map(escapeHtml).join("<br>"));
        return;
      }
      // Only overwrite what actually came back: a partial scrape must not wipe
      // fields the operator already filled in by hand.
      if (d.title) $("#f-title").value = d.title;
      if (d.filed_at_display) $("#f-date").value = d.filed_at_display;
      if (d.report_text) $("#f-report").value = d.report_text;
      if (d.poc_b64) setPocFile(d.poc_filename, d.poc_b64);

      const got = [
        d.title && "title",
        d.filed_at_display && "date",
        d.report_text && "report",
        d.poc_b64 && `PoC (${d.poc_filename}, ${d.poc_size} bytes)`,
      ].filter(Boolean);
      const warn = (d.warnings || []).map(escapeHtml).join("<br>");
      say(warn ? "warn" : "ok",
          `Filled in: ${escapeHtml(got.join(", ") || "nothing")}.` +
          (warn ? `<br>${warn}` : "") +
          `<br>Bug ID is yours to choose &mdash; it is never auto-assigned.`);
    } catch (err) {
      say("err", escapeHtml(err.message || String(err)));
    } finally {
      btn.disabled = false;
      btn.textContent = "Fetch";
    }
  });
}

function initForm() {
  const form = $("#submit-form");
  const pocInput = $("#f-poc");
  const bugIdInput = $("#f-bug-id");
  const errBox = $("#form-errors");
  const submitBtn = $("#submit-btn");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errBox.hidden = true;
    errBox.innerHTML = "";

    const pocFile = pocInput.files[0];
    if (pocFile && /\.txt$/i.test(pocFile.name)) {
      errBox.hidden = false;
      errBox.textContent = "PoC file must not be a .txt file.";
      return;
    }

    const bugId = bugIdInput.value.trim();
    if (!bugId) {
      errBox.hidden = false;
      errBox.textContent = "Bug ID is required.";
      return;
    }
    if (!/^[A-Za-z0-9_.-]+$/.test(bugId)) {
      errBox.hidden = false;
      errBox.textContent = "Bug ID may only contain letters, digits, '-', '_', '.'.";
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "Submitting...";
    try {
      const fd = new FormData(form);
      const res = await fetch("/api/bugs", { method: "POST", body: fd });
      const body = await readJson(res);
      if (!res.ok) {
        errBox.hidden = false;
        errBox.innerHTML = (body.errors || ["submit failed"]).map(escapeHtml).join("<br>");
        return;
      }
      // Real navigation to the bug's own page -- not an in-page toggle.
      location.href = `/bugs/${encodeURIComponent(body.id)}`;
    } catch (err) {
      errBox.hidden = false;
      errBox.textContent = "Network error: " + err;
      submitBtn.disabled = false;
      submitBtn.textContent = "Submit & start pipeline";
    }
  });
}

// --- bug list ---------------------------------------------------------

function statusBadgeClass(status) {
  return "badge badge-" + status;
}

async function loadCapacity() {
  const box = $("#capacity");
  try {
    const c = await (await fetch("/api/capacity", { cache: "no-store" })).json();
    const dots = Array.from({ length: c.max_parallel }, (_, i) =>
      `<span class="cap-dot${i < c.running ? " busy" : ""}"></span>`).join("");
    box.innerHTML = `<span class="cap-dots">${dots}</span>`
      + `<span>${c.running} of ${c.max_parallel} running</span>`
      + (c.queued ? `<span class="cap-queued">&middot; ${c.queued} queued</span>` : "");
    box.hidden = false;
  } catch {
    box.hidden = true;
  }
}

// "libxml2:html: Heap-buffer-overflow in xmlSAX2Text (libxml2-05)". Bugs
// submitted before the title field existed have none, so fall back to the bare
// id rather than rendering an empty headline with a parenthesised id after it.
function bugHeadline(b) {
  const id = b.bug_id || b.id;
  return b.title
    ? `${escapeHtml(b.title)} <span class="bug-headline-id">(${escapeHtml(id)})</span>`
    : escapeHtml(id);
}

async function loadBugList() {
  const list = $("#bug-list");
  loadCapacity();
  const res = await fetch("/api/bugs", { cache: "no-store" });
  const bugs = await res.json();
  if (!bugs.length) {
    list.innerHTML = '<p class="empty">No bugs submitted yet.</p>';
    stopListPolling();
    return;
  }
  list.innerHTML = bugs.map((b) => `
    <a class="bug-card" href="/bugs/${encodeURIComponent(b.id)}">
      <div class="bug-card-main">
        <span class="bug-id">${bugHeadline(b)}</span>
        <span class="bug-date">${escapeHtml(b.date)} &middot; ${escapeHtml(b.id)}</span>
      </div>
      <div class="bug-card-side">
        <span class="progress">${b.done_count}/${b.total_stages}</span>
        <span class="${statusBadgeClass(b.overall_status)}">${escapeHtml(b.overall_status)}</span>
      </div>
    </a>
  `).join("");

  // Keep polling while anything is running OR waiting for a slot -- a queued
  // run flips to running on its own, with no user action to trigger a reload.
  if (!bugs.some((b) => b.overall_status === "running" || b.overall_status === "queued")) {
    stopListPolling();
  }
}

function startListPolling() {
  if (listPollTimer) return;
  listPollTimer = setInterval(loadBugList, 4000);
}

function stopListPolling() {
  if (listPollTimer) {
    clearInterval(listPollTimer);
    listPollTimer = null;
  }
}

initTabs();
initFetch();
initForm();
