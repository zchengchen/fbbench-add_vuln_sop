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
      const body = await res.json();
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
        <span class="bug-id">${escapeHtml(b.bug_id || b.id)}</span>
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
initForm();
