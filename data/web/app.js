// No frameworks. Confirmation prompts and the host filter only.
document.addEventListener("submit", function (e) {
  var f = e.target, m = f.dataset.confirm;
  var b = e.submitter && e.submitter.dataset.confirm;
  if ((b || m) && !window.confirm(b || m)) e.preventDefault();
  else if (e.submitter) { e.submitter.disabled = false; setTimeout(function () { f.classList.add("busy"); }, 0); }
});
document.addEventListener("input", function (e) {
  var sel = e.target.dataset && e.target.dataset.filter;
  if (!sel) return;
  var q = e.target.value.toLowerCase();
  document.querySelectorAll(sel).forEach(function (r) {
    r.hidden = q && r.textContent.toLowerCase().indexOf(q) < 0;
  });
});
// "load from file" helpers for certificate textareas
document.addEventListener("change", function (e) {
  var sel = e.target.dataset && e.target.dataset.load;
  if (!sel || !e.target.files || !e.target.files[0]) return;
  var f = e.target.files[0];
  if (f.size > 100000) { window.alert("That file is too large for a certificate."); e.target.value = ""; return; }
  var r = new FileReader();
  r.onload = function () { document.querySelector(sel).value = r.result; e.target.value = ""; };
  r.readAsText(f);
});
// show the certificate boxes only when "My own certificate" is chosen
document.addEventListener("change", function (e) {
  if (e.target.name !== "cert") return;
  var box = document.getElementById("owncert");
  if (box) box.hidden = e.target.value !== "custom";
  var sh = document.getElementById("sharedcert");
  if (sh) sh.hidden = e.target.value !== "shared";
});
// "select all" for a list of checkboxes
document.addEventListener("change", function (e) {
  var sel = e.target.dataset && e.target.dataset.selectAll;
  if (!sel) return;
  document.querySelectorAll(sel).forEach(function (c) { c.checked = e.target.checked; });
});

// Certificates page: run "Renew selected" in the background and show a progress bar
(function () {
  var form = document.getElementById("certform"), box = document.getElementById("progress");
  if (!form || !box || !window.fetch) return;
  var bar = document.getElementById("p-bar"), text = document.getElementById("p-text"), title = document.getElementById("p-title");
  var list = document.getElementById("p-items"), log = document.getElementById("p-log"), reload = document.getElementById("p-reload");
  var timer = null;
  reload.addEventListener("click", function () { window.location.reload(); });

  function fmt(sec) { sec = Math.max(0, Math.round(sec)); return Math.floor(sec / 60) + ":" + ("0" + (sec % 60)).slice(-2); }
  function setButtons(off) { form.querySelectorAll("button").forEach(function (b) { b.disabled = off; }); }
  function pill(st) { return { pending: "", running: "info", ok: "ok", fail: "bad" }[st] || ""; }

  function render(v) {
    box.hidden = false;
    var running = v.state === "running";
    bar.max = Math.max(v.total, 1);
    title.textContent = running ? (v.title || "Working") + "…" : (v.ok ? "All done" : "Finished with problems");
    if (v.total === 0) bar.removeAttribute("value"); else bar.value = v.done;
    var cur = v.items.filter(function (i) { return i.state === "running"; })[0];
    text.textContent = (v.total ? v.done + " of " + v.total + " finished · " : (running ? "working · " : (v.items.length ? "" : "nothing needed doing · "))) + fmt(v.now - v.started) + " elapsed" +
      (running && cur ? " · now: " + cur.name + " (" + fmt(v.now - cur.since) + ")" : "") + (running ? " · " + v.phase : "");
    list.textContent = "";
    v.items.forEach(function (i) {
      var li = document.createElement("li"); li.className = "row";
      var main = document.createElement("div"); main.className = "main";
      var b = document.createElement("b"); b.textContent = i.name; main.appendChild(b);
      if (i.message) { var s = document.createElement("span"); s.className = "sub" + (i.state === "fail" ? " bad" : ""); s.textContent = i.message; main.appendChild(s); }
      var tag = document.createElement("span"); tag.className = "pill " + pill(i.state);
      tag.textContent = { pending: "waiting", running: "working", ok: "done", fail: "failed" }[i.state];
      li.appendChild(main); li.appendChild(tag); list.appendChild(li);
    });
    log.textContent = v.log;
    reload.hidden = running;
    setButtons(running);
  }

  function poll(id) {
    function tick() {
      fetch("/certs/job/" + id, { credentials: "same-origin" }).then(function (r) { return r.json(); }).then(function (v) {
        render(v);
        if (v.state === "running") timer = setTimeout(tick, 2000);
      }).catch(function () { timer = setTimeout(tick, 4000); });
    }
    tick();
  }

  if (box.dataset.job) poll(box.dataset.job);          // a job is already running: pick it up

  form.addEventListener("submit", function (e) {
    if (!e.submitter || ["selected", "issue", "force", "renew"].indexOf(e.submitter.value) < 0) return;
    e.stopPropagation();                                // we ask for confirmation ourselves
    e.preventDefault();
    var q = e.submitter.dataset.confirm;
    if (q && !window.confirm(q)) return;
    var fd = new FormData(form);
    fd.append("action", e.submitter.value);
    var btn = e.submitter, label = btn.textContent;
    btn.textContent = "Starting…"; setButtons(true);       // immediate feedback right where you clicked
    box.hidden = false; title.textContent = "Starting…"; text.textContent = "";
    box.scrollIntoView({ behavior: "smooth", block: "start" });   // the panel is above the (long) list
    fetch("/certs/job", { method: "POST", body: fd, credentials: "same-origin" }).then(function (r) {
      return r.json().then(function (d) { return { ok: r.ok, d: d }; });
    }).then(function (x) {
      btn.textContent = label;
      if (!x.ok) { setButtons(false); box.hidden = true; window.alert(x.d.error || "Could not start."); return; }
      poll(x.d.id);
    }).catch(function () {
      var h = document.createElement("input");           // fetch failed: fall back to the normal blocking form post
      h.type = "hidden"; h.name = "action"; h.value = btn.value; form.appendChild(h);
      form.submit();
    });
  });
})();

// top-bar indicator: is a background job running? (also on pages that do not show the progress panel)
(function () {
  var ind = document.getElementById("jobind"), txt = document.getElementById("jobtext");
  if (!ind || !window.fetch) return;
  function tick() {
    fetch("/jobs/active", { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        var j = d.running[0];
        ind.hidden = !j;
        if (j) txt.textContent = "Certs" + (j.total ? " " + j.done + "/" + j.total : "") + (d.running.length > 1 ? " +" + (d.running.length - 1) : "");
        setTimeout(tick, j ? 3000 : 8000);
      })
      .catch(function () { setTimeout(tick, 15000); });
  }
  setTimeout(tick, ind.hidden ? 8000 : 1500);
})();
