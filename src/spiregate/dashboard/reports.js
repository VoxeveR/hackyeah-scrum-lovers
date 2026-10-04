/* SpireGate · Reports page: the background security analyst (every N requests) and the daily reports.
   Summaries, findings and recommendations are written by a model from log data that may contain attacker text:
   they reach the DOM only through esc(). Wiring: SpireReports.render(root, { api, esc, toast, token }). */
(function () {
  "use strict";

  const SEV = { critical: "tag-block", high: "tag-block", medium: "tag-escalate", low: "" };
  const BACKEND = { openai: "OpenAI", template: "Template (no model)", off: "Off" };
  const when = (iso) => (iso ? new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" }) : "—");
  const usd = (v) => `${Number(v || 0).toFixed(4)} USD`;

  function render(root, ctx) {
    if (!root) return;
    const { api, esc } = ctx;
    if (!root.dataset.ready) root.innerHTML = `<div class="empty">Loading…</div>`;
    api("/v1/admin/analyst").then((s) => paint(root, s, ctx)).catch(() => {
      root.innerHTML = `<div class="banner err">Could not load the analyst status.</div>`;
    });
    // keep the page fresh while it is open (the analyst runs in the background every N requests)
    clearInterval(root._timer);
    root._timer = setInterval(() => {
      if (!root.isConnected) { clearInterval(root._timer); return; }
      api("/v1/admin/analyst").then((s) => paint(root, s, ctx)).catch(() => {});
    }, 10000);
  }

  function paint(root, s, ctx) {
    const { esc } = ctx;
    root.dataset.ready = "1";
    if (!s.enabled) {
      root.innerHTML = `<div class="card" style="padding:20px"><b>The analyst is off.</b>
        <div class="card-sub">Add an <code>analyst:</code> section to the policy to turn it on.</div></div>`;
      return;
    }
    const left = Math.max(0, s.every_requests - s.pending);
    const status = `<section class="pol-group"><div class="pol-head"><h3>Security analyst</h3></div>
      ${s.last_error ? `<div class="banner err" style="margin:0 0 10px">${esc(s.last_error)}</div>` : ""}
      <div class="card pol-list"><div class="pol-row locked">
        <div class="pol-main"><div class="pol-title">${esc(BACKEND[s.backend] || s.backend)}${s.backend === "openai" ? ` · ${esc(s.model)}` : ""}${s.running ? ` · running ${esc(s.running)}…` : ""}</div>
          <div class="pol-detail" style="white-space:normal">assesses every ${esc(s.every_requests)} requests (next in ${esc(left)}) · daily report at ${esc(s.daily_report_at)} · spent today ${esc(usd(s.spent_today_usd))} of ${esc(usd(s.max_usd_per_day))}</div></div>
        <span class="pol-tag">advisory only</span><span class="pol-hits"></span>
        <div class="pol-actions" style="min-width:auto"><button class="btn" data-assess>Assess now</button><button class="btn primary" data-daily>Daily report</button></div>
      </div></div></section>`;
    root.innerHTML = `<div class="pol">${status}${latest(s.latest, esc)}${reports(s.reports, esc, ctx.token)}${history(s.history, esc)}</div>`;
    wire(root, ctx);
  }

  function latest(a, esc) {
    if (!a) return `<section class="pol-group"><div class="pol-head"><h3>Latest assessment</h3></div>
      <div class="card"><div class="empty">No assessment yet. One runs after the next batch of requests, or press “Assess now”.</div></div></section>`;
    const w = a.window || {};
    const findings = (a.findings || []).map((f) => `<div class="pol-row locked">
        <div class="pol-main"><div class="pol-title">${esc(f.title)}</div>
          <div class="pol-detail" style="white-space:normal">${esc(f.detail)} — ${esc(f.recommendation)}</div>
          <div class="pol-detail">evidence: ${esc((f.evidence || []).map((x) => "#" + x).join(", "))} · ${esc(f.source || "")}</div></div>
        <span class="pol-tag ${SEV[f.severity] || ""}">${esc(f.severity)}</span><span class="pol-hits"></span><div class="pol-actions"></div></div>`).join("");
    return `<section class="pol-group"><div class="pol-head"><h3>Latest assessment</h3><span>${esc(when(a.ts))}</span></div>
      <div class="card pol-list">
        <div class="pol-row locked"><div class="pol-main">
          <div class="pol-title">Posture ${esc(a.posture_score)}/100 · ${esc(a.risk_level)} risk</div>
          <div class="pol-detail" style="white-space:normal">${esc(a.summary)}</div>
          <div class="pol-detail">requests #${esc(w.seq ? w.seq[0] : "—")}–#${esc(w.seq ? w.seq[1] : "—")} (${esc(w.requests)}) · ${esc(BACKEND[a.backend] || a.backend)}${a.dropped ? ` · ${esc(a.dropped)} claims without evidence dropped` : ""}${a.note ? ` · ${esc(a.note)}` : ""}</div></div>
          <span class="pol-tag ${SEV[a.risk_level] || ""}">${esc(a.risk_level)}</span><span class="pol-hits"></span><div class="pol-actions"></div></div>
        ${findings || `<div class="pol-row locked"><div class="pol-main"><div class="pol-detail">No findings in this window.</div></div></div>`}
      </div></section>`;
  }

  function reports(list, esc, token) {
    const rows = (list || []).map((r) => `<div class="pol-row locked">
        <div class="pol-main"><div class="pol-title">${esc(r.date)} — ${esc(r.headline)}</div>
          <div class="pol-detail">posture ${esc(r.posture_score)}/100 · ${esc(r.risk_level)} risk · ${esc(BACKEND[r.backend] || r.backend)} · generated ${esc(when(r.generated_at))}</div></div>
        <span class="pol-tag ${SEV[r.risk_level] || ""}">${esc(r.risk_level)}</span><span class="pol-hits"></span>
        <div class="pol-actions" style="min-width:auto"><a class="btn" target="_blank" rel="noopener"
          href="/v1/admin/reports/daily/${encodeURIComponent(r.date)}.html?token=${encodeURIComponent(token || "")}">Open</a></div></div>`).join("");
    return `<section class="pol-group"><div class="pol-head"><h3>Daily reports</h3><span>${esc((list || []).length)}</span></div>
      <div class="card pol-list">${rows || `<div class="empty">No daily report yet.</div>`}</div></section>`;
  }

  function history(list, esc) {
    if (!list || !list.length) return "";
    const rows = list.map((h) => `<tr><td>${esc(when(h.ts))}</td><td>#${esc(h.window.seq ? h.window.seq[0] : "—")}–#${esc(h.window.seq ? h.window.seq[1] : "—")}</td>
      <td>${esc(h.window.requests)}</td><td>${esc(h.posture_score)}</td><td>${esc(h.risk_level)}</td><td>${esc(h.findings)}</td>
      <td>${esc(BACKEND[h.backend] || h.backend)}</td><td>${esc(usd(h.cost_usd))}</td></tr>`).join("");
    return `<section class="pol-group"><div class="pol-head"><h3>Assessment history</h3></div>
      <div class="card" style="overflow-x:auto"><table><thead><tr><th>Time</th><th>Requests</th><th>Count</th><th>Score</th><th>Risk</th>
      <th>Findings</th><th>Analyst</th><th>Cost</th></tr></thead><tbody>${rows}</tbody></table></div></section>`;
  }

  function wire(root, ctx) {
    const { api, toast } = ctx;
    const busy = (btn, fn) => async () => {
      btn.disabled = true;
      try { await fn(); } catch (e) { toast("Request failed"); }
      btn.disabled = false;
      render(root, ctx);
    };
    const a = root.querySelector("[data-assess]");
    if (a) a.onclick = busy(a, async () => {
      const r = await api("/v1/admin/analyst/run", { method: "POST", body: "{}" });
      const k = r.ok ? r.assessment.window.requests : 0;
      toast(r.ok ? `Assessed ${k} request${k === 1 ? "" : "s"}: ${r.assessment.posture_score}/100` : r.error || "Nothing new to assess");
    });
    const d = root.querySelector("[data-daily]");
    if (d) d.onclick = busy(d, async () => {
      const r = await api("/v1/admin/reports/daily", { method: "POST", body: "{}" });
      toast(r.ok ? `Daily report ${r.date} is ready` : "Could not write the report");
    });
  }

  window.SpireReports = { render };
})();
