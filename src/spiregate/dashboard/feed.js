/* SpireGate · Signature feed card on the Policy page.
   Shows the signed bundle the gateway runs (version, key, validity, rejected updates) and, per signature,
   what this policy does with it. Signature titles and feed messages come from an external system: they
   reach the DOM only through esc(). Wiring: SpireFeed.render(slot, { api, esc, toast }) after each policy render. */
(function () {
  "use strict";

  const ACTION = { block: ["Blocks", "tag-block"], escalate: ["Review", "tag-escalate"], taint: ["Labels", "tag-taint"] };
  const PHASE = { prompt: "prompt", tool_call: "actions", tool_result: "results" };
  const SEVERITY = { critical: "critical", high: "high", medium: "medium", low: "low" };
  let last = null;   // last payload: a policy re-render paints at once, then refreshes

  const when = (iso) => (iso ? new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" }) : "—");

  function render(slot, { api, esc, toast }) {
    if (!slot) return;
    if (last) paint(slot, last, esc);
    api("/v1/admin/feed")
      .then((data) => { last = data; if (slot.isConnected) paint(slot, data, esc, { api, toast }); })
      .catch(() => { if (!last) slot.innerHTML = ""; });
  }

  function paint(slot, d, esc, ctx) {
    if (!d.configured) {
      slot.innerHTML = section(esc, 0, `<div class="pol-row locked"><div class="pol-main"><div class="pol-title">No feed configured</div>
        <div class="pol-detail">Add a <code>feed:</code> section to the policy to load signed signatures.</div></div></div>`);
      return;
    }
    const banner = d.error ? `<div class="banner err" style="margin:0 0 10px">${esc(d.error)}</div>` : "";
    const status = d.loaded
      ? `<div class="pol-row locked"><div class="pol-main">
           <div class="pol-title">${esc(d.feed)} v${esc(d.version)} · signature verified${d.expired ? " · EXPIRED" : ""}</div>
           <div class="pol-detail">key ${esc(d.key_id)} · issued ${esc(when(d.issued_at))} · valid until ${esc(when(d.expires_at))} · source ${esc(d.source)}${d.remote && d.last_pull ? ` · last poll ${esc(when(d.last_pull.ts))} (${esc(d.last_pull.status ?? "error")})` : ""}</div></div>
           <span class="pol-tag ${d.expired ? "tag-escalate" : ""}">${d.remote ? `polled every ${esc(d.refresh_s)} s` : "local file"}</span>
           <span class="pol-hits"></span>
           <div class="pol-actions"><button class="btn" data-feed-refresh>Fetch now</button></div></div>`
      : `<div class="pol-row locked"><div class="pol-main"><div class="pol-title">No signatures loaded</div>
           <div class="pol-detail">source ${esc(d.source)}</div></div><span class="pol-tag tag-escalate">not loaded</span><span class="pol-hits"></span>
           <div class="pol-actions"><button class="btn" data-feed-refresh>Fetch now</button></div></div>`;
    const rows = (d.signatures || []).map((s) => sigRow(s, esc)).join("");
    slot.innerHTML = section(esc, (d.signatures || []).length, status + rows, banner);
    const btn = slot.querySelector("[data-feed-refresh]");
    if (btn && ctx) btn.onclick = async (e) => {
      e.stopPropagation();
      btn.disabled = true;
      try {
        last = await ctx.api("/v1/admin/feed/refresh", { method: "POST", body: "{}" });
        paint(slot, last, esc, ctx);
        ctx.toast(last.error ? "Feed update rejected — the last good bundle keeps running" : `Feed v${last.version} is current`);
      } catch (err) {
        ctx.toast("Could not reach the feed");
        btn.disabled = false;
      }
    };
  }

  function section(esc, count, body, banner = "") {
    return `<section class="pol-group"><div class="pol-head"><i class="lane-dot lane-d"></i><h3>Signature feed</h3><span>${esc(count)}</span></div>
      ${banner}<div class="card pol-list">${body}</div></section>`;
  }

  function sigRow(s, esc) {
    // the strongest action any SIG-* control gives this signature; none = the policy does not apply it
    const applied = s.applied || [];
    const order = ["taint", "escalate", "block"];
    const top = applied.reduce((a, x) => (order.indexOf(x.action) > order.indexOf(a) ? x.action : a), null);
    const [label, cls] = top ? ACTION[top] : ["Off", ""];
    const where = applied.map((a) => PHASE[a.phase] || a.phase).join(", ");
    const detail = [s.id, SEVERITY[s.severity] || s.severity, where ? `on ${where}` : "not applied by this policy", (s.refs || [])[0]]
      .filter(Boolean).join(" · ");
    return `<div class="pol-row locked" title="${esc((s.refs || []).join(" · "))}">
      <div class="pol-main"><div class="pol-title">${esc(s.title)}</div><div class="pol-detail">${esc(detail)}</div></div>
      <span class="pol-tag ${cls}">${esc(label)}</span>
      <span class="pol-hits" title="times it acted">${s.hits ? esc(s.hits) + "×" : ""}</span>
      <div class="pol-actions"></div></div>`;
  }

  window.SpireFeed = { render };
})();
