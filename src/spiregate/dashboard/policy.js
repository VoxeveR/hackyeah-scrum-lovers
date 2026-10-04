/* SpireGate · Policy: add, change and remove rules, and turn a company policy written in plain language
   into rules. Every change goes through the admin API, which validates the whole policy before writing it.
   Rule titles, details and imported text are user content: they reach the DOM only through esc(). */
(function () {
  "use strict";

  const LANES = [
    { key: "d", label: "Deterministic" },
    { key: "dj", label: "Deterministic + Jev" },
    { key: "j", label: "Jev" },
  ];
  const ICON = {
    edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M13.5 6.5l4 4"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/></svg>',
  };

  function create(root, { api, toast, esc, drawer, closeDrawer, onRender }) {
    let data = null, armed = null, armedTimer = 0;

    async function load() {
      data = await api("/v1/admin/policy");
      render();
    }

    const fmt = (n) => Number(n || 0).toLocaleString("en-US");
    const laneDot = (k) => `<i class="lane-dot lane-${esc(k)}"></i>`;
    const ruleTemplates = () => data.templates.filter((t) => t.target !== "budget");

    function render() {
      if (!data) { root.innerHTML = `<div class="empty">Loading…</div>`; return; }
      const groups = LANES.map((l) => {
        const rules = data.rules.filter((r) => r.lane === l.key);
        if (!rules.length) return "";
        return `<section class="pol-group"><div class="pol-head">${laneDot(l.key)}<h3>${esc(l.label)}</h3><span>${rules.length}</span></div>
          <div class="card pol-list">${rules.map(row).join("")}</div></section>`;
      }).join("");
      root.innerHTML = `${data.error ? `<div class="banner err">The policy file has an error; the previous version is still in force: ${esc(data.error)}</div>` : ""}
        <div class="pol">${groups}<div id="feed-slot"></div></div>`;
      wire();
      if (onRender) onRender(root.querySelector("#feed-slot"));
    }

    function row(r) {
      const actions = r.invariant
        ? `<span class="pol-lock" title="Invariant: always on, cannot be removed">${ICON.lock}</span>`
        : `<button class="icon-btn" data-edit="${esc(r.id)}" aria-label="Edit">${ICON.edit}</button>
           <button class="icon-btn danger ${armed === r.id ? "armed" : ""}" data-del="${esc(r.id)}" aria-label="Delete">${armed === r.id ? "Delete?" : ICON.trash}</button>`;
      return `<div class="pol-row ${r.invariant ? "locked" : ""}" data-row="${esc(r.id)}">
        <div class="pol-main"><div class="pol-title">${esc(r.title)}</div>${r.detail ? `<div class="pol-detail">${esc(r.detail)}</div>` : ""}</div>
        <span class="pol-tag tag-${esc(r.action)}">${esc(r.label)}</span>
        <span class="pol-hits" title="times it fired">${r.hits ? fmt(r.hits) + "×" : ""}</span>
        <div class="pol-actions">${actions}</div></div>`;
    }

    function wire() {
      root.querySelectorAll("[data-edit]").forEach((b) => (b.onclick = (e) => { e.stopPropagation(); openEdit(b.dataset.edit); }));
      root.querySelectorAll(".pol-row[data-row]:not(.locked)").forEach((r) => (r.onclick = () => openEdit(r.dataset.row)));
      root.querySelectorAll("[data-del]").forEach((b) => (b.onclick = (e) => { e.stopPropagation(); confirmThen(b.dataset.del, () => remove(`/v1/admin/policy/rules/${encodeURIComponent(b.dataset.del)}`)); }));
    }

    // a delete needs a second click within 4 s
    function confirmThen(key, fn) {
      clearTimeout(armedTimer);
      if (armed === key) { armed = null; fn(); return; }
      armed = key; render();
      armedTimer = setTimeout(() => { armed = null; render(); }, 4000);
    }

    async function remove(path) {
      const r = await api(path, { method: "DELETE" });
      if (!r.ok) { toast(r.error || "Could not delete"); render(); return; }
      data = r; render(); toast(`Deleted · policy rev ${r.rev}`);
    }

    /* ------------------------------------------------------------ add: catalog → form */
    function openAdd() {
      const groups = [...new Set(ruleTemplates().map((t) => t.group))];
      const byGroup = groups.map((g) => `<div class="section-label">${esc(g)}</div><div class="tpl-grid">${ruleTemplates().filter((t) => t.group === g).map((t) =>
        `<button class="tpl" data-tpl="${esc(t.key)}">${laneDot(t.lane)}<b>${esc(t.title)}</b><span>${esc(t.summary)}</span></button>`).join("")}</div>`).join("");
      drawer(`<div><div class="drawer-kicker">New rule</div><div class="drawer-title">Choose a check</div></div>`, byGroup);
      document.querySelectorAll("[data-tpl]").forEach((b) => (b.onclick = () => openForm(data.templates.find((t) => t.key === b.dataset.tpl), null)));
    }

    function field(p, value) {
      const v = value === undefined ? p.default : value;
      const name = esc(p.name), label = `<span class="field-label">${esc(p.label)}</span>`;
      if (p.type === "kinds") {
        const on = new Set(v || []);
        return `<div class="field">${label}<div class="chips" data-param="${name}" data-type="kinds">${data.kinds.map((k) =>
          `<button type="button" class="chip-opt ${on.has(k.value) ? "on" : ""}" data-v="${esc(k.value)}">${esc(k.label)}</button>`).join("")}</div></div>`;
      }
      if (p.type === "choice") {
        return `<div class="field">${label}<div class="seg" data-param="${name}" data-type="choice">${p.options.map((o) =>
          `<button type="button" data-v="${esc(o.value)}" class="${o.value === v ? "on" : ""}">${esc(o.label)}</button>`).join("")}</div></div>`;
      }
      if (p.type === "bool") {
        return `<label class="switch-row"><input type="checkbox" data-param="${name}" data-type="bool" ${v ? "checked" : ""}><span class="switch"></span><span>${esc(p.label)}</span></label>`;
      }
      if (p.type === "text" && p.name === "text") return `<label class="field">${label}<textarea rows="3" class="prose" data-param="${name}" data-type="text" placeholder="e.g. The agent must not promise clients any rate of return.">${esc(v || "")}</textarea></label>`;
      if (p.type === "text") return `<label class="field">${label}<input type="text" data-param="${name}" data-type="text" value="${esc(v || "")}"></label>`;
      if (p.type === "number") return `<label class="field">${label}<input type="number" step="any" data-param="${name}" data-type="number" value="${esc(v ?? "")}"></label>`;
      return `<label class="field">${label}<input type="text" data-param="${name}" data-type="list" value="${esc(Array.isArray(v) ? v.join(", ") : v || "")}" placeholder="comma-separated"></label>`;
    }

    const named = (form, n) => form.elements.namedItem(n);

    function readForm(scope) {
      const params = {};
      scope.querySelectorAll("[data-param]").forEach((el) => {
        const t = el.dataset.type, k = el.dataset.param;
        if (t === "kinds") params[k] = [...el.querySelectorAll(".chip-opt.on")].map((b) => b.dataset.v);
        else if (t === "choice") { const on = el.querySelector("button.on"); params[k] = on ? on.dataset.v : undefined; }
        else if (t === "bool") params[k] = el.checked;
        else if (t === "list") params[k] = el.value.split(/[\s,;]+/).filter(Boolean);
        else params[k] = el.value;
      });
      return params;
    }

    function wireForm(scope) {
      scope.querySelectorAll(".chip-opt").forEach((b) => (b.onclick = () => b.classList.toggle("on")));
      scope.querySelectorAll(".seg[data-type=choice]").forEach((seg) => (seg.onclick = (e) => {
        const b = e.target.closest("button"); if (!b) return;
        seg.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
      }));
    }

    function openForm(t, rule) {
      const values = rule ? rule.params || {} : {};
      const body = `<form class="form pol-form">
          <label class="field"><span class="field-label">Name</span><input type="text" name="title" value="${esc(rule ? rule.title : "")}" placeholder="${esc(t.title)}"></label>
          ${t.params.map((p) => field(p, values[p.name])).join("")}
          <div class="banner err" hidden></div>
          <div class="form-foot"><button class="btn primary" type="submit">${rule ? "Save" : "Add"}</button>
            <button class="btn" type="button" data-cancel>Cancel</button></div>
        </form>`;
      drawer(`<div><div class="drawer-kicker">${laneDot(t.lane)}${rule ? "Edit" : "New rule"}</div><div class="drawer-title">${esc(t.title)}</div>
        <div class="drawer-sub">${esc(t.summary)}</div></div>`, body);
      const form = document.querySelector(".pol-form");
      wireForm(form);
      form.querySelector("[data-cancel]").onclick = closeDrawer;
      form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = { template: t.key, params: readForm(form), title: named(form, "title").value };
        const r = rule
          ? await api(`/v1/admin/policy/rules/${encodeURIComponent(rule.id)}`, { method: "PUT", body: JSON.stringify(payload) })
          : await api("/v1/admin/policy/rules", { method: "POST", body: JSON.stringify(payload) });
        done(r, form, rule ? "Saved" : "Added");
      };
    }

    function openAdvanced(rule) {
      const a = rule.advanced || {};
      const body = `<form class="form pol-form">
          <label class="field"><span class="field-label">Name</span><input type="text" name="title" value="${esc(a.title || "")}"></label>
          ${a.when !== undefined ? `<label class="field"><span class="field-label">Condition (CEL)</span><textarea name="when" rows="3" class="mono">${esc(a.when)}</textarea></label>` : ""}
          ${a.action !== undefined ? field({ name: "action", label: "When the rule fires", type: "choice", options: [
            { value: "block", label: "Block" }, { value: "escalate", label: "Send to review" }] }, a.action) : ""}
          ${"escalate_at" in a ? `<div class="row"><label class="field"><span class="field-label">Review from (Jev risk)</span><input type="number" step="0.01" min="0" max="1" name="escalate_at" value="${esc(a.escalate_at ?? "")}"></label>
            <label class="field"><span class="field-label">Block from (Jev risk)</span><input type="number" step="0.01" min="0" max="1" name="block_at" value="${esc(a.block_at ?? "")}" placeholder="never blocks"></label></div>` : ""}
          <div class="banner err" hidden></div>
          <div class="form-foot"><button class="btn primary" type="submit">Save</button><button class="btn" type="button" data-cancel>Cancel</button></div>
        </form>`;
      drawer(`<div><div class="drawer-kicker">${laneDot(rule.lane)}Edit</div><div class="drawer-title">${esc(rule.title)}</div></div>`, body);
      const form = document.querySelector(".pol-form");
      wireForm(form);
      form.querySelector("[data-cancel]").onclick = closeDrawer;
      form.onsubmit = async (e) => {
        e.preventDefault();
        const adv = { title: named(form, "title").value };
        if (named(form, "when")) adv.when = named(form, "when").value;
        const choice = form.querySelector("[data-param=action] button.on");
        if (choice) adv.action = choice.dataset.v;
        if (named(form, "escalate_at")) { adv.escalate_at = named(form, "escalate_at").value; adv.block_at = named(form, "block_at").value; }
        done(await api(`/v1/admin/policy/rules/${encodeURIComponent(rule.id)}`, { method: "PUT", body: JSON.stringify({ advanced: adv }) }), form, "Saved");
      };
    }

    function openEdit(id) {
      const rule = data.rules.find((r) => r.id === id);
      if (!rule || rule.invariant) return;
      const t = rule.template && data.templates.find((x) => x.key === rule.template);
      t ? openForm(t, rule) : openAdvanced(rule);
    }

    function done(r, form, verb) {
      if (!r.ok) {
        const err = form.querySelector(".banner.err");
        err.hidden = false; err.textContent = r.error || "Could not save";
        return;
      }
      data = r; render(); closeDrawer(); toast(`${verb} · policy rev ${r.rev}`);
    }

    /* ------------------------------------------------------------ import from free text */
    function openImport() {
      drawer(`<div><div class="drawer-kicker">Import</div><div class="drawer-title">Company policy → rules</div>
          <div class="drawer-sub">Whatever a rule can check becomes a rule. Jev judges the rest.</div></div>`,
        `<div class="form"><textarea class="import-text" rows="11" placeholder="Paste your company's rules, one per line…"></textarea>
          <div class="form-foot"><button class="btn primary" data-analyze>Analyze</button><button class="btn" data-sample>Insert example</button></div>
          <div class="import-out"></div></div>`);
      const ta = document.querySelector(".import-text"), out = document.querySelector(".import-out");
      document.querySelector("[data-sample]").onclick = async () => { ta.value = (await api("/v1/admin/policy/sample")).text; };
      document.querySelector("[data-analyze]").onclick = async () => {
        if (!ta.value.trim()) return;
        out.innerHTML = `<div class="empty">Analyzing…</div>`;
        const { proposals } = await api("/v1/admin/policy/import", { method: "POST", body: JSON.stringify({ text: ta.value }) });
        showProposals(out, proposals.filter((p) => p.target !== "budget"));
      };
    }

    function chips(p) {
      const v = p.params || {};
      const kindLabel = (k) => (data.kinds.find((x) => x.value === k) || { label: k }).label;
      const parts = [];
      if (v.kinds) parts.push(...v.kinds.map(kindLabel));
      if (v.domains) parts.push(...v.domains);
      if (v.amount) parts.push(`> ${fmt(v.amount)}`);
      if (v.tools) parts.push(...v.tools);
      if (v.start !== undefined) parts.push(`${v.start}:00–${v.end}:00`);
      if (v.action) parts.push(v.action === "block" ? "blocks" : "to review");
      if (v.verify) parts.push("Jev verifies");
      return parts.map((x) => `<span class="chip-sm">${esc(x)}</span>`).join("");
    }

    function showProposals(out, proposals) {
      if (!proposals.length) { out.innerHTML = `<div class="empty">No rules found in this text.</div>`; return; }
      const fresh = proposals.filter((p) => !p.exists), det = fresh.filter((p) => p.lane !== "j").length;
      const dup = proposals.length - fresh.length;
      out.innerHTML = `<div class="import-sum"><b>${fresh.length}</b> new · ${det} deterministic · ${fresh.length - det} judged by Jev${dup ? ` · ${dup} already in the policy` : ""}</div>
        <div class="props">${proposals.map((p, i) => `<label class="prop ${p.item && p.item.id ? "" : "bad"} ${p.exists ? "dup" : ""}">
          <input type="checkbox" data-i="${i}" ${!(p.item && p.item.id) ? "disabled" : p.exists ? "" : "checked"}>
          <div><div class="prop-title">${laneDot(p.lane)}${esc(p.title || p.template_title)}${p.exists ? `<span class="prop-dup">already in the policy</span>` : ""}</div>
            <div class="prop-src">“${esc(p.statement)}”</div><div class="prop-chips">${chips(p)}</div>
            ${p.item && p.item.id ? "" : `<div class="prop-why">${esc(p.why)}</div>`}</div></label>`).join("")}</div>
        <div class="banner err" hidden></div>
        <div class="form-foot"><button class="btn primary" data-apply>Add selected</button></div>`;
      const btn = out.querySelector("[data-apply]");
      const sync = () => { const n = out.querySelectorAll("input[data-i]:checked").length; btn.textContent = n ? `Add ${n} rule${n === 1 ? "" : "s"}` : "Nothing selected"; btn.disabled = !n; };
      out.querySelectorAll("input[data-i]").forEach((c) => (c.onchange = sync)); sync();
      btn.onclick = async () => {
        const chosen = [...out.querySelectorAll("input[data-i]:checked")].map((c) => proposals[Number(c.dataset.i)])
          .map((p) => ({ template: p.template, params: p.params, title: p.title }));
        const r = await api("/v1/admin/policy/import/apply", { method: "POST", body: JSON.stringify({ proposals: chosen }) });
        if (!r.ok) { const e = out.querySelector(".banner.err"); e.hidden = false; e.textContent = r.error || "Could not add"; return; }
        data = r; render(); closeDrawer(); toast(`Added ${chosen.length} · policy rev ${r.rev}`);
      };
    }

    load().catch(() => { root.innerHTML = `<div class="empty">Could not load the policy.</div>`; });
    return { openAdd, openImport, reload: load };
  }

  window.SpirePolicy = { create };
})();
