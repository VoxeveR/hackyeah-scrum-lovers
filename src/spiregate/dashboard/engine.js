/* SpireGate · Silnik: a live pipeline of the decision engine.

   Shared by the dashboard (fed by the SSE stream /v1/admin/stream) and the animation lab (fed by synthetic
   events). The middle is a grid: rows are the three kinds of rules, columns are the two engines.

                       Deterministyka        Jev
     facts             [ rules       ] ───────────────     access, paths, data flow, budgets
     semantic rules    [ detector    ] → [ verifies    ]     PESEL in any form, what is sent where
     prose rules       ─────────────── → [ judges      ]     intent, instructions hidden in content

   Every request enters through identity and budget checks, takes the row of the rules that actually checked
   it, changes colour where its decision was made, and waits visibly while Jev answers. The agent's own model
   call (proxy channel) is not a decision stage and is not drawn.

   Event text (agent names, labels, control ids) is attacker-influenced: it only ever reaches the DOM
   through textContent, never innerHTML. */
(function () {
  "use strict";

  const BINS = [
    { key: "allow", label: "Allowed", color: "--green" },
    { key: "redact", label: "Redacted", color: "--blue" },
    { key: "escalate", label: "Needs review", color: "--orange" },
    { key: "block", label: "Blocked", color: "--red" },
  ];
  const PORTS = [
    { key: "claude", label: "Claude Code", short: "Claude" },
    { key: "codex", label: "Codex", short: "Codex" },
    { key: "sdk", label: "SDK", short: "SDK" },
    { key: "proxy", label: "Proxy OpenAI", short: "Proxy" },
  ];
  const LANES = [
    { key: "d", label: "Deterministic", color: "--accent" },
    { key: "dj", label: "Deterministic + Jev", color: "--purple" },
    { key: "j", label: "Jev", color: "--purple" },
  ];
  // the grid: lane = row, col = engine; only the middle row uses both engines
  const CELLS = [
    { id: "d_det", lane: 0, col: "det", title: "Deterministic", color: "--accent",
      hint: "Fact rules: tool access, protected paths, data flow, budgets. Jev is not asked." },
    { id: "dj_det", lane: 1, col: "det", title: "Deterministic", color: "--accent",
      hint: "Semantic rules, step 1: a detector (e.g. a checksum-valid PESEL, an allow-listed recipient)." },
    { id: "dj_jev", lane: 1, col: "jev", title: "Jev", color: "--purple",
      hint: "Semantic rules, step 2: Jev checks what the detector may have missed, and can send it to review or block it." },
    { id: "j_jev", lane: 2, col: "jev", title: "Jev", color: "--purple",
      hint: "Plain-language rules that no pattern can express: does the action match the request, are there instructions hidden in content." },
  ];
  const portOf = (s) => (s === "hook:claude-code" ? "claude" : s === "hook:codex" ? "codex" : s === "proxy" ? "proxy" : "sdk");
  const binOf = (d) => (d === "allow" || d === "redact" || d === "escalate" ? d : "block"); // withhold, taint -> block
  const isJev = (c) => /^S1-|\/verify$/.test(c || "");                     // a System One verdict, not a rule
  // A dot is in a Jev cell for exactly as long as Jev took: it leaves when the answer arrives, or, if the answer
  // came while the dot was still on its way, after the measured Jev time.
  const gateMs = (e) => Math.max(0, (e.ms || 0) - (e.upstream_ms || 0));   // without the agent's model call
  const MAX_LIVE = 260, MAX_QUEUE = 320, STALE_MS = 30000;

  /* ---------------------------------------------------------------- colours */
  function hexToRgb(v) {
    v = (v || "").trim();
    if (v.startsWith("#")) {
      const h = v.length === 4 ? v.slice(1).split("").map((c) => c + c).join("") : v.slice(1, 7);
      return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
    }
    const m = v.match(/\d+(\.\d+)?/g);
    return m ? m.slice(0, 3).map(Number) : [136, 136, 136];
  }
  const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
  const mix = (a, b, t) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];

  /* ---------------------------------------------------------------- geometry */
  class Path {
    constructor() { this.pts = []; this.cum = []; this.total = 0; this.marks = {}; }
    add(x, y) {
      const n = this.pts.length;
      if (n) {
        const p = this.pts[n - 1], dl = Math.hypot(x - p[0], y - p[1]);
        if (dl < 0.01) return;
        this.total += dl;
      }
      this.pts.push([x, y]); this.cum.push(this.total);
    }
    mark(name) { this.marks[name] = this.total; }
    // cubic S-curve from the current end to (x, y), horizontal tangents
    curve(x, y, n = 22) {
      const a = this.pts[this.pts.length - 1], dx = (x - a[0]) * 0.55;
      const p1 = [a[0] + dx, a[1]], p2 = [x - dx, y];
      for (let i = 1; i <= n; i++) {
        const t = i / n, u = 1 - t;
        this.add(u * u * u * a[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * x,
                 u * u * u * a[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * y);
      }
    }
    at(d, hint) {
      const c = this.cum, p = this.pts;
      if (d <= 0) return [p[0][0], p[0][1], 0];
      if (d >= this.total) return [p[p.length - 1][0], p[p.length - 1][1], p.length - 1];
      let i = Math.max(0, Math.min(hint || 0, c.length - 2));
      while (i < c.length - 2 && c[i + 1] < d) i++;
      while (i > 0 && c[i] > d) i--;
      const t = (d - c[i]) / (c[i + 1] - c[i] || 1);
      return [p[i][0] + (p[i + 1][0] - p[i][0]) * t, p[i][1] + (p[i + 1][1] - p[i][1]) * t, i];
    }
  }

  function layout(W, H) {
    const compact = W < 780, tiny = W < 580;
    const pad = compact ? 12 : 22;
    const portW = tiny ? 62 : compact ? 88 : 140, portH = compact ? 28 : 34, portGap = compact ? 12 : 18;
    const stW = tiny ? 100 : compact ? 124 : 146, stH = compact ? 56 : 66, pairGap = tiny ? 20 : compact ? 28 : 40;
    const binW = tiny ? 116 : compact ? 140 : 196, binH = compact ? 64 : 78, binGap = compact ? 10 : 14;
    const hubR = compact ? 15 : 24, entryR = compact ? 6 : 8;
    const polW = tiny ? 0 : compact ? 78 : 150;                       // the "Company policy" station (a dot on tiny screens)
    const cy = Math.round(H / 2);
    const portX = pad + portW / 2, binX = W - pad - binW / 2;
    const hubX = binX - binW / 2 - (compact ? 40 : 84);
    const polX = portX + portW / 2 + (compact ? 14 : 30) + polW / 2;
    const entryX = polW ? polX + polW / 2 : portX + portW / 2 + 22;  // where a request leaves the policy station
    const mid = (entryX + (polW ? 0 : entryR) + hubX - hubR) / 2;     // the centre axis between entry and decision
    const colX = { det: mid - pairGap / 2 - stW / 2, jev: mid + pairGap / 2 + stW / 2 };
    const cellX = (c) => (c.lane === 1 ? colX[c.col] : mid);           // a lone engine sits on the axis
    const rowGap = Math.min(compact ? 88 : 104, (H - stH - 28) / 2);
    const rows = [cy - rowGap, cy, cy + rowGap];
    return {
      W, H, compact, tiny, cy, stW, stH, binW, binH, portW, portH, hubR, entryR, polW, rows, colX, mid,
      ports: PORTS.map((p, i) => ({ ...p, x: portX, y: cy + (i - 1.5) * (portH + portGap) })),
      entry: { x: entryX, y: cy }, policy: { x: polW ? polX : entryX, y: cy },
      cells: CELLS.map((c) => ({ ...c, x: cellX(c), y: rows[c.lane] })),
      hub: { x: hubX, y: cy },
      bins: BINS.map((b, i) => ({ ...b, x: binX, y: cy + (i - 1.5) * (binH + binGap) })),
    };
  }

  /* routes. Every route = in(port) + toWait(lane) + rest(lane) + out(bin); pipes are drawn with the same
     builders, so a dot follows exactly the drawn pipe. Marks: entry, wait, det (exit), jev (exit), hub, bin */
  function routeIn(L, port, p) {
    p.add(port.x + L.portW / 2, port.y);
    if (L.polW) { p.curve(L.policy.x - L.polW / 2, L.cy); p.add(L.entry.x, L.entry.y); }   // through the policy station's slot
    else { p.curve(L.entry.x - L.entryR, L.entry.y); p.add(L.entry.x, L.entry.y); }
    p.mark("entry");
  }
  function routeToWait(L, lane, p) {
    const y = L.rows[lane], half = L.stW / 2;
    if (lane === 1) {   // both engines side by side
      p.add(L.colX.det - half, y); p.add(L.colX.det + half, y); p.mark("det");
      p.add(L.colX.jev - half, y); p.mark("jevIn"); p.add(L.colX.jev + half - 6, y); p.mark("wait");
      return;
    }
    p.curve(L.mid - half, y);                                   // one engine, on the axis
    if (lane === 2) { p.mark("jevIn"); p.add(L.mid + half - 6, y); p.mark("wait"); return; }
    p.add(L.mid, y); p.mark("wait");
  }
  function routeRest(L, lane, p) {
    const y = L.rows[lane], half = L.stW / 2;
    if (lane === 1) { p.add(L.colX.jev + half, y); p.mark("jev"); }
    else { p.add(L.mid + half, y); p.mark(lane === 0 ? "det" : "jev"); }
    p.curve(L.hub.x - L.hubR, L.hub.y);
  }
  function routeOut(L, bin, p) {
    p.add(L.hub.x, L.hub.y); p.mark("hub"); p.add(L.hub.x + L.hubR, L.hub.y);
    p.curve(bin.x - L.binW / 2 - 2, bin.y); p.mark("bin"); p.add(bin.x - L.binW / 2 + 3, bin.y);   // absorbed by the coloured edge
  }

  function pipes(L) {
    const out = [];
    for (const port of L.ports) { const p = new Path(); routeIn(L, port, p); out.push({ path: p, color: "--faint", lane: "in:" + port.key }); }
    LANES.forEach((lane, i) => {
      const p = new Path(); p.add(L.entry.x, L.entry.y); routeToWait(L, i, p); routeRest(L, i, p);
      if (i === 1) {   // the middle lane changes engine half-way: rules colour first, then Jev colour
        const cut = p.marks.det, a = new Path(), b = new Path();
        p.pts.forEach((pt, k) => { if (p.cum[k] <= cut + 0.5) a.add(pt[0], pt[1]); if (p.cum[k] >= cut - 0.5) b.add(pt[0], pt[1]); });
        out.push({ path: a, color: "--accent", lane: lane.key }, { path: b, color: "--purple", lane: lane.key });
      } else out.push({ path: p, color: lane.color, lane: lane.key });
    });
    for (const bin of L.bins) {
      const p = new Path(); p.add(L.hub.x + L.hubR, L.hub.y); p.curve(bin.x - L.binW / 2, bin.y);
      out.push({ path: p, color: bin.color, lane: "out:" + bin.key });
    }
    return out;
  }

  /* ---------------------------------------------------------------- the flow */
  function create(root, opts = {}) {
    // manual: no requestAnimationFrame loop; the caller drives frames with step(now) (deterministic tests)
    // policy: () => ({rules, rev}) for the "Company policy" station; onPolicy: click handler for it
    opts = { onStats: null, onDecision: null, manual: false, clock: () => performance.now(), policy: null, onPolicy: null, ...opts };
    const clock = opts.clock;
    root.classList.add("sf");
    root.innerHTML = "";
    const back = document.createElement("canvas"), front = document.createElement("canvas");
    back.className = "sf-back"; front.className = "sf-front";
    const nodes = document.createElement("div"); nodes.className = "sf-nodes";
    root.append(back, nodes, front);
    const bctx = back.getContext("2d"), fctx = front.getContext("2d");

    // DOM nodes (static text only; live numbers are set through textContent)
    const el = (cls, html) => { const d = document.createElement("div"); d.className = cls; if (html) d.innerHTML = html; nodes.appendChild(d); return d; };
    const portEls = {}, binEls = {}, cellEls = {};
    for (const p of PORTS) {
      const d = el("sf-port", `<i></i><span class="sf-pl"></span><b class="sf-pc">0</b>`);
      d._label = d.querySelector(".sf-pl"); d._count = d.querySelector(".sf-pc");
      d._label.textContent = p.label;
      portEls[p.key] = d;
    }
    const entryEl = el("sf-entry");
    entryEl.title = "Company policy: agent identity and budgets first, then your rules";
    const policyEl = el("sf-station sf-policy",
      `<div class="sf-st-head"><i></i><b class="sf-st-title"></b></div><div class="sf-slot"></div><div class="sf-st-foot"><b class="sf-st-m"></b></div>`);
    policyEl._metric = policyEl.querySelector(".sf-st-m"); policyEl._title = policyEl.querySelector(".sf-st-title");
    policyEl.title = "Your company's rules, imported from text or added on the Policy page. Every request is checked "
      + "against them: agent identity and budgets first, then the rules below.";
    if (opts.onPolicy) { policyEl.classList.add("click"); policyEl.onclick = opts.onPolicy; }
    for (const c of CELLS) {
      const d = el(`sf-station sf-${c.col}`,
        `<div class="sf-st-head"><i></i><b class="sf-st-title"></b></div><div class="sf-slot"></div><div class="sf-st-foot"><b class="sf-st-m"></b></div>`);
      d._title = d.querySelector(".sf-st-title"); d._metric = d.querySelector(".sf-st-m");
      d._title.textContent = c.title;
      d.title = c.hint;
      cellEls[c.id] = d;
    }
    const hubEl = el("sf-hub", `<div class="sf-hub-ring"></div><span>Decision</span>`);
    for (const b of BINS) {
      const d = el(`sf-bin sf-bin-${b.key}`, `<div class="sf-bin-top"><i></i><span class="sf-bl"></span></div>
        <div class="sf-bin-mid"><b class="sf-bin-count">0</b><em class="sf-bs">0%</em></div><div class="sf-bin-bar"><i></i></div>`);
      d.querySelector(".sf-bl").textContent = b.label;
      d._count = d.querySelector(".sf-bin-count"); d._share = d.querySelector(".sf-bs"); d._bar = d.querySelector(".sf-bin-bar i");
      d._bumped = 0;
      binEls[b.key] = d;
    }

    const reduced = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
    const S = {
      L: null, pipes: [], colors: {}, dark: false, sprites: new Map(),
      info: new Map(), dots: [], queue: [], ripples: [], lastRelease: 0,
      counts: { allow: 0, redact: 0, escalate: 0, block: 0 }, shown: { allow: 0, redact: 0, escalate: 0, block: 0 },
      lanes: [0, 0, 0], ports: { claude: 0, codex: 0, sdk: 0, proxy: 0 }, laneHit: {}, cellHit: {}, hubHit: 0, entryHit: 0,
      s1Inflight: new Map(), endTimes: [], rate: 0, peak: 0, total: 0, noLLM: 0, s1Req: 0, s1Calls: 0,
      usd: 0, times: [], t0Times: [], s1Times: { 1: [], 2: [] },
      raf: 0, lastFrame: clock(), lastStats: 0, lastDom: 0, destroyed: false,
    };

    function readColors() {
      const cs = getComputedStyle(root);
      const get = (n) => hexToRgb(cs.getPropertyValue(n));
      S.dark = !!(window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches);
      for (const n of ["--green", "--blue", "--orange", "--red", "--purple", "--accent", "--faint", "--muted", "--text", "--line", "--fill"]) S.colors[n] = get(n);
      S.colors.neutral = S.dark ? [235, 235, 245] : S.colors["--faint"];
      S.sprites.clear();
    }

    function sprite(rgb) {
      const key = rgb.map((v) => v | 0).join(",") + (S.dark ? "d" : "l");
      let c = S.sprites.get(key);
      if (c) return c;
      const r = 14, dpr = Math.min(2, window.devicePixelRatio || 1);
      c = document.createElement("canvas"); c.width = c.height = r * 2 * dpr;
      const x = c.getContext("2d"); x.scale(dpr, dpr);
      const g = x.createRadialGradient(r, r, 0, r, r, r);
      g.addColorStop(0, rgba(rgb, S.dark ? 0.55 : 0.32)); g.addColorStop(0.35, rgba(rgb, S.dark ? 0.22 : 0.12)); g.addColorStop(1, rgba(rgb, 0));
      x.fillStyle = g; x.fillRect(0, 0, r * 2, r * 2);
      if (S.sprites.size > 64) S.sprites.clear();
      S.sprites.set(key, c);
      return c;
    }

    /* ------------------------------------------------------------ layout */
    function resize() {
      const W = Math.max(320, root.clientWidth), H = root.clientHeight;
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      if (S.L && S.L.W === W && S.L.H === H && S.dpr === dpr) return;   // observers also fire without a real change
      S.dpr = dpr;
      for (const [c, x] of [[back, bctx], [front, fctx]]) {
        c.width = W * dpr; c.height = H * dpr; c.style.width = W + "px"; c.style.height = H + "px";
        x.setTransform(dpr, 0, 0, dpr, 0, 0);
      }
      const old = S.L;
      S.L = layout(W, H);
      S.pipes = pipes(S.L);
      root.classList.toggle("sf-compact", S.L.compact); root.classList.toggle("sf-tiny", S.L.tiny);
      place();
      readColors();
      drawBack();
      if (old && (old.W !== W || old.H !== H)) for (const d of S.dots) relayoutDot(d);
      step(S.lastFrame);                                                   // resizing clears the canvas: redraw now, no blank frame
    }

    function place() {
      const L = S.L, pos = (e, x, y, w, h) => { e.style.left = x - w / 2 + "px"; e.style.top = y - h / 2 + "px"; e.style.width = w + "px"; e.style.height = h + "px"; };
      for (const p of L.ports) { pos(portEls[p.key], p.x, p.y, L.portW, L.portH); portEls[p.key]._label.textContent = L.compact ? p.short : p.label; }
      pos(entryEl, L.entry.x, L.entry.y, L.entryR * 2, L.entryR * 2);
      entryEl.hidden = !!L.polW; policyEl.hidden = !L.polW;
      if (L.polW) { pos(policyEl, L.policy.x, L.policy.y, L.polW, L.stH); policyEl._title.textContent = L.compact ? "Policy" : "Company policy"; }
      for (const c of L.cells) pos(cellEls[c.id], c.x, c.y, L.stW, L.stH);
      pos(hubEl, L.hub.x, L.hub.y, L.hubR * 2, L.hubR * 2);
      for (const b of L.bins) pos(binEls[b.key], b.x, b.y, L.binW, L.binH);
    }

    function drawBack() {
      const L = S.L, x = bctx;
      x.clearRect(0, 0, L.W, L.H);
      // dotted grid, very faint: gives depth without noise
      x.fillStyle = rgba(S.colors["--muted"], S.dark ? 0.12 : 0.1);
      for (let gx = 12; gx < L.W; gx += 24) for (let gy = 12; gy < L.H; gy += 24) x.fillRect(gx, gy, 1, 1);
      const w = L.compact ? 9 : 13;
      for (const p of S.pipes) {
        const c = S.colors[p.color] || S.colors["--faint"];
        x.lineCap = "round"; x.lineJoin = "round";
        x.beginPath(); p.path.pts.forEach(([px, py], i) => (i ? x.lineTo(px, py) : x.moveTo(px, py)));
        x.strokeStyle = rgba(c, S.dark ? 0.1 : 0.08); x.lineWidth = w; x.stroke();
        x.strokeStyle = rgba(c, S.dark ? 0.22 : 0.18); x.lineWidth = 1; x.stroke();
      }
    }

    /* ------------------------------------------------------------ routing */
    function spawn(info, now) {
      const L = S.L, port = L.ports.find((p) => p.key === info.port) || L.ports[2];
      const path = new Path(); routeIn(L, port, path);
      S.dots.push({ info, path, dist: 0, hint: 0, stage: "in", lane: null, complete: false, colorAt: Infinity, color: null,
                    born: now, trail: [] });
      S.ports[info.port] = (S.ports[info.port] || 0) + 1;
    }

    // which row: the kinds of rules that actually checked this request
    function laneOf(info) {
      const e = info.end;
      const kinds = new Set([...(info.kinds || []), ...((e && e.s1_kinds) || [])]);
      const afterRule = info.afterRule || !!(e && (e.s1_after_rule || (e.controls || []).some((c) => !isJev(c))));
      if (kinds.has("verify")) return 1;                         // a detector, then Jev on what it may have missed
      if (kinds.has("jev") || info.s1) return afterRule ? 1 : 2;  // both engines acted / only Jev judged
      if (e) return (e.s1_calls || 0) > 0 ? 2 : 0;               // no Jev: decided by facts alone
      return null;                                               // still being decided: wait at the entry
    }

    // where the decision was made, so the dot changes colour at the right cell
    function decidedAt(info, lane) {
      const e = info.end, dec = binOf(e.decision);
      if (lane === 0) return "det";
      if (lane === 2) return "jev";
      const byJev = (e.controls || []).some(isJev);
      return dec !== "allow" && !byJev ? "det" : "jev";          // the detector decided, or Jev's verdict shaped it
    }

    // when a dot may leave its Jev cell (null: Jev has not answered yet)
    const departOf = (d) => {
      const info = d.info;
      if (!info.end) return null;
      if (info.answerAt >= d.cellAt) return info.answerAt;            // answered while the dot was in the cell
      return d.cellAt + Math.max(0, info.end.s1_ms || 0);            // answered earlier: replay the real duration
    };

    function extend(d) {
      const L = S.L, info = d.info, p = d.path;
      if (d.stage === "in") {
        const lane = laneOf(info);
        if (lane == null) return;
        routeToWait(L, lane, p); d.lane = lane; d.stage = "lane";
      }
      if (d.stage === "lane" && info.end) {
        routeRest(L, d.lane, p);
        const key = binOf(info.end.decision);
        routeOut(L, L.bins.find((b) => b.key === key), p);
        const at = p.marks[decidedAt(info, d.lane)];
        d.colorAt = at != null ? at : p.marks.hub;
        d.color = S.colors[BINS.find((b) => b.key === key).color];
        d.complete = true; d.stage = "done";
      }
    }

    // after a resize the old path coordinates are stale: rebuild the same route and keep relative progress
    function relayoutDot(d) {
      const frac = d.path.total ? d.dist / d.path.total : 0;
      const L = S.L, info = d.info, port = L.ports.find((p) => p.key === info.port) || L.ports[2];
      const fresh = { ...d, path: new Path(), stage: "in", complete: false };
      routeIn(L, port, fresh.path);
      if (d.stage !== "in") extend(fresh);
      Object.assign(d, fresh, { dist: frac * fresh.path.total, hint: 0, trail: [] });
    }

    /* ------------------------------------------------------------ events */
    function push(events) {
      const now = clock();
      for (const e of [].concat(events || [])) {
        if (!e || typeof e !== "object") continue;
        if (e.type === "start") {
          const info = { id: e.id, port: portOf(e.surface), kind: e.kind, agent: e.agent, label: e.label, surface: e.surface,
                         s1: false, kinds: [], end: null, t: now };
          S.info.set(e.id, info);
          // proxy: the gate's work is split around the agent's model call; show the request once it is decided
          if (info.kind === "model") { info.deferred = true; continue; }
          enqueue(info);
        } else if (e.type === "s1") {
          const info = S.info.get(e.id);
          if (info) { info.s1 = true; info.kinds = [...new Set([...info.kinds, ...(e.kinds || [])])]; info.afterRule = info.afterRule || !!e.after_rule; }
          const lane = (e.kinds || []).includes("verify") ? 1 : 2;
          if (e.state === "start") {
            S.s1Inflight.set(e.id, { n: ((S.s1Inflight.get(e.id) || {}).n || 0) + 1, lane });
            S.cellHit[lane === 1 ? "dj_jev" : "j_jev"] = now;
          } else {
            const cur = S.s1Inflight.get(e.id);
            if (cur && cur.n > 1) cur.n--; else S.s1Inflight.delete(e.id);
            if (typeof e.ms === "number") pushTime(S.s1Times[lane], e.ms);
          }
        } else if (e.type === "end") {
          let info = S.info.get(e.id);
          if (!info) { info = { id: e.id, port: "sdk", kind: "action", s1: false, kinds: [], t: now, orphan: true }; S.info.set(e.id, info); }
          info.end = e; info.answerAt = now;
          if (info.deferred) { info.deferred = false; enqueue(info); }
          S.s1Inflight.delete(e.id);
          S.endTimes.push(now); S.total++;
          if ((e.s1_calls || 0) > 0) { S.s1Req++; S.s1Calls += e.s1_calls; } else S.noLLM++;
          S.usd += e.s1_usd || 0;                                 // the cost of control; the agent's model spend is on the Budgets page
          pushTime(S.times, gateMs(e)); pushTime(S.t0Times, e.t0_ms);
          if (info.orphan) landInstant(info);                     // stream joined mid-request: count it, no animation
        }
      }
    }
    function enqueue(info) {
      if (S.queue.length >= MAX_QUEUE) landInstant(S.queue.shift());
      S.queue.push(info);
    }
    const pushTime = (arr, v) => { if (typeof v === "number") { arr.push(v); if (arr.length > 500) arr.shift(); } };

    // counted without animation (hidden tab, overload): the numbers must stay right even when frames are skipped
    function landInstant(info) {
      if (!info) return;
      if (!info.end) { info.lateLand = true; return; }            // lands as soon as its decision arrives
      land(info, null, laneOf(info) ?? 0);
    }

    function land(info, at, lane) {
      const key = binOf(info.end.decision);
      S.counts[key]++; S.lanes[lane]++;
      if (at) S.ripples.push({ x: at[0], y: at[1], t: clock(), c: S.colors[BINS.find((b) => b.key === key).color] });
      S.info.delete(info.id);
      const b = binEls[key], t = clock();
      if (t - b._bumped > 160) { b._bumped = t; b.classList.remove("sf-bump"); void b.offsetWidth; b.classList.add("sf-bump"); }
      if (opts.onDecision) opts.onDecision({ id: info.id, seq: info.end.seq, surface: info.surface, agent: info.agent, label: info.label,
        decision: key, raw: info.end.decision, controls: info.end.controls || [], ms: gateMs(info.end), usd: info.end.s1_usd || 0,
        s1: (info.end.s1_calls || 0) > 0, s1p: info.end.s1_p, lane, decidedAt: decidedAt(info, lane) });
    }

    /* ------------------------------------------------------------ frame */
    function frame() {
      if (S.destroyed) return;
      S.raf = requestAnimationFrame(frame);
      step(clock());
    }

    function step(now) {
      const dt = Math.min(50, Math.max(0, now - S.lastFrame)); S.lastFrame = now;
      const L = S.L; if (!L) return;

      // release queued requests as a stream, not a blob
      const spacing = S.queue.length > 80 ? 5 : S.queue.length > 16 ? 11 : 20;   // keeps up with ~90 req/s, still a stream
      let released = 0;
      while (S.queue.length && S.dots.length < MAX_LIVE && now - S.lastRelease >= spacing && released < 4) {
        spawn(S.queue.shift(), now); S.lastRelease = now; released++;
      }
      for (const info of S.info.values()) {
        if (info.lateLand && info.end) land(info, null, laneOf(info) ?? 0);
        else if (!info.end && now - info.t > STALE_MS) S.info.delete(info.id);   // lost request: no decision ever came
      }

      // ~1.4 s from port to bin: a rule decides in ~1 ms, so the trip itself should be quick; the visible
      // difference between lanes is the stop in a Jev cell, which lasts as long as Jev really took
      const speed = (reduced ? 4 : 1) * Math.max(0.45, Math.min(0.95, L.W / 1300));
      const ctx = fctx;
      ctx.clearRect(0, 0, L.W, L.H);

      // live flow in the pipes; brighter where traffic just passed
      if (!reduced) {
        ctx.save(); ctx.lineCap = "round"; ctx.lineWidth = L.compact ? 1.6 : 2;
        ctx.setLineDash([2, L.compact ? 11 : 14]); ctx.lineDashOffset = -now * 0.035;
        for (const p of S.pipes) {
          const hit = S.laneHit[p.lane] || 0, act = Math.max(0, 1 - (now - hit) / 1400);
          const c = S.colors[p.color] || S.colors["--faint"];
          ctx.strokeStyle = rgba(c, 0.12 + act * 0.5);
          ctx.beginPath(); p.path.pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y))); ctx.stroke();
        }
        ctx.restore();
      }

      // dots
      const neutral = S.colors.neutral, purple = S.colors["--purple"];
      const glowA = Math.max(0.3, Math.min(1, 1.25 - S.dots.length / 160));   // dense traffic: softer halos, no white-out
      ctx.save();
      if (S.dark) ctx.globalCompositeOperation = "lighter";
      // 1. move: full speed on the pipes; in a Jev cell, exactly as long as Jev took
      const gap = L.compact ? 7 : 9;
      const waiting = { 1: [], 2: [] };                                  // in a Jev cell, no answer yet
      for (const d of S.dots) {
        if (!d.complete) extend(d);
        const m = d.path.marks;
        let v = speed * (0.55 + 0.45 * Math.min(1, (now - d.born) / 260));     // ease in from the port
        if (d.lane > 0 && m.jevIn != null && d.dist >= m.jevIn - 0.5 && (m.jev == null || d.dist < m.jev)) {
          if (d.cellAt == null) d.cellAt = now;
          const dep = departOf(d);
          if (dep == null) waiting[d.lane].push(d);
          else if (dep > now) v = Math.min(v, Math.max(0, m.wait - d.dist) / (dep - now));   // arrive at the exit on time
        }
        d.prev = d.dist;
        d.next = Math.min(d.path.total, d.dist + v * dt);
      }
      // 2. those still waiting for Jev line up at the exit of the cell, first come first served
      for (const lane of [1, 2]) {
        waiting[lane].sort((a, b) => a.cellAt - b.cellAt).forEach((d, k) => {
          const m = d.path.marks, stop = m.wait - gap * k;
          if (d.next > stop) d.next = Math.max(d.prev, stop);
        });
      }
      // 3. draw
      const keep = [];
      for (const d of S.dots) {
        const info = d.info;
        d.dist = d.next;
        const holding = !d.complete && d.dist >= d.path.total - 0.5;
        if (d.complete && d.dist >= d.path.total - 0.5) {
          const end = d.path.at(d.path.total); land(info, [end[0], end[1]], d.lane); continue;
        }
        if (!info.end && now - info.t > STALE_MS) { S.info.delete(info.id); continue; } // lost request
        keep.push(d);
        const pos = d.path.at(d.dist, d.hint); d.hint = pos[2];
        const x = pos[0], y = pos[1];
        if (holding) {   // waiting calmly at the front: at the entry while rules run (rare), at a Jev exit until it answers
          if (d.stage === "in") S.entryHit = now;
          else { const cell = d.lane === 1 ? "dj_jev" : d.lane === 2 ? "j_jev" : "d_det"; S.cellHit[cell] = Math.max(S.cellHit[cell] || 0, now - 300); }
        }

        // cell, entry and hub glow when a dot is inside
        for (const c of L.cells) {
          if (Math.abs(x - c.x) < L.stW / 2 && Math.abs(y - c.y) < 13) S.cellHit[c.id] = now;
        }
        if (L.polW ? Math.abs(x - L.policy.x) < L.polW / 2 && Math.abs(y - L.cy) < 13
                   : Math.hypot(x - L.entry.x, y - L.entry.y) < L.entryR + 3) S.entryHit = now;
        if (Math.hypot(x - L.hub.x, y - L.hub.y) < L.hubR) S.hubHit = now;
        const m = d.path.marks;
        if (d.dist < m.entry) S.laneHit["in:" + info.port] = now;
        else if (d.lane != null && (m.hub == null || d.dist < m.hub)) S.laneHit[LANES[d.lane].key] = now;
        else if (d.complete) S.laneHit["out:" + binOf(info.end.decision)] = now;

        // colour: neutral until the cell where the decision was made, then a short blend
        const t = d.color ? Math.max(0, Math.min(1, (d.dist - d.colorAt) / 48)) : 0;
        const c = t > 0 ? mix(neutral, d.color, t) : neutral;
        const r = L.compact ? 2.6 : 3.2;

        if (!reduced) {
          d.trail.push([x, y]); if (d.trail.length > 7) d.trail.shift();
          if (d.trail.length > 2) {
            ctx.lineCap = "round";
            for (let i = 1; i < d.trail.length; i++) {
              const a = i / d.trail.length;
              ctx.strokeStyle = rgba(c, a * (S.dark ? 0.32 : 0.24)); ctx.lineWidth = r * 1.5 * a;
              ctx.beginPath(); ctx.moveTo(d.trail[i - 1][0], d.trail[i - 1][1]); ctx.lineTo(d.trail[i][0], d.trail[i][1]); ctx.stroke();
            }
          }
          const sp = sprite(t < 0.5 ? neutral : d.color);
          ctx.globalAlpha = glowA; ctx.drawImage(sp, x - 14, y - 14, 28, 28); ctx.globalAlpha = 1;
        }
        ctx.fillStyle = rgba(c, 1);
        ctx.beginPath(); ctx.arc(x, y, r, 0, 6.2832); ctx.fill();
        if (d.lane != null && d.lane > 0 && d.dist >= m.entry) {                    // a Jev question is part of this request
          ctx.strokeStyle = rgba(purple, 0.9); ctx.lineWidth = 1.2;
          ctx.beginPath(); ctx.arc(x, y, r + 3, 0, 6.2832); ctx.stroke();
        }
      }
      S.dots = keep;
      ctx.restore();

      // landing ripples
      S.ripples = S.ripples.filter((rp) => {
        const k = (now - rp.t) / 520;
        if (k >= 1) return false;
        ctx.strokeStyle = rgba(rp.c, (1 - k) * 0.75); ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(rp.x, rp.y, 3 + k * 11, Math.PI * 0.5, Math.PI * 1.5); ctx.stroke();   // half ring, outside the card
        return true;
      });

      if (now - S.lastDom > 60) { S.lastDom = now; dom(now); }
      if (now - S.lastStats > 250) stats(now);
    }

    /* ------------------------------------------------------------ DOM updates (throttled) */
    const pct = (a, n) => (n ? Math.round((a / n) * 100) : 0);
    const p50 = (arr) => { if (!arr.length) return null; const s = arr.slice().sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };
    const p95 = (arr) => { if (!arr.length) return null; const s = arr.slice().sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * 0.95))]; };
    const msFmt = (v) => (v == null ? "—" : v < 10 ? v.toFixed(1) : Math.round(v).toLocaleString("en-US"));

    function glow(e, key, hit, now) {
      const a = Math.max(0, 1 - (now - hit) / 700);
      const c = S.colors[key] || S.colors["--accent"];
      e.style.boxShadow = a > 0.01 ? `0 0 0 1px ${rgba(c, 0.25 + a * 0.45)}, 0 0 ${10 + a * 26}px ${rgba(c, a * 0.45)}` : "";
    }

    function dom(now) {
      for (const c of CELLS) glow(cellEls[c.id], c.color, S.cellHit[c.id] || 0, now);
      glow(hubEl, "--accent", S.hubHit, now);
      glow(S.L.polW ? policyEl : entryEl, "--accent", S.entryHit, now);
      const pol = opts.policy && opts.policy();
      const polText = pol && pol.rules != null ? `${pol.rules} rules` + (S.L.compact ? "" : ` · rev ${pol.rev}`) : "";
      if (policyEl._metric.textContent !== polText) policyEl._metric.textContent = polText;
      const landed = S.counts.allow + S.counts.redact + S.counts.escalate + S.counts.block;
      for (const b of BINS) {
        const target = S.counts[b.key], cur = S.shown[b.key];
        S.shown[b.key] = cur + (target - cur) * 0.35 + (target > cur ? 0.2 : 0);
        if (Math.abs(target - S.shown[b.key]) < 0.5) S.shown[b.key] = target;
        const e = binEls[b.key], share = pct(target, landed) + "%";
        e._count.textContent = Math.round(S.shown[b.key]).toLocaleString("en-US");
        if (e._share.textContent !== share) { e._share.textContent = share; e._bar.style.width = share; }
      }
      for (const p of PORTS) portEls[p.key]._count.textContent = (S.ports[p.key] || 0).toLocaleString("en-US");
      const det = S.t0Times.length ? `p50 ${msFmt(p50(S.t0Times))} ms` : "";
      cellEls.d_det._metric.textContent = det;
      cellEls.dj_det._metric.textContent = det;
      for (const [id, lane] of [["dj_jev", 1], ["j_jev", 2]]) {
        let inflight = 0;
        for (const v of S.s1Inflight.values()) if (v.lane === lane) inflight += v.n;
        cellEls[id]._metric.textContent = inflight ? `${inflight} in flight` : S.s1Times[lane].length ? `p50 ${msFmt(p50(S.s1Times[lane]))} ms` : "";
      }
    }

    function stats(now) {
      S.lastStats = now;
      // throughput from when decisions arrived, so it stays right even if frames were paused (hidden tab)
      while (S.endTimes.length && S.endTimes[0] < now - 2000) S.endTimes.shift();
      S.rate += (S.endTimes.length / 2 - S.rate) * 0.4;
      if (S.rate < 0.05) S.rate = 0;
      S.peak = Math.max(S.peak, S.rate);
      if (!opts.onStats) return;
      opts.onStats({
        live: S.dots.length + S.queue.length, rate: S.rate, peak: S.peak, total: S.total,
        noLLMShare: S.total ? S.noLLM / S.total : null, s1Calls: S.s1Calls, s1Share: S.total ? S.s1Req / S.total : null,
        usd: S.usd, usdPer1k: S.total ? (S.usd / S.total) * 1000 : null, p50: p50(S.times), p95: p95(S.times),
        counts: { ...S.counts }, lanes: [...S.lanes],
      });
    }

    /* ------------------------------------------------------------ lifecycle */
    const ro = new ResizeObserver(() => resize());
    ro.observe(root);
    const mq = window.matchMedia ? matchMedia("(prefers-color-scheme: dark)") : null;
    const onScheme = () => { readColors(); drawBack(); };
    if (mq && mq.addEventListener) mq.addEventListener("change", onScheme);
    resize();
    if (!opts.manual) S.raf = requestAnimationFrame(frame);

    return {
      push, step,
      destroy() {
        S.destroyed = true; cancelAnimationFrame(S.raf); ro.disconnect();
        if (mq && mq.removeEventListener) mq.removeEventListener("change", onScheme);
      },
      reset() {
        S.dots = []; S.queue = []; S.info.clear(); S.ripples = []; S.s1Inflight.clear();
        for (const k of Object.keys(S.counts)) { S.counts[k] = 0; S.shown[k] = 0; }
        for (const k of Object.keys(S.ports)) S.ports[k] = 0;
        Object.assign(S, { total: 0, noLLM: 0, s1Req: 0, s1Calls: 0, usd: 0, rate: 0, peak: 0, lanes: [0, 0, 0],
                           times: [], t0Times: [], s1Times: { 1: [], 2: [] } });
      },
      debug: () => ({ live: S.dots.length, queued: S.queue.length, info: S.info.size, counts: { ...S.counts }, lanes: [...S.lanes],
                      total: S.total, L: S.L }),
    };
  }

  /* ---------------------------------------------------------------- the whole Silnik page body */
  const BIN_LABEL = Object.fromEntries(BINS.map((b) => [b.key, b.label]));
  const SURFACE = { "hook:claude-code": "Claude Code", "hook:codex": "Codex", sdk: "SDK", proxy: "Proxy", playground: "Playground" };
  const WHERE = { det: "deterministic", jev: "Jev" };
  const usdFmt = (v) => "$" + Number(v || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: v && v < 0.01 ? 6 : 4 });
  const numFmt = (v, d = 0) => Number(v || 0).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });
  const msShort = (v) => (v == null ? "—" : v < 10 ? numFmt(v, 1) : numFmt(v));
  const EMPTY_FEED = `<div class="empty">No decisions since the page opened.</div>`;

  function page(container, opts = {}) {
    opts = { backend: () => "—", onOpen: null, ...opts };
    container.innerHTML = `
      <div class="engine-kpi">
        ${[["live", "In flight", "--accent", "requests on screen"], ["rate", "Throughput", "--green", "peak —"],
           ["nollm", "No LLM", "--blue", "decided without Jev"], ["s1", "Jev calls", "--purple", "System One calls"],
           ["usd", "Control cost", "--orange", "Jev calls"], ["lat", "Gate latency p50", "--red", "excluding the agent's model"]]
          .map(([k, l, c, f]) => `<div class="card kpi" data-k="${k}"><div class="kpi-label"><i style="background:var(${c})"></i>${l}</div>
            <div class="kpi-value">—</div><div class="kpi-foot">${f}</div></div>`).join("")}
      </div>
      <div class="card flow-card mt">
        <div class="flow-head"><div><div class="card-title">Flow through the engine</div>
          <div class="card-sub">every dot is one real request</div></div></div>
        <div class="sf-host"></div>
        <div class="flow-legend">
          <span><i class="lg-dot"></i>in transit</span><span><i class="lg-ring"></i>asking Jev</span>
          <span class="lg-note">a dot stays in a Jev cell exactly as long as Jev takes to answer</span>
        </div>
      </div>
      <div class="grid g-21 mt">
        <div class="card"><div class="card-head"><div class="card-title">Latest decisions</div><div class="card-sub">in landing order</div></div>
          <div class="feed">${EMPTY_FEED}</div></div>
        <div class="card"><div class="card-head"><div class="card-title">Traffic by lane</div><div class="card-sub">since the page opened</div></div>
          <div class="cascade cascade-lanes"></div></div>
      </div>`;
    const tile = (k) => container.querySelector(`[data-k="${k}"]`);
    const feed = container.querySelector(".feed"), lanesBox = container.querySelector(".cascade-lanes");
    const lanes = [0, 0, 0];
    let rows = 0, cascadeDirty = false;

    function onDecision(r) {
      lanes[r.lane] = (lanes[r.lane] || 0) + 1;
      if (!rows) feed.innerHTML = "";
      const row = document.createElement("div");
      row.className = "feed-row fresh" + (opts.onOpen && r.seq ? " click" : "");
      const pill = document.createElement("span"); pill.className = `pill ${r.decision}`; pill.textContent = BIN_LABEL[r.decision];
      const main = document.createElement("div"); main.className = "feed-main";
      const what = document.createElement("div"); what.className = "what mono"; what.textContent = r.label || "—";
      const by = document.createElement("div"); by.className = "who";
      by.textContent = [r.agent || "unknown key", SURFACE[r.surface] || r.surface || "", LANES[r.lane] && LANES[r.lane].label]
        .filter(Boolean).join(" · ");
      main.append(what, by);
      const meta = document.createElement("div"); meta.className = "meta";
      const t = document.createElement("b"); t.textContent = `${msShort(r.ms)} ms`;
      const c = document.createElement("span"); c.className = "mono";
      const risk = typeof r.s1p === "number" ? `Jev: risk ${Math.round(r.s1p * 100)}%` : r.s1 ? "Jev" : "";
      if (r.decision === "allow") c.textContent = risk;                               // Jev approved, with its risk
      else if (r.decidedAt === "jev") c.textContent = [(r.controls || []).find(isJev) || (r.controls || [])[0], risk].filter(Boolean).join(" · ");
      else c.textContent = [(r.controls || []).find((x) => !isJev(x)) || (r.controls || [])[0], WHERE.det].filter(Boolean).join(" · ");
      if (risk) c.classList.add("jev");
      meta.append(t, c);
      row.append(pill, main, meta);
      if (opts.onOpen && r.seq) row.onclick = () => opts.onOpen(r.seq);
      feed.prepend(row); rows++;
      while (feed.children.length > 8) feed.lastChild.remove();
      cascadeDirty = true;                                         // redrawn on the next stats tick, not per landing
    }

    const bars = (items, total) => items.map(([n, l, col]) => {
      const p = total ? Math.round((n / total) * 100) : 0;
      return `<div><div class="bar-label"><span>${l}</span><span><b>${numFmt(n)}</b> · ${p}%</span></div>
        <div class="bar-track"><i style="width:${p}%;background:var(${col})"></i></div></div>`;
    }).join("");
    function renderCascade() {
      lanesBox.innerHTML = bars(LANES.map((l, i) => [lanes[i], l.label, i === 0 ? "--accent" : "--purple"]), lanes[0] + lanes[1] + lanes[2]);
    }
    renderCascade();

    const flow = create(container.querySelector(".sf-host"), {
      manual: opts.manual, clock: opts.clock || (() => performance.now()), policy: opts.policy, onPolicy: opts.onPolicy,
      onDecision,
      onStats(st) {
        if (cascadeDirty) { cascadeDirty = false; renderCascade(); }
        const set = (k, v, foot) => { const e = tile(k); if (!e) return; e.querySelector(".kpi-value").textContent = v; if (foot != null) e.querySelector(".kpi-foot").textContent = foot; };
        set("live", numFmt(st.live));
        set("rate", `${numFmt(st.rate, 1)}/s`, `peak ${numFmt(st.peak, 1)}/s`);
        set("nollm", st.noLLMShare == null ? "—" : `${Math.round(st.noLLMShare * 100)}%`, "decided without Jev");
        set("s1", numFmt(st.s1Calls), st.s1Share == null ? `backend: ${opts.backend()}` : `${Math.round(st.s1Share * 100)}% of requests · ${opts.backend()}`);
        set("usd", usdFmt(st.usd), st.usdPer1k == null ? "Jev calls" : `≈ ${usdFmt(st.usdPer1k)} per 1,000 requests`);
        set("lat", st.p50 == null ? "—" : `${msShort(st.p50)} ms`, st.p95 == null ? "excluding the agent's model" : `p95 ${msShort(st.p95)} ms`);
      },
    });
    return {
      push: flow.push, debug: flow.debug, step: flow.step,
      destroy: flow.destroy,
      reset() {
        flow.reset(); lanes.fill(0); rows = 0; feed.innerHTML = EMPTY_FEED; renderCascade();
      },
    };
  }

  window.SpireFlow = { create, page, BINS, LANES };
})();
