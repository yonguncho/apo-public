/* APO shell — 상태 바 · Overview · Action Plan · 하위 탭.
 *
 * app.js는 그대로 두고(기존 배선을 건드리지 않는다) 이 파일이 그 위에
 * 정보 구조를 얹는다. app.js는 상태가 바뀔 때 window.APO.on*() 만 호출한다.
 */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  /* 색과 이름은 Findings 화면(app.js의 SEV_BG/SEV_LABELS)과 같아야 한다.
     인접한 두 화면이 같은 등급을 다른 색·다른 말로 부르면 읽는 사람은
     둘이 다른 축이라고 생각한다. */
  const SEV_COLOR = { 0: "#B7B5AD", 1: "#FFCCCC", 2: "#D3D1C7", 3: "#FFE0B2",
                      4: "#B5D4F4", 5: "#FFF9C4", 6: "#C0DD97", 7: "#9FE1CB" };
  const SEV_NAME = { 0: "Unknown", 1: "Critical", 2: "High", 3: "Medium (S-U)",
                     4: "Medium (S-S)", 5: "Low (S-U)", 6: "Low (S-S)", 7: "Keep" };

  const table = (p) => (String(p._ptype || "").indexOf("proxy") >= 0
    ? "config firewall proxy-policy" : "config firewall policy");
  const cliDisable = (p) => `${table(p)}\n edit ${p.policy_id}\n  set status disable\n end`;
  const cliRemoveSvc = (p) =>
    `${table(p)}\n edit ${p.policy_id}\n  (remove flagged services from 'set service')\n end`;

  /* 조치 우선순위 · 근거 · 실행 명령.
   *
   * cli가 null인 조치에는 명령을 보여주지 않는다. 이건 스타일이 아니라 안전
   * 문제다 — "Register ticket"(접근은 정당한데 결재 기록이 없음) 아래에 복사
   * 버튼과 함께 `set status disable`이 놓이면, 서류를 만들라는 판정이 정책을
   * 꺼버리는 원클릭이 된다. 엑셀 Action Plan 시트(_ACTION_PLAN_ORDER)도 같은
   * 세 건에 명령을 비워 두므로, 화면과 산출물이 어긋나서도 안 된다.
   */
  const ACTION_ORDER = [
    ["Disable now", "Reversible, and stops the risk immediately", cliDisable],
    ["Remove service only", "Keep the policy, drop just the risky service", cliRemoveSvc],
    ["Disable & monitor", "Turn off, watch 30–90 days, then remove", cliDisable],
    ["Remove (already inert)", "Configuration already prevents any match — confirm, then delete", null],
    ["Needs review", "Not enough evidence to decide automatically", null],
    ["Register ticket", "Access looks legitimate but has no approval record", null],
  ];
  const NEXT_STEP = {
    "Remove (already inert)": "No command — confirm the policy is genuinely unused, then delete it in your change window.",
    "Needs review": "No command — a person has to decide this one. The reason above says what evidence is missing.",
    "Register ticket": "No command — raise a change record for this access so the next audit has an approval trail.",
  };

  const state = {
    config: null, findings: null, reach: null,
    usage: 0, ranges: 0, profile: null, license: null,
  };
  /* 완료 체크는 장비별로 따로 기억한다. 키를 공유하면 A장비에서 3·7·12번을
     체크한 컨설턴트가 B장비를 열었을 때 3·7·12번이 이미 완료로 그어져 있다 —
     정책 번호는 어느 장비에나 있는 정수라 반드시 충돌한다(재비판). */
  let doneKey = "apo.done";
  let done = loadDone();

  /* ── 화면 전환 (app.js의 하드코딩 setView를 대체) ─────────────── */
  const VIEWS = ["overview", "analysis", "severity", "remediation", "diff", "settings"];
  const SECTION = { overview: "overviewView", analysis: "analysisView",
                    severity: "severityView", remediation: "remediationView",
                    diff: "diffView", settings: "settingsView" };

  function setView(mode) {
    if (VIEWS.indexOf(mode) < 0) mode = "overview";
    document.querySelectorAll(".page-view").forEach((v) => v.classList.add("hidden"));
    $(SECTION[mode])?.classList.remove("hidden");
    document.querySelectorAll("[data-view]").forEach((b) =>
      b.classList.toggle("active", b.getAttribute("data-view") === mode));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  // 상단 nav 클릭은 app.js가 처리하고 window.APO.setView로 위임한다(리스너 중복 방지).
  function wireGoto(el) {
    el.addEventListener("click", () => {
      // data-sev가 있으면 등급 필터까지 걸어야 한다. 화면만 바꾸면 "Critical 2"를
      // 눌렀는데 직전 등급 필터가 걸린 표가 그대로 보인다.
      const sev = el.getAttribute("data-sev");
      if (sev !== null && el.getAttribute("data-goto") === "severity") {
        drillToSeverity(Number(sev));
        return;
      }
      setView(el.getAttribute("data-goto"));
      const sub = el.getAttribute("data-fnd-goto");
      if (sub) setFnd(sub);
    });
  }
  document.querySelectorAll("[data-goto]").forEach(wireGoto);

  /* ── Findings 하위 탭 ─────────────────────────────────────────── */
  /* 어느 숫자를 눌러 Findings로 왔는지와 상관없이 하위 탭은 직전 상태를
     유지했다. Unreachable 지표를 눌렀는데 Policy findings 탭이 열려 있으면,
     방금 클릭한 그 수치가 보이지 않는 화면에 도착한다. */
  function setFnd(key) {
    document.querySelectorAll(".fnd-tab").forEach((t) =>
      t.classList.toggle("active", t.getAttribute("data-fnd") === key));
    document.querySelectorAll("[data-fnd-panel]").forEach((p) =>
      p.classList.toggle("hidden", p.getAttribute("data-fnd-panel") !== key));
  }
  document.querySelectorAll(".fnd-tab").forEach((tab) => {
    tab.addEventListener("click", () => setFnd(tab.getAttribute("data-fnd")));
  });

  /* ── 상태 바 ─────────────────────────────────────────────────── */
  function chip(el, on, warn) {
    if (!el) return;
    el.classList.toggle("is-on", !!on && !warn);
    el.classList.toggle("is-warn", !!warn);
    el.classList.toggle("is-off", !on && !warn);
  }

  function renderStatus() {
    const meta = state.config?.meta || {};
    // hostname이 파싱되지 않는 config도 있다. else가 없으면 아래에 결과가
    // 떠 있는 채로 상단에는 "No configuration loaded"가 박혀 있게 된다.
    if (!state.config) {
      $("stDevice").textContent = "No configuration loaded";
      $("stDeviceSub").textContent = "Connect a device or import a config file to begin";
    } else {
      const name = meta.hostname || state.config.filename || "Unnamed device";
      $("stDevice").textContent = name;
      $("stDevice").title = name;   // 잘려도 전체 이름을 확인할 수 있게
      const bits = [];
      if (meta.config_version) bits.push(meta.config_version);
      if (state.config.policies != null) bits.push(`${state.config.policies} policies`);
      if (state.config.source) bits.push(state.config.source);
      $("stDeviceSub").textContent = bits.join(" · ");
    }
    chip($("stChipConfig"), !!state.config);
    chip($("stChipUsage"), state.usage > 0, state.config && !state.usage);
    chip($("stChipRanges"), state.ranges > 0, state.config && !state.ranges);
    chip($("stChipFqdn"), !!state.reach?.fqdn_captured_at);
    chip($("stChipAssessed"), !!state.findings);
    $("stProfile").textContent = state.profile ? "Criteria: " + state.profile : "";
    /* 조회에 실패하면 state.license가 null로 남는다. else가 없으면 Settings에
       "Checking…"이 영원히 박혀 있다 — 값과 설명을 짝지어 갱신하라는 같은
       규칙의 마지막 위반이었다. */
    const licensed = state.license?.licensed === true;
    const msp = state.license?.tier === "msp";
    $("stLicense").textContent = !state.license ? "" : (licensed ? (msp ? "MSP licence" : "Licensed") : "Free");
    $("stLicense").classList.toggle("is-paid", licensed);
    const st = $("setLicenseState");
    if (st) st.textContent = !state.license
      ? "Could not read the licence state — exports may be locked."
      : licensed
        ? `Active — ${state.license.email || ""} (${msp ? "MSP / Consultant" : "Single organisation"})`
        : "No licence — exports are locked, everything else works.";
    const hint = $("setLicenseHint");
    if (hint) hint.textContent = !state.license ? ""
      : licensed ? (msp ? "MSP / Consultant — report white-labelling enabled" : "Single organisation")
                 : "one-time purchase · includes 1 year of updates";
  }

  /* ── Overview ────────────────────────────────────────────────── */
  function allPolicies() {
    const f = state.findings;
    if (!f) return [];
    return (f.firewall || []).map((p) => ({ ...p, _ptype: "firewall" }))
      .concat((f.proxy || []).map((p) => ({ ...p, _ptype: "proxy" })));
  }

  function renderOverview() {
    const has = !!state.config;
    $("ovEmpty").classList.toggle("hidden", has);
    $("ovContent").classList.toggle("hidden", !has);
    if (!has) return;

    const meta = state.config.meta || {};
    $("ovTitle").textContent = meta.hostname ? `${meta.hostname} — assessment` : "Assessment overview";
    $("ovSubtitle").textContent = state.findings
      ? "Every number below links to the findings behind it."
      : "Configuration loaded. Run the assessment to see findings.";

    const pols = allPolicies();
    $("ovMetricPolicies").textContent = state.config.policies ?? (pols.length || "—");
    $("ovMetricPoliciesNote").textContent = state.config.source || "";

    const actionable = new Set(ACTION_ORDER.map((a) => a[0]));
    const byAction = {};
    let critical = 0, unknown = 0;
    pols.forEach((p) => {
      if (p.urgency === 1) critical += 1;
      if ((p.urgency ?? 0) === 0) unknown += 1;
      const lab = p.action_label || "";
      if (actionable.has(lab)) byAction[lab] = (byAction[lab] || 0) + 1;
    });
    const needsAction = Object.values(byAction).reduce((a, b) => a + b, 0);
    $("ovMetricAction").textContent = state.findings ? needsAction : "—";
    $("ovMetricCritical").textContent = state.findings ? critical : "—";
    $("ovMetricUnknown").textContent = state.findings ? unknown : "—";
    /* 값과 설명문은 반드시 같은 조건에서 갱신한다. 값만 초기화하고 설명문에
       else를 안 달면, 다음 장비에서 값은 "—"인데 밑에는 이전 장비의 문장이
       그대로 남는다. 지금까지 두 번 같은 형태로 사고가 났다. */
    $("ovMetricUnknownNote").textContent = !state.findings
      ? "run the assessment to see this"
      : unknown ? "not enough data to judge — excluded from the counts here"
                : "every policy was judged";
    $("ovMetricUnreachable").textContent = state.reach ? (state.reach.unreachable || []).length : "—";
    // "provably" 라고만 적으면 전수 검사한 것처럼 읽힌다. 실제로는 FQDN·지역·
    // ISDB·사용자 객체·부정 조건 정책을 건너뛴다. 검사 범위를 카드에 같이 적는다.
    const sk = (state.reach?.skipped || []).length;
    $("ovMetricUnreachableNote").textContent = !state.reach
      ? "unreachable — never match traffic"
      : sk ? `checked ${state.reach.checked} of ${state.reach.total_enabled} enabled — ${sk} could not be resolved`
           : `all ${state.reach.checked} enabled policies checked`;

    // 심각도 분포
    const counts = {};
    pols.forEach((p) => { counts[p.urgency ?? 0] = (counts[p.urgency ?? 0] || 0) + 1; });
    const total = pols.length || 1;
    const bar = $("ovSevBar"), leg = $("ovSevLegend");
    const levels = Object.keys(counts).map(Number).sort((a, b) => a - b);
    bar.innerHTML = levels.map((lv) => {
      const pct = (counts[lv] / total) * 100;
      return `<div class="ov-sevbar-seg" data-sev="${lv}" style="width:${pct}%;background:${SEV_COLOR[lv]}"
                   title="Severity ${lv} — ${counts[lv]} policies">${pct > 6 ? counts[lv] : ""}</div>`;
    }).join("");
    leg.innerHTML = levels.map((lv) =>
      `<span class="ov-legend-item" data-sev="${lv}"><i class="ov-legend-dot" style="background:${SEV_COLOR[lv]}"></i>
        ${lv} ${esc(SEV_NAME[lv] || "")} <strong>${counts[lv]}</strong></span>`).join("");
    bar.querySelectorAll("[data-sev]").forEach(gotoFindings);
    leg.querySelectorAll("[data-sev]").forEach(gotoFindings);

    // 조치별
    const max = Math.max(1, ...Object.values(byAction));
    $("ovActions").innerHTML = ACTION_ORDER.filter(([k]) => byAction[k])
      .map(([k]) => `<div class="ov-action-row" data-goto="remediation">
          <span class="ov-action-name">${esc(k)}</span>
          <span class="ov-action-bar"><i style="width:${(byAction[k] / max) * 100}%"></i></span>
          <span class="ov-action-count">${byAction[k]}</span></div>`).join("")
      || `<div class="ov-gap-text" style="padding:10px 8px">No actionable findings — run the assessment first.</div>`;
    $("ovActions").querySelectorAll("[data-goto]").forEach((el) =>
      el.addEventListener("click", () => setView("remediation")));

    renderGaps(pols);
  }

  /* Overview의 숫자를 눌렀을 때 Findings에서 그 숫자가 실제로 보이게 만든다.
     화면·하위탭·firewall/proxy 탭·등급 필터가 전부 맞아야 하고, 넷 중 하나만
     빠져도 "누른 값과 다른 화면"이 된다. 그래서 한 곳에 모아 둔다. */
  function drillToSeverity(lv) {
    setView("severity");
    setFnd("policies");   // 필터가 걸리는 표가 이 패널 안에 있다
    /* Overview 막대는 firewall과 proxy를 합쳐 세지만 Findings 표는 한 번에
       한쪽만 보여준다. 탭을 한 방향으로만 바꾸면, proxy 전용 등급을 본 뒤에
       firewall 등급을 누를 때 proxy 표에 필터가 걸려 "0건"이 뜬다. 양방향으로
       맞춘다. */
    const has = (side) => (state.findings?.[side] || []).some((p) => (p.urgency ?? 0) === lv);
    const want = has("firewall") ? "firewall" : (has("proxy") ? "proxy" : null);
    if (want) {
      const btn = document.querySelector(`.sev-subtab-btn[data-sev-tab="${want}"]`);
      if (btn && !btn.classList.contains("active")) btn.click();
    }
    /* Findings의 등급 칩은 토글이다. 이미 그 등급으로 걸려 있는데 또 누르면
       필터가 풀린다 — Overview에서 "Critical"을 두 번째로 눌렀을 때 필터가
       사라지는 꼴이라, 켜져 있지 않을 때만 누른다. */
    const chipEl = document.querySelector(`.sev-chip[data-sev="${lv}"]`);
    if (chipEl) {
      if (!chipEl.classList.contains("active")) chipEl.click();
      return;
    }
    /* 해당 등급이 0건이면 칩 자체가 없다. 그냥 두면 직전에 걸어 둔 다른 등급의
       필터가 남아, "Critical 0"을 누르고 Medium 정책 목록을 보게 된다.
       걸려 있는 필터를 꺼서 전체 목록으로 되돌린다. */
    document.querySelector(".sev-chip.active")?.click();
  }
  function gotoFindings(el) {
    el.addEventListener("click", () => drillToSeverity(Number(el.getAttribute("data-sev"))));
  }

  /* 근거의 한계를 결과와 같은 위계로 보여준다 — 무엇이 빠졌고 그래서 무엇을
     판정하지 못했는지 말하지 않으면, 읽는 사람이 수치를 실제보다 확정적으로 읽는다. */
  function renderGaps(pols) {
    const g = [];
    const unknown = pols.filter((p) => (p.urgency ?? 0) === 0).length;
    g.push(state.usage
      ? ok("Usage statistics", `Loaded for ${state.usage} policies — disuse can be judged.`)
      : warn("Usage statistics missing", "Hit counts and last-used dates are not loaded, so no policy can be called unused. Collect from the device or import the policy CSV.", "analysis"));
    g.push(state.ranges
      ? ok("User IP ranges", `${state.ranges} range(s) set — server and user traffic can be told apart.`)
      : warn("User IP ranges not set", unknown
          ? `${unknown} policies cannot be assessed without knowing which ranges belong to users.`
          : "Needed to tell server traffic from user traffic.", "severity"));
    if (state.reach) {
      const skipped = (state.reach.skipped || []).length;
      g.push(skipped
        ? warn("Unreachable check coverage", `${state.reach.checked}/${state.reach.total_enabled} policies assessed; ${skipped} skipped because their objects cannot be resolved offline.`, "severity", "unreachable")
        : ok("Unreachable check coverage", `All ${state.reach.checked} enabled policies assessed.`));
      if (state.reach.fqdn_captured_at) {
        g.push(ok("FQDN resolutions", `Captured ${state.reach.fqdn_captured_at} — FQDN findings are provable as of that time, not indefinitely.`));
      }
    }
    $("ovGaps").innerHTML = g.join("");
    // 정적 마크업의 [data-goto]와 똑같은 처리를 쓴다 — 여기만 따로 구현하면
    // 규칙이 늘 때마다 한쪽이 빠진다(지금까지 그렇게 세 번 어긋났다).
    $("ovGaps").querySelectorAll("[data-goto]").forEach(wireGoto);
  }
  const ok = (t, d) => `<div class="ov-gap is-ok"><span class="ov-gap-icon">✓</span>
      <div class="ov-gap-body"><div class="ov-gap-title">${esc(t)}</div><div class="ov-gap-text">${esc(d)}</div></div></div>`;
  const warn = (t, d, goto, sub) => `<div class="ov-gap is-warn"><span class="ov-gap-icon">!</span>
      <div class="ov-gap-body"><div class="ov-gap-title">${esc(t)}</div><div class="ov-gap-text">${esc(d)}</div></div>
      ${goto ? `<button type="button" class="mini-btn ov-gap-act" data-goto="${goto}"${sub ? ` data-fnd-goto="${sub}"` : ""}>Fix</button>` : ""}</div>`;

  /* ── Action Plan ─────────────────────────────────────────────── */
  function loadDone() {
    try { return new Set(JSON.parse(localStorage.getItem(doneKey) || "[]")); }
    catch (_) { return new Set(); }
  }
  function saveDone() {
    try { localStorage.setItem(doneKey, JSON.stringify([...done])); } catch (_) {}
  }

  function updateProgress() {
    const boxes = $("apGroups").querySelectorAll(".ap-check");
    const hit = $("apGroups").querySelectorAll(".ap-check:checked").length;
    $("apProgress").textContent = boxes.length ? `${hit} of ${boxes.length} done` : "";
  }

  function renderActionPlan() {
    const pols = allPolicies();
    const groups = [];
    const seen = new Set();

    // 도달 불가는 증거가 가장 강하므로 맨 위에 둔다(엑셀 Action Plan과 동일 순서).
    const un = (state.reach?.unreachable || []).map((u) => ({
      policy_id: u.policy_id, name: u.name, _ptype: "firewall",
      reason: `Never matches traffic — policy ${u.shadowed_by} above it already handles everything it could match`,
      action_label: "Unreachable", proof: u.proof,
    }));
    /* 원래 조치 라벨(Register ticket 등)과 무관하게 disable 명령을 준다.
       명령 없는 조치 규칙의 예외로 보일 수 있지만 의도한 것이다 — 도달불가는
       "이 정책은 어떤 패킷도 매칭하지 않는다"는 증명이고 라벨보다 강한 근거다.
       매칭되지 않는 정책에 결재를 붙이거나 서비스만 빼는 건 의미가 없다.

       다만 증명의 등급은 두 가지고, 이 둘을 한 그룹에 담으면 안 된다.
       proof=config는 설정만으로 영구히 참이지만, proof=capture는 DNS 캐시를
       뜬 그 시점의 해석 결과에 기댄다. 내일 FQDN이 다른 IP로 풀리면 그 정책은
       살아난다. "설정상 확실"이라는 머리말 아래 그걸 같이 두면, 시한부 근거를
       영구 증명으로 읽게 만든다. */
    /* 강한 주장은 proof가 'config'라고 명시된 경우에만 한다. 값이 없거나
       모르는 등급이면 약한 쪽으로 보낸다 — 판정 등급이 늘었을 때 기본값이
       "설정상 확실"이 되면, 새 등급이 조용히 과대 주장으로 나간다. */
    const byProof = [
      [(u) => u.proof === "config",
       "Shadowed (unreachable) — provably dead",
       "Certain from the configuration alone — this stays true until the rules change"],
      [(u) => u.proof !== "config",
       "Shadowed — verify before removing",
       // 이 그룹에는 capture 근거와 '등급 미상'이 함께 들어온다. 수집이 있었다고
       // 단정하지 않으면서 시한부라는 점은 분명히 하는 문구여야 한다.
       "Not provable from the configuration alone — the evidence can change over time, so re-check before removing"],
    ];
    byProof.forEach(([pick, name, why]) => {
      const rows = un.filter(pick);
      if (!rows.length) return;
      rows.forEach((u) => seen.add("firewall:" + u.policy_id));
      groups.push({ name, why, cli: cliDisable, rows });
    });
    ACTION_ORDER.forEach(([label, why, cli]) => {
      const rows = pols.filter((p) => p.action_label === label && !seen.has(p._ptype + ":" + p.policy_id));
      if (rows.length) groups.push({ name: label, why, cli, rows });
    });

    const empty = !groups.length;
    $("apEmpty").classList.toggle("hidden", !empty);
    $("apGroups").classList.toggle("hidden", empty);
    // 숨기기만 하면 이전 장비의 행이 DOM에 남는다 — MSP는 한 세션에서 여러
    // 고객 장비를 연다. 남은 마크업이 다른 고객 것으로 보일 여지를 없앤다.
    if (empty) { $("apGroups").innerHTML = ""; $("apProgress").textContent = ""; return; }

    $("apGroups").innerHTML = groups.map((g, gi) => {
      const rows = g.rows.map((p) => {
        const key = p._ptype + ":" + p.policy_id;
        const isDone = done.has(key);
        const cmd = g.cli ? g.cli(p) : null;
        return `<div class="ap-row ${isDone ? "done" : ""}" data-key="${esc(key)}">
            <input type="checkbox" class="ap-check" data-key="${esc(key)}" ${isDone ? "checked" : ""} />
            <span class="ap-row-id">#${esc(p.policy_id)}</span>
            <div>
              <div class="ap-row-name">${esc(p.name || "(unnamed)")}</div>
              <div class="ap-row-reason">${esc(p.reason || "")}${p.proof === "capture" ? " · proof: DNS capture" : ""}</div>
              ${cmd ? `<div class="ap-cli">${esc(cmd)}</div>`
                    : `<div class="ap-nocli">${esc(NEXT_STEP[g.name] || "No command for this action.")}</div>`}
            </div>
            ${cmd ? `<button type="button" class="mini-btn ap-copy" data-cli="${esc(cmd)}">Copy</button>` : "<span></span>"}
          </div>`;
      }).join("");
      return `<div class="ap-group ${gi === 0 ? "open" : ""}">
          <div class="ap-group-head">
            <span class="ap-group-rank">${gi + 1}</span>
            <div><div class="ap-group-name">${esc(g.name)}</div><div class="ap-group-why">${esc(g.why)}</div></div>
            <span class="ap-group-count">${g.rows.length}</span>
          </div>
          <div class="ap-rows">${rows}</div></div>`;
    }).join("");

    updateProgress();
    $("apGroups").querySelectorAll(".ap-group-head").forEach((h) =>
      h.addEventListener("click", () => h.parentElement.classList.toggle("open")));
    // 체크할 때마다 전체를 다시 그리면 펼쳐 둔 그룹이 닫히고 포커스가 날아가,
    // 40행짜리 목록을 한 건 체크할 때마다 다시 찾아 들어가야 한다. 제자리 갱신.
    $("apGroups").querySelectorAll(".ap-check").forEach((cb) =>
      cb.addEventListener("change", () => {
        const k = cb.getAttribute("data-key");
        cb.checked ? done.add(k) : done.delete(k);
        cb.closest(".ap-row")?.classList.toggle("done", cb.checked);
        saveDone(); updateProgress();
      }));
    $("apGroups").querySelectorAll(".ap-copy").forEach((b) =>
      b.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(b.getAttribute("data-cli")); b.textContent = "Copied"; }
        catch (_) { b.textContent = "Select manually"; }
        setTimeout(() => { b.textContent = "Copy"; }, 1400);
      }));
  }

  $("apResetBtn")?.addEventListener("click", () => { done.clear(); saveDone(); renderActionPlan(); });
  $("ovRunBtn")?.addEventListener("click", () => {
    setView("severity"); setFnd("policies"); $("sevClassifyBtn")?.click();
  });
  $("setLicenseBtn")?.addEventListener("click", () => $("licenseModal")?.classList.remove("hidden"));
  /* 시작 버튼 두 개가 같은 화면으로만 보내면 사실 같은 버튼이다. 장비 연결은
     접힌 아코디언을 펴 주고, 파일 가져오기는 파일 선택창을 바로 연다. */
  $("ovStartCollect")?.addEventListener("click", () => {
    const d = $("collectDetails"); if (d) d.open = true;
    $("collIp")?.focus();
  });
  $("ovStartUpload")?.addEventListener("click", () => $("configFile")?.click());

  /* ── app.js가 부르는 훅 ───────────────────────────────────────── */
  window.APO = {
    setView,
    onConfig(info) {
      state.config = info; state.findings = null; state.reach = null;
      /* 서버가 준 설정 해시로 기억을 가른다. hostname은 공장 기본값
         "FortiGate"로 남은 장비가 흔해 서로 다른 고객 장비가 한 키를 공유하고,
         장비 수집 경로에는 filename 자체가 없다. */
      doneKey = "apo.done." + (info?.configSha
        || info?.meta?.hostname || info?.filename || "unknown");
      done = loadDone();
      renderStatus(); renderOverview(); renderActionPlan();
    },
    /* app.js가 이전 분류 결과를 버릴 때(=설정이 실제로 바뀌었을 때) 불린다.
       서버는 파싱/수집이 성공한 뒤에만 상태를 갈아치우므로 이 호출도 성공
       경로에서만 일어난다 — 실패한 업로드는 서버 상태를 안 건드리니 화면의
       기존 결과도 여전히 유효하고, 그때 지우면 멀쩡한 분석을 날리게 된다.
       config 자체는 건드리지 않는다(곧 onConfig가 새 값으로 덮는다). */
    onStale() {
      state.findings = null; state.reach = null;
      /* 사용량 데이터도 이 설정에 딸린 것이라 같이 버린다. 바로 뒤에 onConfig →
         onUsage가 새 값으로 덮으므로 실제로는 깜빡임도 없다.
         반대로 user IP 대역은 분석가의 환경 설정이지 이 설정 파일의 속성이
         아니므로 유지한다. */
      state.usage = 0;
      renderStatus(); renderOverview(); renderActionPlan();
    },
    onUsage(n)     { state.usage = n || 0; renderStatus(); renderOverview(); },
    onRanges(n)    { state.ranges = n || 0; renderStatus(); renderOverview(); },
    onFindings(d)  { state.findings = d; state.reach = d?.reachability || null;
                     renderStatus(); renderOverview(); renderActionPlan(); },
    // 라이선스 등록 직후 — 다시 물어보고 헤더/Settings 표시를 갱신한다.
    async onLicense() {
      try { state.license = await (await fetch("/api/license/status")).json(); } catch (_) {}
      renderStatus();
    },
  };

  /* ── 초기화 ──────────────────────────────────────────────────── */
  (async () => {
    try {
      const p = await (await fetch("/api/profile")).json();
      state.profile = p.name || "default";
    } catch (_) {}
    try { state.license = await (await fetch("/api/license/status")).json(); } catch (_) {}
    renderStatus(); renderOverview(); renderActionPlan();
  })();
})();
