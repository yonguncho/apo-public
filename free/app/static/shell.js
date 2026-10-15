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

  /* 이 파일은 번역 통로를 전혀 쓰지 않고 있었다 — 그래서 개요 화면의 문구가
     한국어 모드에서도 통째로 영어였다(라운드 30 지적). app.js 와 **같은
     사전**을 쓴다. i18n.js 가 아직 안 실렸으면 원문을 그대로 돌려준다. */
  const t = (text, vars) => (window.APO_I18N?.t
    ? window.APO_I18N.t(text, vars)
    : String(text).replace(/\{(\w+)\}/g, (m, k) =>
        (vars && vars[k] != null ? String(vars[k]) : m)));

  /* "어디서 온 설정인가" 한 줄. app.js 가 **완성된 문장이 아니라 {key, vars}**
     를 넘긴다 — 완성된 것을 받아 들고 있었더니 언어를 바꿔도 그 한 줄만
     영어로 남았다(다시 그려도 이미 번역된 문자열을 그대로 쓰니까). 그릴 때
     번역해야 다시 그리기가 언어 전환을 따라간다. */
  const sourceText = (src) => (!src ? ""
    : typeof src === "string" ? src        /* 옛 형태 — 번역은 안 되지만 사라지지도 않는다 */
    : t(src.key, src.vars));

  /* 색과 이름은 Findings 화면(app.js의 SEV_BG/SEV_LABELS)과 같아야 한다.
     인접한 두 화면이 같은 등급을 다른 색·다른 말로 부르면 읽는 사람은
     둘이 다른 축이라고 생각한다. */
  const SEV_COLOR = { 0: "#B7B5AD", 1: "#FFCCCC", 2: "#D3D1C7", 3: "#FFE0B2",
                      4: "#B5D4F4", 5: "#FFF9C4", 6: "#C0DD97", 7: "#9FE1CB" };
  const SEV_NAME = { 0: "Unknown", 1: "Critical", 2: "High", 3: "Medium (S-U)",
                     4: "Medium (S-S)", 5: "Low (S-U)", 6: "Low (S-S)", 7: "Keep" };

  const table = (p) => (String(p._ptype || "").indexOf("proxy") >= 0
    ? "config firewall proxy-policy" : "config firewall policy");
  /* **VDOM 은 정책 번호의 일부다.** 워크북 Action Plan 은 명령을
     `config vdom / edit <이름>` 으로 감싸는데(_cli_with_vdom) 화면 복사
     버튼만 맨 명령을 줬다 — 기본 SSH 세션(관리 VDOM)에서 붙여넣으면 같은
     번호의 **다른 VDOM 살아있는 정책**이 꺼진다(라운드 47 이 워크북에서
     고친 사고의 화면 형제, 라운드 54). 같은 이유로 행 식별 키에도 VDOM 을
     넣는다 — 단일 VDOM(vdom 없음)은 기존 키 그대로라 저장된 완료 체크가
     유지된다. */
  const wrapVdom = (cli, vdom) =>
    (vdom ? `config vdom\nedit ${vdom}\n${cli}\nend` : cli);
  const cliDisable = (p) => wrapVdom(
    `${table(p)}\n edit ${p.policy_id}\n  set status disable\n end`, p.vdom);
  const cliRemoveSvc = (p) => wrapVdom(
    `${table(p)}\n edit ${p.policy_id}\n  (remove flagged services from 'set service')\n end`, p.vdom);
  const rowKey = (p) =>
    p._ptype + ":" + (p.vdom ? p.vdom + "/" : "") + p.policy_id;

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
    usage: 0, usageVdom: "", ranges: 0, profile: null, license: null,
  };
  /* 완료 체크는 장비별로 따로 기억한다. 키를 공유하면 A장비에서 3·7·12번을
     체크한 컨설턴트가 B장비를 열었을 때 3·7·12번이 이미 완료로 그어져 있다 —
     정책 번호는 어느 장비에나 있는 정수라 반드시 충돌한다(재비판). */
  let doneKey = "apo.done";
  let done = loadDone();

  /* ── 화면 전환 (app.js의 하드코딩 setView를 대체) ─────────────── */
  const VIEWS = ["overview", "analysis", "severity", "remediation",
                 "diff", "evidence", "ipref", "customers", "settings",
                 "reference"];
  const SECTION = { overview: "overviewView", analysis: "analysisView",
                    severity: "severityView", remediation: "remediationView",
                    diff: "diffView", evidence: "evidenceView",
                    ipref: "iprefView", customers: "customersView",
                    settings: "settingsView", reference: "referenceView" };

  function setView(mode) {
    if (VIEWS.indexOf(mode) < 0) mode = "overview";
    document.querySelectorAll(".page-view").forEach((v) => v.classList.add("hidden"));
    $(SECTION[mode])?.classList.remove("hidden");
    /* 하위 항목(data-fnd-goto가 있는 것)은 상위 항목과 같은 data-view를 갖는다.
       그것까지 active로 칠하면 세 개가 동시에 켜지므로 상위만 칠한다. */
    document.querySelectorAll("[data-view]").forEach((b) => {
      if (b.hasAttribute("data-fnd-goto")) return;
      b.classList.toggle("active", b.getAttribute("data-view") === mode);
    });
    // Findings를 떠나면 하위 항목 강조도 끈다
    if (mode !== "severity") {
      document.querySelectorAll(".side-subitem").forEach((b) => b.classList.remove("active"));
    } else if (!document.querySelector(".side-subitem.active")) {
      /* 상위 "Findings"만 눌러 들어온 경우 — 지금 열려 있는 패널의 하위 항목을
         칠한다. 마크업에 active를 하드코딩하면 첫 화면부터 강조가 떠 있게 된다. */
      const vis = document.querySelector("[data-fnd-panel]:not(.hidden)");
      if (vis) setFnd(vis.getAttribute("data-fnd-panel"));
    }
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

  /* 사이드바 하위 항목은 data-view로 화면을 바꾸지만(app.js가 처리), 어느
     패널을 열지는 아무도 안 정해 준다 — 눌러도 상위 화면만 뜨고 패널은 직전
     상태 그대로다. 여기서 잇는다. */
  document.querySelectorAll(".side-subitem[data-fnd-goto]").forEach((el) => {
    el.addEventListener("click", () => setFnd(el.getAttribute("data-fnd-goto")));
  });

  /* ── Findings 하위 탭 ─────────────────────────────────────────── */
  /* 어느 숫자를 눌러 Findings로 왔는지와 상관없이 하위 탭은 직전 상태를
     유지했다. Unreachable 지표를 눌렀는데 Policy findings 탭이 열려 있으면,
     방금 클릭한 그 수치가 보이지 않는 화면에 도착한다. */
  function setFnd(key) {
    document.querySelectorAll(".side-subitem").forEach((t) =>
      t.classList.toggle("active", t.getAttribute("data-fnd-goto") === key));
    document.querySelectorAll("[data-fnd-panel]").forEach((p) =>
      p.classList.toggle("hidden", p.getAttribute("data-fnd-panel") !== key));
  }

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
      $("stDevice").textContent = t("No configuration loaded");
      $("stDeviceSub").textContent =
        t("Connect a device or import a config file to begin");
    } else {
      const name = meta.hostname || state.config.filename || t("Unnamed device");
      /* 고객사를 함께 말한다. 여러 고객사를 다루는 도구에서 'DEMO-FGT-01' 만
         보여주면 누구 장비인지 알 수 없고, 자동 이어받기로 열린 아침에는
         특히 그렇다(라운드 22 지적). hostname 이 공장 기본값으로 겹치는
         장비들에서는 이게 유일한 구분이 되기도 한다. */
      const label = state.customer ? `${state.customer} · ${name}` : name;
      $("stDevice").textContent = label;
      $("stDevice").title = label;   // 잘려도 전체 이름을 확인할 수 있게
      const bits = [];
      if (meta.config_version) bits.push(meta.config_version);
      if (state.config.policies != null)
        bits.push(t("{n} policies", { n: state.config.policies }));
      if (state.config.source) bits.push(sourceText(state.config.source));
      $("stDeviceSub").textContent = bits.join(" · ");
    }
    chip($("stChipConfig"), !!state.config);
    chip($("stChipUsage"), state.usage > 0, state.config && !state.usage);
    chip($("stChipRanges"), state.ranges > 0, state.config && !state.ranges);
    chip($("stChipFqdn"), !!state.reach?.fqdn_captured_at);
    chip($("stChipAssessed"), !!state.findings);
    $("stProfile").textContent = state.profile
      ? t("Criteria: {name}", { name: state.profile }) : "";
    /* 조회에 실패하면 state.license가 null로 남는다. else가 없으면 Settings에
       "Checking…"이 영원히 박혀 있다 — 값과 설명을 짝지어 갱신하라는 같은
       규칙의 마지막 위반이었다. */
    const licensed = state.license?.licensed === true;
    const msp = state.license?.tier === "msp";
    $("stLicense").textContent = !state.license ? ""
      : licensed ? (msp ? t("MSP licence") : t("Licensed")) : t("Free");
    $("stLicense").classList.toggle("is-paid", licensed);
    const st = $("setLicenseState");
    if (st) st.textContent = !state.license
      ? t("Could not read the licence state — exports may be locked.")
      : licensed
        ? t("Active — {email} ({tier})", { email: state.license.email || "",
            tier: msp ? t("MSP / Consultant") : t("Single organisation") })
        /* **자격을 잃은 유료 고객에게 사유를 말한다.** 서버가 `problem` 을
           내려주는데 화면이 안 읽어서, $699 를 낸 MSP 가 업데이트 창 만료로
           잠겨도 "No licence" 만 보였다 — 자기가 왜 무료 사용자가 됐는지 알
           방법이 없었다(2026-09-10 재비판 F1). 키가 아예 없는 미구매와
           자격상실은 다른 상황이고, 다르게 말해야 한다. */
        : (state.license.problem
           || t("No licence — exports are locked, everything else works."));
    /* **잠기기 전에 알린다.** 종료일을 서버가 주는데 아무도 안 읽어서
       고객은 잠긴 뒤에야 알았다 — 갱신 매출이 여기 달려 있다. */
    if (licensed && st && state.license.update_window_end) {
      const end = new Date(state.license.update_window_end + "T00:00:00");
      const days = Math.ceil((end - new Date()) / 86400000);
      if (days <= 30) {
        st.textContent += "  " + (days >= 0
          ? t("Included updates end on {date} ({days} days left).",
              { date: state.license.update_window_end, days: String(days) })
          : t("Included updates ended on {date}. This version keeps working.",
              { date: state.license.update_window_end }));
      }
    }
    const hint = $("setLicenseHint");
    if (hint) hint.textContent = !state.license ? ""
      : licensed ? (msp ? t("MSP / Consultant — report white-labelling enabled")
                        : t("Single organisation"))
                 // 미구매 상태에서는 두 안의 가격을 여기서 처음 본다.
                 : (state.license.problem
                    ? t("Your key is saved but not currently valid — see above.")
                    : t("$199 single organisation · $699 MSP / consultant"));
  }

  /* ── Overview ────────────────────────────────────────────────── */
  function allPolicies() {
    const f = state.findings;
    if (!f) return [];
    return (f.firewall || []).map((p) => ({ ...p, _ptype: "firewall" }))
      .concat((f.proxy || []).map((p) => ({ ...p, _ptype: "proxy" })));
  }

  function renderOverview() {
    /* **'못 읽었다'와 '비었다'는 다른 말이다.** 보관소를 못 읽는데 첫 화면이
       '장비를 연결하거나 설정 파일을 가져오세요'를 띄우면, 사용자는 데이터가
       사라졌다고 판단한다(라운드 41). 그 오해의 대가는 복구 가능한 파일을
       지우는 것이다. */
    if (state.storeError) {
      $("ovEmpty").classList.remove("hidden");
      $("ovContent").classList.add("hidden");
      const e = $("ovEmpty");
      e.innerHTML = `<div class="ov-empty-title">${esc(t("APO could not read its saved devices"))}</div>`
        + `<div class="ov-empty-sub">${esc(state.storeError)}</div>`;
      return;
    }
    const has = !!state.config;
    $("ovEmpty").classList.toggle("hidden", has);
    $("ovContent").classList.toggle("hidden", !has);
    if (!has) return;

    const meta = state.config.meta || {};
    $("ovTitle").textContent = meta.hostname
      ? t("{name} — assessment", { name: meta.hostname })
      : t("Assessment overview");
    $("ovSubtitle").textContent = state.findings
      ? t("Every number below links to the findings behind it.")
      : t("Configuration loaded. Run the assessment to see findings.");

    const pols = allPolicies();
    $("ovMetricPolicies").textContent = state.config.policies ?? (pols.length || "—");
    $("ovMetricPoliciesNote").textContent = sourceText(state.config.source);

    let critical = 0, unknown = 0;
    pols.forEach((p) => {
      if (p.urgency === 1) critical += 1;
      if ((p.urgency ?? 0) === 0) unknown += 1;
    });
    /* **조치 계획이 실제로 말할 것을 그대로 센다.** 라벨별로 따로 세면
       가려진 정책 재분류를 놓쳐 두 화면의 수가 어긋난다(라운드 39). */
    const byAction = {};
    planGroups().forEach((g) => { byAction[g.name] = g.rows.length; });
    const needsAction = Object.values(byAction).reduce((a, b) => a + b, 0);
    $("ovMetricAction").textContent = state.findings ? needsAction : "—";
    $("ovMetricCritical").textContent = state.findings ? critical : "—";
    $("ovMetricUnknown").textContent = state.findings ? unknown : "—";
    /* 값과 설명문은 반드시 같은 조건에서 갱신한다. 값만 초기화하고 설명문에
       else를 안 달면, 다음 장비에서 값은 "—"인데 밑에는 이전 장비의 문장이
       그대로 남는다. 지금까지 두 번 같은 형태로 사고가 났다. */
    /* **"집계에서 제외됩니다"는 사실이 아니었다.** 판정 불가(등급 0) 정책은
       바로 옆 '조치 필요' 수에도, 아래 심각도 분포에도 **들어 있다**(실측:
       정책 5건 중 판정 불가 1건인데 조치 필요도 5, 분포 합계도 5). 안내문이
       반대로 말하면 사용자는 분모를 잘못 읽는다 — 어디에 있는지 사실대로
       적고, 무엇을 하면 판정되는지 알려 준다(라운드 45). */
    $("ovMetricUnknownNote").textContent = !state.findings
      ? t("run the assessment to see this")
      : unknown ? t("counted as Unknown below — set User IP ranges to judge them")
                : t("every policy was judged");
    $("ovMetricUnreachable").textContent = state.reach ? (state.reach.unreachable || []).length : "—";
    // "provably" 라고만 적으면 전수 검사한 것처럼 읽힌다. 실제로는 FQDN·지역·
    // ISDB·사용자 객체·부정 조건 정책을 건너뛴다. 검사 범위를 카드에 같이 적는다.
    const sk = (state.reach?.skipped || []).length;
    /* **증거로 쓸 수 없었던 정책도 커버리지다.** '모르는 필드가 있으면 가림막
       으로 믿지 않는다'는 규칙 때문에 발견이 0건이 될 수 있는데, 그 사실이
       어디에도 안 남으면 '발견 0건'이 '이상 없음'으로 읽힌다 — 같은 장비를
       `show full-configuration` 으로 받으면 전건 보류인데 화면은 초록으로
       '전수 검사했다'고 말했다(라운드 43 실측). */
    const nt = (state.reach?.untrusted_shadowers || []).length;
    $("ovMetricUnreachableNote").textContent = !state.reach
      ? t("unreachable — never match traffic")
      : sk ? t("checked {n} of {total} enabled firewall policies — {skipped} "
               + "could not be resolved",
               { n: state.reach.checked, total: state.reach.total_enabled,
                 skipped: sk })
           : nt ? t("checked all {n} enabled firewall policies, but {u} of them "
                    + "use features APO does not model, so they were not used "
                    + "as evidence — findings here may be incomplete",
                    { n: state.reach.checked, u: nt })
                : t("all {n} enabled firewall policies checked",
                    { n: state.reach.checked });

    // 심각도 분포
    const counts = {};
    pols.forEach((p) => { counts[p.urgency ?? 0] = (counts[p.urgency ?? 0] || 0) + 1; });
    const total = pols.length || 1;
    const bar = $("ovSevBar"), leg = $("ovSevLegend");
    const levels = Object.keys(counts).map(Number).sort((a, b) => a - b);
    bar.innerHTML = levels.map((lv) => {
      const pct = (counts[lv] / total) * 100;
      return `<div class="ov-sevbar-seg" data-sev="${lv}" style="width:${pct}%;background:${SEV_COLOR[lv]}"
                   title="${esc(t("Severity {lv} — {n} policies",
                                 { lv, n: counts[lv] }))}">${pct > 6 ? counts[lv] : ""}</div>`;
    }).join("");
    leg.innerHTML = levels.map((lv) =>
      `<span class="ov-legend-item" data-sev="${lv}"><i class="ov-legend-dot" style="background:${SEV_COLOR[lv]}"></i>
        ${lv} ${esc(SEV_NAME[lv] || "")} <strong>${counts[lv]}</strong></span>`).join("");
    bar.querySelectorAll("[data-sev]").forEach(gotoFindings);
    leg.querySelectorAll("[data-sev]").forEach(gotoFindings);

    // 조치별
    const max = Math.max(1, ...Object.values(byAction));
    $("ovActions").innerHTML = Object.keys(byAction)
      .map((k) => `<div class="ov-action-row" data-goto="remediation">
          <span class="ov-action-name">${esc(k)}</span>
          <span class="ov-action-bar"><i style="width:${(byAction[k] / max) * 100}%"></i></span>
          <span class="ov-action-count">${byAction[k]}</span></div>`).join("")
      || `<div class="ov-gap-text" style="padding:10px 8px">${
            esc(t("No actionable findings — run the assessment first."))}</div>`;
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
    /* **값이 하나도 없으면 초록이면 안 된다.** 8라운드에 전체 등급으로
       가드를 걸었는데 그것은 다른 축이라 한 번도 안 탔고, 탔더라도 `ok()`
       라 초록 체크가 그대로였다 — 이 패널은 아이콘으로 훑는 자리다
       (9라운드 F5). 사용량 축의 사실로 판단하고 경고로 렌더한다. */
    g.push(state.usage && !state.usageUsable
      ? warn(t("Hit count / last used has no values"),
             t("{n} rows matched this configuration, but none of them carry a "
               + "hit count or a last-used date — check that you picked the "
               + "Hit Count column, not Bytes.", { n: state.usage }),
             "analysis")
      : state.usage
      ? ok(t("Hit count / last used"),
           state.usageVdom
             /* 한 VDOM 만 커버하면서 장비 전체 문장으로 말하면, 다른 VDOM
                정책이 전부 'usage unknown' 인데 초록 체크가 그걸 숨긴다
                (라운드 56 완성도 렌즈 — 워크북 문서정보와 같은 규칙). */
             ? t("Loaded for {n} policies in VDOM '{vdom}' only — policies in "
                 + "other VDOMs are judged without usage data.",
                 { n: state.usage, vdom: state.usageVdom })
             /* **행이 있다는 것과 값이 있다는 것은 다르다.** FortiGate GUI
                에서 Bytes 칸을 Hit Count 로 골라 올리면(흔한 실수) 파서가
                쓰레기를 0 이 아니라 `null` 로 정직하게 돌리는데, 이 패널은
                "행 N건 매칭" 만 보고 **"미사용 판정이 가능합니다" 초록 체크**
                를 줬다 — 실제로는 판정 가능한 것이 0건이다(8라운드 발견 5).
                이 패널의 존재 이유가 "지금 이 결과를 제약하는 것" 을 말하는
                것인데, 제약이 100% 인 상태에서 제약 없음이라고 말했다.
                판정 불가 수는 **바로 위에서 이미 세고 있다** — 그걸 본다. */
             : t("Loaded for {n} policies — disuse can be judged.",
                   { n: state.usage }))
      : warn(t("Hit count / last used missing"),
             t("No per-policy usage history is loaded, so no policy can be called "
               + "unused. Collect from the device or import the policy CSV."),
             "analysis"));
    g.push(state.ranges
      ? ok(t("User IP ranges"),
           t("{n} range(s) set — server and user traffic can be told apart.",
             { n: state.ranges }))
      : warn(t("User IP ranges not set"), unknown
          ? t("{n} policies cannot be assessed without knowing which ranges "
              + "belong to users.", { n: unknown })
          : t("Needed to tell server traffic from user traffic."), "severity"));
    if (state.reach) {
      const skipped = (state.reach.skipped || []).length;
      g.push(skipped
        ? warn(t("Unreachable check coverage"),
               t("{n} of {total} enabled firewall policies assessed; {skipped} "
                 + "skipped because their objects cannot be resolved offline. "
                 + "Proxy policies are outside this check.",
                 { n: state.reach.checked, total: state.reach.total_enabled,
                   skipped }), "severity", "unreachable")
        : ok(t("Unreachable check coverage"),
             t("All {n} enabled firewall policies assessed. Proxy policies are "
               + "outside this check.", { n: state.reach.checked })));
      if (state.reach.fqdn_captured_at) {
        g.push(ok(t("FQDN resolutions"),
                  t("Captured {when} — FQDN findings are provable as of that "
                    + "time, not indefinitely.",
                    { when: state.reach.fqdn_captured_at })));
      }
    }
    $("ovGaps").innerHTML = g.join("");
    // 정적 마크업의 [data-goto]와 똑같은 처리를 쓴다 — 여기만 따로 구현하면
    // 규칙이 늘 때마다 한쪽이 빠진다(지금까지 그렇게 세 번 어긋났다).
    $("ovGaps").querySelectorAll("[data-goto]").forEach(wireGoto);
  }
  /* 인자 이름을 t 로 두면 **모듈의 번역 함수 t() 를 가린다** — 안에서 t("Fix")
     를 부르는 순간 "t is not a function" 으로 이 패널이 통째로 안 그려진다
     (실측). 제목·본문이라는 뜻이 드러나는 이름을 쓴다. */
  const ok = (title, text) => `<div class="ov-gap is-ok"><span class="ov-gap-icon">✓</span>
      <div class="ov-gap-body"><div class="ov-gap-title">${esc(title)}</div><div class="ov-gap-text">${esc(text)}</div></div></div>`;
  /* goto/sub도 이스케이프한다 — 지금은 전 호출부가 리터럴이지만, 동적 값이
     들어오는 순간 속성 주입이 되는 풋건이었다(리뷰 게이트 지적). */
  const warn = (title, text, goto, sub) => `<div class="ov-gap is-warn"><span class="ov-gap-icon">!</span>
      <div class="ov-gap-body"><div class="ov-gap-title">${esc(title)}</div><div class="ov-gap-text">${esc(text)}</div></div>
      ${goto ? `<button type="button" class="mini-btn ov-gap-act" data-goto="${esc(goto)}"${sub ? ` data-fnd-goto="${esc(sub)}"` : ""}>${esc(t("Fix"))}</button>` : ""}</div>`;

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
    $("apProgress").textContent = boxes.length
      ? t("{done} of {total} done", { done: hit, total: boxes.length }) : "";
  }

  /* **조치 그룹은 한 곳에서만 계산한다.**
     개요와 조치 계획이 각자 세던 동안, 같은 라벨('Disable now')에 서로 다른
     수가 인쇄됐다(개요 4 / 계획 1). 가려진 정책을 앞 그룹으로 옮기며
     재분류하는 것을 개요가 몰랐기 때문이다 — 두 화면이 같은 세션에서 다른
     말을 하면 어느 쪽을 믿어야 할지 알 수 없다(라운드 39). */
  function planGroups() {
    const pols = allPolicies();
    const groups = [];
    const seen = new Set();

    /* 도달 불가는 증거가 가장 강하므로 맨 위에 둔다(엑셀 Action Plan과 동일 순서).

       단, "절대 매칭 안 됨"은 **가리는 상위 정책이 켜져 있는 동안만** 참이다.
       그 상위 정책이 같은 계획에서 끄라고 지목돼 있으면, 시키는 대로 상위를 끈
       순간 아래 정책들이 되살아난다 — 그리고 계획은 그걸 삭제하라고 적어 뒀다.
       순서를 안 알려주면 장애가 난다(샘플에서 6건 중 5건이 이 관계였다). */
    /* 선행관계는 (VDOM, 번호)로 판정한다 — 번호만 보면 다른 VDOM 의 같은
       번호가 "이 계획이 바꾼다"로 잡혀 거짓 유보가 생기고, 워크북 Action
       Plan(같은 판정을 (vdom, policy_id)로 함)과 같은 정책을 다른 그룹에
       놓는다(라운드 54 — 라운드 50 이 워크북에서 고친 것의 화면판). 가림막은
       가려진 정책과 같은 VDOM 에 있으므로 u.vdom 으로 함께 조회한다. */
    const wcKey = (vdom, id) => `${vdom || ""}|${id}`;
    const willChange = new Set(
      pols.filter((p) => p._ptype === "firewall" &&
        ["Disable now", "Disable & monitor", "Remove (already inert)"].includes(p.action_label))
        .map((p) => wcKey(p.vdom, p.policy_id)));
    (state.reach?.unreachable || []).forEach((u) => willChange.add(wcKey(u.vdom, u.policy_id)));

    const un = (state.reach?.unreachable || []).map((u) => ({
      policy_id: u.policy_id, name: u.name, _ptype: "firewall",
      vdom: u.vdom || "",
      /* **번역하지 않는다.** 이 문장은 워크북 Action Plan 의 Why 칸과 같은
         내용이고, 감사자는 화면과 엑셀을 나란히 놓고 본다. 한쪽만 번역하면
         같은 정책이 두 문서에서 다른 말을 하게 된다(스모크가 잡는다). */
      reason: `Never matches traffic — policy ${u.shadowed_by} above it already handles everything it could match`
        + (willChange.has(wcKey(u.vdom, u.shadowed_by))
           ? ` — but this plan also changes policy ${u.shadowed_by}. Decide that one first; if it is disabled, re-run the assessment before touching this policy.`
           : ""),
      action_label: "Unreachable", proof: u.proof,
      dependsOn: willChange.has(wcKey(u.vdom, u.shadowed_by)) ? u.shadowed_by : null,
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
       // **워크북과 글자까지 같아야 한다.** 화면을 번역하지 않는
       // 이유가 "엑셀과 같은 말을 해야 한다" 인데, 정작 두 곳이
       // 서로 다른 영어를 쓰고 있었다(라운드 40 지적). 그러면
       // 번역을 막는 근거 자체가 성립하지 않는다.
       "Unreachable (provably never matches)",
       "Certain from the configuration alone — this stays true until the rules change"],
      [(u) => u.proof !== "config",
       "Unreachable — verify before removing",
       // 이 그룹에는 capture 근거와 '등급 미상'이 함께 들어온다. 수집이 있었다고
       // 단정하지 않으면서 시한부라는 점은 분명히 하는 문구여야 한다.
       "Not provable from the configuration alone — the evidence can change over time, so re-check before removing"],
    ];
    /* **경고만으로는 부족했다.** Why 칸에 '먼저 정하라'고 적어 두고도 순서와
       체크박스는 반대를 지시했고, 인쇄된 순서대로 실행하면 승인된 운영 정책이
       죽었다(R39 실측 3건). 증명이 이 계획 자신에 기대는 정책은 **명령 없이
       맨 뒤로** 보낸다 — 가림막을 어떻게 할지 정하기 전에는 할 말이 없다. */
    /* seen 키에도 VDOM — 번호만 잡으면 VDOM-A 의 도달불가 7번이 VDOM-B 의
       살아있는 7번을 조치 그룹에서 통째로 지운다(라운드 54 — 라운드 50 이
       배치 집계에서 고친 것과 동일 클래스의 화면판, 과소보고). */
    byProof.forEach(([pick, name, why]) => {
      const rows = un.filter((u) => pick(u) && !u.dependsOn);
      if (!rows.length) return;
      rows.forEach((u) => seen.add(rowKey(u)));
      groups.push({ name, why, cli: cliDisable, rows });
    });
    un.filter((u) => u.dependsOn).forEach((u) => seen.add(rowKey(u)));
    ACTION_ORDER.forEach(([label, why, cli]) => {
      const rows = pols.filter((p) => p.action_label === label && !seen.has(rowKey(p)));
      if (rows.length) groups.push({ name: label, why, cli, rows });
    });

    /* 증명이 위 항목들에 기대는 정책 — 맨 뒤, 명령 없음. */
    const later = un.filter((u) => u.dependsOn);
    if (later.length) {
      groups.push({
        name: "Decide after the changes above",
        why: "These are unreachable only while the policies above stay enabled, "
             + "and this plan changes those. Do the rows above first, take a "
             + "fresh backup, and run APO again — these may be live by then.",
        cli: null, rows: later });
    }

    return groups;
  }

  function renderActionPlan() {
    const groups = planGroups();
    const empty = !groups.length;
    $("apEmpty").classList.toggle("hidden", !empty);
    $("apGroups").classList.toggle("hidden", empty);
    // 숨기기만 하면 이전 장비의 행이 DOM에 남는다 — MSP는 한 세션에서 여러
    // 고객 장비를 연다. 남은 마크업이 다른 고객 것으로 보일 여지를 없앤다.
    if (empty) { $("apGroups").innerHTML = ""; $("apProgress").textContent = ""; return; }

    $("apGroups").innerHTML = groups.map((g, gi) => {
      const rows = g.rows.map((p) => {
        /* 완료 체크 키에도 VDOM — 번호만 쓰면 root#7 을 체크할 때 guest#7
           까지 완료로 그어진다(라운드 54. 장비별 done 분리까지 해 놓고 VDOM
           축만 빠져 있었다). 행 표시도 어느 VDOM 의 몇 번인지 말한다. */
        const key = rowKey(p);
        const isDone = done.has(key);
        const cmd = g.cli ? g.cli(p) : null;
        return `<div class="ap-row ${isDone ? "done" : ""}" data-key="${esc(key)}">
            <input type="checkbox" class="ap-check" data-key="${esc(key)}" ${isDone ? "checked" : ""} />
            <span class="ap-row-id">${p.vdom ? esc(p.vdom) : ""}#${esc(p.policy_id)}</span>
            <div>
              <div class="ap-row-name">${esc(p.name || t("(unnamed)"))}</div>
              <div class="ap-row-reason">${esc(p.reason || "")}${p.proof === "capture" ? " · proof: DNS capture" : ""}</div>
              ${cmd ? `<div class="ap-cli">${esc(cmd)}</div>`
                    : `<div class="ap-nocli">${esc(t(NEXT_STEP[g.name]
                        || "No command for this action."))}</div>`}
            </div>
            ${cmd ? `<button type="button" class="mini-btn ap-copy" data-cli="${esc(cmd)}">${esc(t("Copy"))}</button>` : "<span></span>"}
          </div>`;
      }).join("");
      return `<div class="ap-group ${gi === 0 ? "open" : ""}">
          <div class="ap-group-head">
            <span class="ap-group-rank">${gi + 1}</span>
            <div><div class="ap-group-name">${esc(t(g.name))}</div><div class="ap-group-why">${esc(t(g.why))}</div></div>
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
        try { await navigator.clipboard.writeText(b.getAttribute("data-cli")); b.textContent = t("Copied"); }
        catch (_) { b.textContent = t("Select manually"); }
        setTimeout(() => { b.textContent = t("Copy"); }, 1400);
      }));
  }

  $("apResetBtn")?.addEventListener("click", () => { done.clear(); saveDone(); renderActionPlan(); });
  $("ovRunBtn")?.addEventListener("click", () => {
    setView("severity"); setFnd("policies"); $("sevClassifyBtn")?.click();
    /* FortiOS 권고 분석도 함께 돈다 — '점검 실행' 후 '판정 완료' 칩이
       켜져도 펌웨어 취약점 점검은 미실행이라는 사실이 어디에도 안 떠서,
       권고 탭은 있는데 발견 안 되는 기능이었다(2026-08-25 전면 검토 M-8.
       config 만으로 도는 검사라 추가 입력·비용이 없다). */
    $("advisorRunBtn")?.click();
  });
  /* 정책 표는 넓을수록 좋다. 접힘 상태는 기억한다 — 매번 다시 접게 하면
     넓게 쓰려는 사람에게 계속 방해가 된다. */
  const SIDE_KEY = "apo.sideCollapsed";
  function applySide(collapsed) {
    document.body.classList.toggle("side-collapsed", collapsed);
    const b = $("sideCollapseBtn");
    if (b) { b.textContent = collapsed ? "»" : "«";
             b.title = collapsed ? t("Expand menu") : t("Collapse menu"); }
  }
  try { applySide(localStorage.getItem(SIDE_KEY) === "1"); } catch (_) {}
  $("sideCollapseBtn")?.addEventListener("click", () => {
    const next = !document.body.classList.contains("side-collapsed");
    applySide(next);
    try { localStorage.setItem(SIDE_KEY, next ? "1" : "0"); } catch (_) {}
  });

  /* 사이드바 높이는 **자기가 실제로 시작하는 위치**에서 계산한다. CSS에
     'calc(100vh - 60px)'처럼 헤더 높이를 박아 두면, 위에 상태 밴드가 있는
     화면에서 박스가 그만큼 아래로 밀려 마지막 메뉴가 첫 화면에서 잘린다
     (실측: 상단 123px인데 60px로 계산 → 세로 512px 이하에서 '판정 기준'이
     화면 밖). 상수를 고치는 대신 측정값을 쓴다. */
  const sideEl = document.querySelector(".app-side");
  function sizeSide() {
    if (!sideEl) return;
    // **지금 뷰포트에서의 top**을 그대로 쓴다. 스크롤 전에는 상태 밴드 아래
    // (실측 123px), 스티키로 붙은 뒤에는 60px이다. 문서 좌표와 섞으면 값이
    // 어긋나 박스가 다시 화면 밖으로 넘친다.
    const reserve = Math.max(0, Math.round(sideEl.getBoundingClientRect().top));
    sideEl.style.maxHeight = `calc(100vh - ${reserve}px)`;
  }
  /* 스크롤마다 곧바로 부르면 읽기(getBoundingClientRect)와 쓰기(inline style)가
     번갈아 일어나 매 이벤트에서 강제 레이아웃이 발생한다. 프레임당 한 번으로 묶는다. */
  let sidePending = false;
  const sizeSideSoon = () => {
    if (sidePending) return;
    sidePending = true;
    requestAnimationFrame(() => { sidePending = false; sizeSide(); });
  };
  sizeSide();
  window.addEventListener("resize", sizeSideSoon);
  window.addEventListener("scroll", sizeSideSoon, { passive: true });

  $("setLicenseBtn")?.addEventListener("click", () => $("licenseModal")?.classList.remove("hidden"));
  /* 시작 버튼 두 개가 같은 화면으로만 보내면 사실 같은 버튼이다. 장비 연결은
     수집 카드의 첫 입력에 포커스를 주고, 파일 가져오기는 파일 선택창을 바로 연다. */
  /* preventScroll — setView의 smooth 스크롤과 focus의 즉시 스크롤이 경합해
     화면이 덜컥거렸다. 스크롤은 setView가, 포커스는 여기가 맡는다. */
  $("ovStartCollect")?.addEventListener("click", () => $("collIp")?.focus({ preventScroll: true }));
  $("ovStartUpload")?.addEventListener("click", () => $("configFile")?.click());

  /* ── 테마 ── 저장된 값은 <head>의 인라인 스크립트가 첫 페인트 전에 적용한다.
     여기서는 버튼 상태 표시와 클릭 배선만 맡는다. */
  const THEME_KEY = "apo.theme";
  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t === "light" ? "light" : "dark");
    document.querySelectorAll("#themeSeg [data-set-theme]").forEach((b) => {
      const on = b.getAttribute("data-set-theme") === t;
      b.classList.toggle("on", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }
  {
    let saved = "dark";
    try { saved = localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark"; } catch (_) {}
    applyTheme(saved);
  }
  document.querySelectorAll("#themeSeg [data-set-theme]").forEach((b) =>
    b.addEventListener("click", () => {
      const t = b.getAttribute("data-set-theme");
      applyTheme(t);
      try { localStorage.setItem(THEME_KEY, t); } catch (_) {}
    }));

  /* ── app.js가 부르는 훅 ───────────────────────────────────────── */
  window.APO = {
    setView,
    /* 지금 열린 장비의 고객사. app.js 가 장비를 채택할 때(adoptDeviceSession)
       한 번만 알려 주고, 상단 상태바가 그것을 쓴다. */
    onCustomer(name) {
      state.customer = name || "";
      renderStatus();
    },
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
    onStoreError(msg) { state.storeError = msg || ""; renderOverview(); },
    onUsage(n, vdom, usable) {
      state.usage = n || 0;
      // 행 수와 **값이 있는 행 수**는 다르다(app.js `_statsUsable` 주석).
      state.usageUsable = (usable === undefined) ? (n || 0) : (usable || 0);
      /* 통계가 한 VDOM 것이면 그 사실을 화면도 말한다(라운드 56) */
      state.usageVdom = vdom || "";
      renderStatus(); renderOverview();
    },
    onRanges(n)    { state.ranges = n || 0; renderStatus(); renderOverview(); },
    onFindings(d)  { state.findings = d; state.reach = d?.reachability || null;
                     renderStatus(); renderOverview(); renderActionPlan(); },
    // 라이선스 등록 직후 — 다시 물어보고 헤더/Settings 표시를 갱신한다.
    async onLicense() {
      try { state.license = await (await fetch("/api/license/status")).json(); } catch (_) {}
      renderStatus();
    },
  };

  /* 언어가 바뀌면 **코드가 만든 문장도** 다시 그린다. data-i18n 은 HTML 에
     이미 있는 요소만 덮으므로, 이 신호가 없으면 한국어로 바꿔도 개요 카드는
     영어로 남는다(라운드 30 지적: 개요가 통째로 영어). */
  document.addEventListener("apo:lang-changed", () => {
    try { renderStatus(); renderOverview(); renderActionPlan(); }
    catch (_) { /* 부팅 전이면 아래 초기화가 곧 그린다 */ }
  });

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
