/* APO 화면 언어 — 메뉴·제목·설명·버튼만 번역한다.
 *
 * 판정 사유, 조치 라벨, 정책/객체 이름, Last Used 같은 표 내용은 **영어로 둔다**.
 * 이유가 둘이다:
 *   1) 그 문자열들은 엔진이 만들어 엑셀 산출물에도 그대로 실린다. 화면만 한글로
 *      바꾸면 같은 판정이 두 곳에서 다른 말로 나온다 — 이번 개발에서 화면과
 *      산출물이 어긋나 생긴 사고를 여러 번 고쳤다.
 *   2) FortiGate 엔지니어는 hit count·last used·srcaddr를 영어로 읽는다.
 *      번역하면 오히려 대조가 어려워진다.
 *
 * 키는 영어 원문 자체다. 사전에 없으면 원문이 그대로 남는다(안전한 폴백).
 */
(function () {
  "use strict";

  const KO = {
    // ── 사이드바 ──
    "Overview": "개요",
    "Sources": "데이터 가져오기",
    "Findings": "점검 결과",
    "Policy findings": "정책 판정",
    "Shadowed (unreachable)": "가려진 정책",
    "FortiOS advisories": "FortiOS 권고",
    "Action Plan": "조치 계획",
    "Change review": "변경 비교",
    "Evidence": "감사 증적",
    "Settings": "설정",
    "How it judges": "판정 기준",

    // ── Overview ──
    "Assess a FortiGate ruleset": "FortiGate 정책 점검",
    "Connect a device": "장비 연결",
    "Import a config file": "설정 파일 가져오기",
    "Run assessment": "점검 실행",
    "Open action plan": "조치 계획 열기",
    "Assessment overview": "점검 개요",
    "Severity distribution": "심각도 분포",
    "What to do": "무엇을 할 것인가",
    "Evidence coverage": "근거 충족도",
    "click a band to filter findings": "막대를 누르면 해당 등급만 봅니다",
    "by action, in working order": "조치 순서대로",
    "what limits these results right now": "지금 이 결과를 제약하는 것",
    "Policies": "정책 수",
    "Needs action": "조치 필요",
    "Critical": "심각",
    "Shadowed": "가려짐",
    "Not judged": "판정 불가",
    "policies with a recommended change": "권고 조치가 있는 정책",
    "disable now — counted inside Needs action": "즉시 비활성 — 조치 필요에 포함됨",
    "unreachable — never match traffic": "도달 불가 — 트래픽이 매칭되지 않음",
    "excluded from the counts above": "위 집계에서 제외됨",

    // ── Sources ──
    "Config File": "설정 파일",
    "Collect from device": "장비에서 수집",
    "Fetch FQDN from device": "장비에서 FQDN 조회",
    "Upload DNS cache dump": "DNS 캐시 덤프 업로드",
    "Import from File": "파일에서 가져오기",
    "Add": "추가",
    "Classify": "판정 실행",
    "Setup": "준비",
    "User IP ranges": "사용자 IP 대역",

    // ── Findings / Action Plan ──
    "Prioritised work list": "우선순위 작업 목록",
    "Clear checkmarks": "완료 표시 지우기",
    "Apply changes over the API": "API로 장비에 적용",
    "Device": "장비",
    "Connect the FortiGate": "FortiGate 연결",
    "Select": "선택",
    "Choose policies to disable": "비활성할 정책 선택",
    "Load Candidates": "후보 불러오기",
    "Export CSV": "CSV 내보내기",
    "Export JSON": "JSON 내보내기",
    "Save Device": "장비 저장",
    "Test Connection": "연결 확인",
    "Select All": "전체 선택",
    "Cancel": "취소",
    "Confirm": "확인",

    // ── Change review / Evidence ──
    "Configuration Change Review": "설정 변경 비교",
    "Ruleset Review Evidence": "정책 검토 증적",
    "Accuracy Verification": "정확도 검증",
    "Build timeline": "타임라인 만들기",
    "Verify": "검증",
    "Audit Trail": "감사 추적",

    // ── Settings / Reference ──
    "Assessment thresholds": "판정 임계값",
    "License": "라이선스",
    "Language": "언어",
    "Enter a licence key": "라이선스 키 입력",
    "See a sample report": "샘플 리포트 보기",
    "See a sample report (.xlsx)": "샘플 리포트 보기 (.xlsx)",
    "Buy Now →": "구매하기 →",
    "Activate": "등록",
    "Single organisation": "단일 조직",
    "MSP / Consultant": "MSP · 컨설턴트",
    "Guide": "안내",
    "How policies are judged": "정책 판정 기준",
    "Severity Classification Criteria": "심각도 분류 기준",
  };

  const DICTS = { ko: KO, en: {} };
  const KEY = "apo.lang";

  function currentLang() {
    try { return localStorage.getItem(KEY) || "en"; } catch (_) { return "en"; }
  }

  function apply(lang) {
    const dict = DICTS[lang] || {};
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      // 원문을 한 번만 보관한다. 이게 없으면 한→영 복귀 때 되돌릴 원본이 없다.
      if (el.dataset.i18nSrc === undefined) {
        el.dataset.i18nSrc = el.textContent.replace(/\s+/g, " ").trim();
      }
      const src = el.dataset.i18nSrc;
      el.textContent = dict[src] || src;
    });
    document.documentElement.lang = lang;
    const sel = document.getElementById("setLangSelect");
    if (sel && sel.value !== lang) sel.value = lang;
  }

  function setLang(lang) {
    try { localStorage.setItem(KEY, lang); } catch (_) {}
    apply(lang);
  }

  document.addEventListener("DOMContentLoaded", () => {
    apply(currentLang());
    document.getElementById("setLangSelect")
      ?.addEventListener("change", (e) => setLang(e.target.value));
  });
  // DOMContentLoaded를 이미 지났으면 바로 적용한다(스크립트 순서 변경 대비).
  if (document.readyState !== "loading") apply(currentLang());

  window.APO_I18N = { apply, setLang, currentLang };
})();
