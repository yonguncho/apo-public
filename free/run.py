import os
import sys
import socket
import webbrowser
import threading
from app.server import create_app, APP_PORT, token_setup_error

app = create_app()

# 포트는 server.py 가 정한다(APO_PORT). 여기서 따로 5000 을 적으면 Host 검사와
# 실제 바인딩이 갈려, 다른 포트로 띄우는 순간 전 요청이 403 이 된다.
PORT = APP_PORT

def get_lan_ip():
    """이 PC 의 LAN IP. **패킷은 나가지 않는다** — UDP 소켓에 connect() 를 하면
    커널이 라우팅 표를 보고 출발지 주소만 정하고 끝난다.

    **대상 주소를 사설 대역으로 둔다.** 예전에는 `8.8.8.8`(구글 DNS)을 썼는데,
    폐쇄망 고객이 소스나 방화벽 로그를 검토하면 **"이 제품이 구글에 접속한다"고
    오해한다**(2026-09-10 마케팅 검토 지적). 이 제품의 가장 큰 판매 논거가
    "외부로 아무것도 나가지 않는다" 인데, 그 논거를 이 한 줄이 설명 없이는
    방어 불가능하게 만들었다. 동작은 같고 오해만 사라진다.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    frozen = getattr(sys, 'frozen', False)
    docker_mode = os.environ.get("APO_DOCKER", "0") == "1"

    if docker_mode:
        # 컨테이너 배포: 외부 접근이 필요하므로 모든 인터페이스에 바인딩.
        # **그래서 토큰이 없으면 뜨지 않는다**(B-77, 2026-08-26 Jayden 승인).
        # 여기서 그냥 띄우면 이 포트에 닿는 누구나 고객 config 를 읽고 실장비
        # 정책을 끌 수 있다 — APO 에는 다른 로그인이 없다. 조용히 열어 두는
        # 것보다 안 뜨는 편이 낫고, 무엇을 하라는지는 아래에서 말해 준다.
        problem = token_setup_error()
        if problem:
            print("[APO] Refusing to start.\n" + problem, flush=True)
            sys.exit(2)
        lan_ip = get_lan_ip()
        print(f"[APO] Local  : http://127.0.0.1:{PORT}/?token=<APO_TOKEN>")
        print(f"[APO] Network: http://{lan_ip}:{PORT}/?token=<APO_TOKEN>")
        print("[APO] The token is checked once, then kept in a cookie.")
        app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
    elif frozen:
        # 데스크톱 exe: 로컬 전용(127.0.0.1)으로만 바인딩 → LAN 노출/무인증 접근 차단
        print(f"[APO] Local  : http://127.0.0.1:{PORT}")
        def _open_browser():
            import time
            time.sleep(1.2)
            webbrowser.open(f"http://127.0.0.1:{PORT}")
        threading.Thread(target=_open_browser, daemon=True).start()
        app.run(host="127.0.0.1", port=PORT, debug=False, use_reloader=False)
    else:
        # 개발: 로컬 전용. **리로더는 기본으로 끈다** — 켜 두면 프로세스가 둘이
        # 되어, 검증 중 파일이 스쳐도 서버가 재기동되며 세션 상태(app.config)가
        # 통째로 날아간다(이 루프에서 검증자 실행을 두 번 죽였다).
        # 디버거가 필요하면 APO_DEBUG=1 로 명시적으로 켠다.
        _dbg = os.environ.get("APO_DEBUG") == "1"
        print(f"[APO] Local  : http://127.0.0.1:{PORT}"
              + (" (debug)" if _dbg else ""))
        app.run(host="127.0.0.1", port=PORT, debug=_dbg, use_reloader=_dbg)
