import os
import sys
import socket
import webbrowser
import threading
from app.server import create_app

app = create_app()

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    frozen = getattr(sys, 'frozen', False)
    docker_mode = os.environ.get("APO_DOCKER", "0") == "1"

    if docker_mode:
        # 컨테이너 배포: 외부 접근이 필요하므로 모든 인터페이스에 바인딩
        lan_ip = get_lan_ip()
        print(f"[APO] Local  : http://127.0.0.1:5000")
        print(f"[APO] Network: http://{lan_ip}:5000")
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    elif frozen:
        # 데스크톱 exe: 로컬 전용(127.0.0.1)으로만 바인딩 → LAN 노출/무인증 접근 차단
        print(f"[APO] Local  : http://127.0.0.1:5000")
        def _open_browser():
            import time
            time.sleep(1.2)
            webbrowser.open("http://127.0.0.1:5000")
        threading.Thread(target=_open_browser, daemon=True).start()
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    else:
        # 개발: 로컬 전용 + 디버거는 loopback에서만 노출
        app.run(host="127.0.0.1", port=5000, debug=True)
