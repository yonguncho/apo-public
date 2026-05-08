import sys
import webbrowser
import threading
from app.server import create_app

app = create_app()

if __name__ == "__main__":
    frozen = getattr(sys, 'frozen', False)

    if frozen:
        def _open_browser():
            import time
            time.sleep(1.2)
            webbrowser.open("http://127.0.0.1:5000")
        threading.Thread(target=_open_browser, daemon=True).start()
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    else:
        app.run(host="127.0.0.1", port=5000, debug=True)
