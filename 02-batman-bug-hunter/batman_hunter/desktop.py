"""Desktop/browser launcher for the local Batman Bug Hunter console."""
from __future__ import annotations

import argparse
import threading
import webbrowser

from werkzeug.serving import make_server

from .web import app

HOST = "127.0.0.1"
PORT = 5000
URL = f"http://{HOST}:{PORT}/"


def main() -> int:
    parser = argparse.ArgumentParser(description="BATCOMPUTER — Batman Bug Hunter X")
    parser.add_argument("--browser", action="store_true", help="Open the console in the default browser")
    args = parser.parse_args()

    try:
        server = make_server(HOST, PORT, app, threaded=True)
    except OSError as exc:
        print(f"Could not start Batman Bug Hunter on {HOST}:{PORT}: {exc}")
        print("Close the other application using port 5000, then try again.")
        return 1

    worker = threading.Thread(target=server.serve_forever, name="bug-hunter-web", daemon=True)
    worker.start()

    try:
        if args.browser:
            webbrowser.open(URL)
            print(f"Batman Bug Hunter is running at {URL}")
            worker.join()
            return 0

        try:
            import webview
        except ImportError:
            webbrowser.open(URL)
            print("Desktop webview is unavailable; opened the browser instead.")
            worker.join()
            return 0

        webview.create_window(
            "BATCOMPUTER — Batman Bug Hunter X",
            URL,
            width=1440,
            height=940,
            min_size=(900, 650),
            text_select=True,
        )
        try:
            webview.start()
        except Exception as exc:
            print(f"Native desktop window could not start: {exc}")
            print(f"Opening the local console in your browser: {URL}")
            webbrowser.open(URL)
            worker.join()
        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
