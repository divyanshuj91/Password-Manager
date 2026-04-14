"""
server.py — Web launcher for the Smart Password Manager.

Starts the FastAPI server with uvicorn and auto-opens the browser.
Run:  python server.py
"""

import threading
import webbrowser

import uvicorn


HOST = "127.0.0.1"
PORT = 8000
URL  = f"http://{HOST}:{PORT}"


def _open_browser():
    """Wait for the server to boot, then open the dashboard."""
    import time
    time.sleep(1.5)
    webbrowser.open(URL)


def main():
    print()
    print("  +----------------------------------------------------+")
    print("  |   Smart Password Manager - Web Edition              |")
    print("  +----------------------------------------------------+")
    print(f"  |   Dashboard :  {URL:<35} |")
    print(f"  |   API Docs  :  {URL + '/docs':<35} |")
    print("  +----------------------------------------------------+")
    print()

    threading.Thread(target=_open_browser, daemon=True).start()

    uvicorn.run(
        "api:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
