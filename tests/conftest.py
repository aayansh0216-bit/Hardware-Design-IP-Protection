import threading
import time
import urllib.request
import pytest
import uvicorn
from hardware_ip_protection.web.app import app


@pytest.fixture(scope="session", autouse=True)
def ensure_live_server():
    """
    Ensures that a live web server is running on http://127.0.0.1:8000 for
    live endpoint and scenario tests.
    """
    try:
        req = urllib.request.Request("http://127.0.0.1:8000/api/benchmarks")
        with urllib.request.urlopen(req, timeout=1):
            yield
            return
    except Exception:
        pass

    config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    start = time.time()
    while time.time() - start < 5:
        try:
            req = urllib.request.Request("http://127.0.0.1:8000/api/benchmarks")
            with urllib.request.urlopen(req, timeout=1):
                break
        except Exception:
            time.sleep(0.1)

    yield

    server.should_exit = True
