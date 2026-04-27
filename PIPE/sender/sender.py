import os
import threading
import time
from typing import Optional

import requests
import uvicorn
from fastapi import FastAPI

LOG_FILE = r"LOG_FILE.log"  # same file written by app.py
SIEM_URL = "http://127.0.0.1:5002/process-logs"  # SIEM rule engine endpoint
POLL_INTERVAL_SECONDS = 20

app = FastAPI()

_stop_event = threading.Event()
_worker_thread: Optional[threading.Thread] = None


def _send_logs_loop(stop_event: threading.Event) -> None:
    """Send only NEW logs from LOG_FILE.log to SIEM every 20 seconds"""
    last_position = 0
    
    while not stop_event.is_set():
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "rb") as f:
                    f.seek(last_position)  # jump to last read position
                    new_logs = f.read()
                    last_position = f.tell()  # remember current position

                if new_logs.strip():
                    response = requests.post(
                        SIEM_URL,
                        data=new_logs,
                        timeout=10,
                    )
                    print(
                        f"📤 Sent new logs to SIEM ({len(new_logs.splitlines())} lines), Response: {response.status_code}"
                    )
        except Exception as e:
            print(f"⚠️ Error: {e}")

        stop_event.wait(POLL_INTERVAL_SECONDS)


@app.on_event("startup")
def _start_sender_thread() -> None:
    global _worker_thread

    if _worker_thread is not None and _worker_thread.is_alive():
        return

    _stop_event.clear()
    _worker_thread = threading.Thread(
        target=_send_logs_loop,
        args=(_stop_event,),
        daemon=True,
        name="log-sender",
    )
    _worker_thread.start()
    print("🚀 Log sender background task started.")


@app.on_event("shutdown")
def _stop_sender_thread() -> None:
    _stop_event.set()
    if _worker_thread is not None and _worker_thread.is_alive():
        _worker_thread.join(timeout=5)
    print("🛑 Log sender background task stopped.")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5000)
