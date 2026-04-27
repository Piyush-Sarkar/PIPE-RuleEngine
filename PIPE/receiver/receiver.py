import uvicorn
import threading
import time
import requests
from fastapi import FastAPI, Request
from typing import Optional

app = FastAPI()

_stop_event = threading.Event()
_worker_thread: Optional[threading.Thread] = None
LOG_FORWARD_INTERVAL = 20
SIEM_ENGINE_URL = "http://127.0.0.1:5002/process-logs"

def _forward_logs_loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            with open("LOG_FILE.log", "rb") as f:
                log_content = f.read()
            
            if log_content.strip():
                # Forward entire log file to siem_rule_engine.py
                try:
                    response = requests.post(
                        SIEM_ENGINE_URL,
                        data=log_content,
                        timeout=10,
                    )
                    print(f"📤 Forwarded logs to SIEM engine, Response: {response.status_code}")
                except Exception as e:
                    print(f"⚠️ Error forwarding to SIEM: {e}")
        except Exception as e:
            print(f"⚠️ Error reading logs: {e}")

        stop_event.wait(LOG_FORWARD_INTERVAL)

@app.on_event("startup")
def _start_forward_thread() -> None:
    global _worker_thread

    if _worker_thread is not None and _worker_thread.is_alive():
        return

    _stop_event.clear()
    _worker_thread = threading.Thread(
        target=_forward_logs_loop,
        args=(_stop_event,),
        daemon=True,
        name="log-forwarder",
    )
    _worker_thread.start()
    print("🚀 Log forwarder background task started.")

@app.on_event("shutdown")
def _stop_forward_thread() -> None:
    _stop_event.set()
    if _worker_thread is not None and _worker_thread.is_alive():
        _worker_thread.join(timeout=5)
    print("🛑 Log forwarder background task stopped.")

@app.post('/receive-logs')
async def receive_logs(request: Request):
    body = await request.body()
    logs = body.decode("utf-8")
    with open("LOG_FILE.log", "a") as f:
        f.write(logs)
    print(f"✅ Received {len(logs.splitlines())} new log lines.")
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5001)
