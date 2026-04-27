import re
import pandas as pd
from urllib.parse import unquote
import threading
import time
from typing import Optional
from fastapi import FastAPI, Request
import uvicorn

app = FastAPI()

_stop_event = threading.Event()
_worker_thread: Optional[threading.Thread] = None
PROCESS_INTERVAL = 20
_last_process_position = 0  # Track last position for incremental processing

# ==============================
# FULL DECODE
# ==============================
def fully_decode(url):
    prev = ""
    url = str(url)
    while prev != url:
        prev = url
        url = unquote(url)
    return url


# ==============================
# PARSE LOGS
# ==============================
def parse_log_line(line):
    pattern = r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\]\s+"?(GET|POST)\s+(.*?)\s+HTTP.*?"?\s+(\d{3})'
    match = re.search(pattern, line)

    if match:
        raw_time = match.group(2)
        raw_time = re.sub(r"\s[+-]\d{4}", "", raw_time)

        if " " in raw_time:
            parts = raw_time.split(" ")
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else ""
        else:
            date_part, time_part = raw_time.split(":", 1)

        return {
            "IP": match.group(1),
            "Date": date_part,
            "Time": time_part,
            "Method": match.group(3),
            "URL": match.group(4),
            "Status Code": match.group(5)
        }
    return None


def txt_to_excel(input_file, output_excel):
    logs = []
    encodings = ['cp1252', 'utf-16', 'utf-8']
    file_opened = False
    for enc in encodings:
        try:
            with open(input_file, "r", encoding=enc) as file:
                for line in file:
                    parsed = parse_log_line(line)
                    if parsed:
                        logs.append(parsed)
            file_opened = True
            break
        except UnicodeDecodeError:
            continue
    if not file_opened:
        # Last resort with errors='replace'
        with open(input_file, "r", encoding='utf-8', errors='replace') as file:
            for line in file:
                parsed = parse_log_line(line)
                if parsed:
                    logs.append(parsed)

    df = pd.DataFrame(logs)

    if df.empty:
        print("⚠️ No valid logs found!")
    else:
        # Sort by timestamp in ascending order
        df["Timestamp"] = pd.to_datetime(
            df["Date"].astype(str) + " " + df["Time"].astype(str),
            format="%d/%b/%Y %H:%M:%S",
            errors="coerce"
        )
        df = df.sort_values(by="Timestamp", ascending=True)
        df = df.drop("Timestamp", axis=1)  # Drop temp column before saving
        
        df.to_excel(output_excel, index=False)
        print(f"✅ Logs converted → {output_excel}")


# ==============================
# ATTACK DETECTION
# ==============================

def detect_sqli(url):
    url = fully_decode(url).lower()

    patterns = [
        r"(\bor\b|\band\b)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
        r"['\"]\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"union\s+select",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"information_schema",
        r"--",
        r"or\s*1\s*=\s*1",
    ]

    return any(re.search(p, url) for p in patterns)


def detect_xss_advanced(url):
    raw = fully_decode(url).lower()
    attacks = []
    flag = True

    if flag:

        # Session hijacking (storage-based)
        if re.search(r"(localstorage|sessionstorage|json\s*\.\s*stringify)", raw):
            attacks.append("Session Hijacking")
            flag = False
        
        # 🍪 Cookie stealing (separate detection)
        elif re.search(r"document\s*\.\s*cookie", raw):
            attacks.append("Cookie Stealing")
            flag = False

        # Keylogging
        elif re.search(r"(onkey(down|press|up)|addEventListener\s*\(\s*['\"]key)", raw):
            attacks.append("Keylogging")
            flag = False

        # Data exfiltration
        elif re.search(r"(fetch\s*\()", raw):
            attacks.append("Data Exfiltration")
            flag = False

        # Credential harvesting
        elif re.search(r"type\s*=\s*['\"]?\s*password", raw):
            attacks.append("Credential Harvesting")
            flag = False

    if flag:
        if re.search(r"(window\s*\.\s*location|location\s*\.\s*href)", raw):
            attacks.append("XSS")

        elif re.search(r"<script[^>]*>\s*alert\s*\(", raw):
            attacks.append("XSS")

        elif "<script" in raw:
            attacks.append("XSS")

    return attacks if attacks else None


def detect_lfi(url):
    url = fully_decode(url).lower()
    return bool(re.search(r"(/etc/passwd|/etc/shadow|php://filter|proc/self)", url))


def detect_rfi(url):
    url = fully_decode(url).lower()

    # RFI only when external URL is used as parameter value
    return bool(re.search(
        r"(file|page|include|path|template)\s*=\s*https?://",
        url
    ))


def detect_traversal(url):
    url = fully_decode(url).lower()
    return bool(re.search(r"(\.\./|\.\.\\|%2e%2e%2f)", url))


def detect_attack(url):
    attacks = []

    if detect_sqli(url):
        attacks.append("SQL Injection")

    xss = detect_xss_advanced(url)
    if xss:
        attacks.extend(xss)

    if detect_lfi(url):
        attacks.append("LFI")

    if detect_rfi(url):
        attacks.append("RFI")

    if detect_traversal(url):
        attacks.append("Directory Traversal")

    return attacks if attacks else None


# ==============================
# BEHAVIOR DETECTION
# ==============================

def detect_dos_time_based(df, window_seconds=5, threshold=20):
    dos_ips = set()

    for ip, group in df.groupby("IP"):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_end = times.iloc[i] + pd.Timedelta(seconds=window_seconds)
            count = ((times >= times.iloc[i]) & (times <= window_end)).sum()

            if count >= threshold:
                dos_ips.add(ip)
                break

    return dos_ips


def detect_bruteforce_time_based(df, window_seconds=10, threshold=5):
    bf_ips = set()

    login_attempts = df[
        (df["URL"].str.contains("login", case=False, na=False)) &
        (df["Status Code"].astype(str) == "401")
    ]

    for ip, group in login_attempts.groupby("IP"):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_end = times.iloc[i] + pd.Timedelta(seconds=window_seconds)
            count = ((times >= times.iloc[i]) & (times <= window_end)).sum()

            if count >= threshold:
                bf_ips.add(ip)
                break

    return bf_ips


# ==============================
# MAIN ANALYSIS
# ==============================

def analyze_excel(input_excel, output_excel):

    df = pd.read_excel(input_excel)

    df["Timestamp"] = pd.to_datetime(
        df["Date"].astype(str) + " " + df["Time"].astype(str),
        format="%d/%b/%Y %H:%M:%S",
        errors="coerce"
    )

    df = df.sort_values(by=["IP", "Timestamp"])

    # 🔥 MULTI ATTACK DETECTION
    df["Attack"] = df["URL"].apply(detect_attack)

    # Flatten multiple attacks
    df = df.explode("Attack")

    # Behavior detection
    # ------------------------------
    # DoS ROW-LEVEL DETECTION (FIXED)
    # ------------------------------
    df["DoS_Flag"] = False

    for (ip, url), group in df.groupby(["IP", "URL"]):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_end = times.iloc[i] + pd.Timedelta(seconds=2)
            mask = (times >= times.iloc[i]) & (times <= window_end)

            if mask.sum() >= 30:   # stricter threshold
                df.loc[group.index[mask], "DoS_Flag"] = True


    # ------------------------------
    # BRUTE FORCE ROW-LEVEL DETECTION
    # ------------------------------
    df["BF_Flag"] = False

    login_df = df[
        (df["URL"].str.contains("login", case=False, na=False)) &
        (df["Status Code"].astype(str) == "401")
    ]

    for ip, group in login_df.groupby("IP"):
        times = group["Timestamp"].dropna().sort_values()

        for i in range(len(times)):
            window_end = times.iloc[i] + pd.Timedelta(seconds=10)
            mask = (times >= times.iloc[i]) & (times <= window_end)

            if mask.sum() >= 5:
                df.loc[group.index[mask], "BF_Flag"] = True


    # APPLY LABELS
    df.loc[df["DoS_Flag"], "Attack"] = "DoS"
    df.loc[df["BF_Flag"], "Attack"] = "Brute Force"

    # Filter only attack rows
    df = df[df["Attack"].notna()]

    summary_df = (
        df.groupby(["IP", "Attack"])
        .agg(
            Time=("Time", "first"),  # First time the attack occurred
            Attack_Count=("Attack", "count")
        )
        .reset_index()
    )
    summary_df = summary_df.rename(columns={"Attack_Count": "Attack Count"})
    
    # Sort by Time in ascending order (earliest to latest)
    summary_df["Time_Sort"] = pd.to_datetime(
        summary_df["Time"],
        format="%H:%M:%S",
        errors="coerce"
    )
    summary_df = summary_df.sort_values(by="Time_Sort", ascending=True)
    summary_df = summary_df.drop("Time_Sort", axis=1)  # Drop temp column

    summary_df.to_excel(output_excel, index=False)

    print(f"⚠️ Threat summary saved → {output_excel}")


# ==============================
# MAIN DRIVER
# ==============================

def _process_logs_loop(stop_event: threading.Event) -> None:
    """Background thread that processes only NEW logs every 20 seconds"""
    global _last_process_position
    
    while not stop_event.is_set():
        try:
            import os
            if os.path.exists("RECEIVE_LOG.log") and os.path.getsize("RECEIVE_LOG.log") > 0:
                # Read only new logs since last position
                with open("RECEIVE_LOG.log", "rb") as f:
                    f.seek(_last_process_position)
                    new_logs = f.read()
                    _last_process_position = f.tell()
                
                if new_logs.strip():
                    # Convert logs to Excel
                    txt_to_excel("RECEIVE_LOG.log", "raw_logs.xlsx")
                    
                    # Analyze and generate threat report
                    analyze_excel("raw_logs.xlsx", "threat_logs.xlsx")
                    
                    print(f"⏰ [SIEM] Processed {len(new_logs.splitlines())} new logs at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            print(f"⚠️ Error processing logs: {e}")

        stop_event.wait(PROCESS_INTERVAL)

@app.on_event("startup")
def _start_process_thread() -> None:
    global _worker_thread

    if _worker_thread is not None and _worker_thread.is_alive():
        return

    _stop_event.clear()
    _worker_thread = threading.Thread(
        target=_process_logs_loop,
        args=(_stop_event,),
        daemon=True,
        name="log-processor",
    )
    _worker_thread.start()
    print("🚀 Log processor background task started.")

@app.on_event("shutdown")
def _stop_process_thread() -> None:
    _stop_event.set()
    if _worker_thread is not None and _worker_thread.is_alive():
        _worker_thread.join(timeout=5)
    print("🛑 Log processor background task stopped.")

@app.post('/process-logs')
async def process_logs(request: Request):
    body = await request.body()
    logs = body.decode("utf-8")
    with open("RECEIVE_LOG.log", "a") as f:
        f.write(logs)
    print(f"✅ SIEM received {len(logs.splitlines())} new log lines.")
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5002)