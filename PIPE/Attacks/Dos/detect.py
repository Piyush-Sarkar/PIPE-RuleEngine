import re
import pandas as pd

log_file = "doslog.txt"

# Regex for Flask access log
log_pattern = re.compile(
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] '
    r'"(?P<method>\w+) (?P<path>[^ ]+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3})'
)

records = []

# Read and parse log file
with open(log_file, "r", encoding="utf-8") as f:
    for line in f:
        match = log_pattern.search(line)
        if match:
            records.append(match.groupdict())

# Convert to DataFrame
df = pd.DataFrame(records)

if df.empty:
    print("No valid log records found.")
    exit()

# Convert timestamp
df["timestamp"] = pd.to_datetime(df["timestamp"], format="%d/%b/%Y %H:%M:%S")

# Create 5-second time buckets
df["time_bucket"] = df["timestamp"].dt.floor("5s")

# Threshold for DoS
DOS_THRESHOLD = 50   # change this if needed

alerts = []

# Group by source IP and 5-second window
grouped = df.groupby(["src_ip", "time_bucket"])

for (src_ip, bucket), group in grouped:
    request_count = len(group)

    if request_count >= DOS_THRESHOLD:
        alerts.append({
            "attack_type": "DOS",
            "src_ip": src_ip,
            "time_bucket": str(bucket),
            "details": f"requests={request_count} in 5 seconds"
        })

# Show results
alerts_df = pd.DataFrame(alerts)

if not alerts_df.empty:
    print(alerts_df.to_string(index=False))
else:
    print("No DoS activity detected.")