#!/usr/bin/env python3

"""syswatch - Process Anomaly Detector for Linux"""

import argparse
import os
import sys
import time
import joblib
import pandas as pd
import psutil
from sklearn.ensemble import IsolationForest
from ollama import chat as ollama_chat

DATA_DIR = os.path.expanduser("~/.syswatch")
MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
BASELINE_PATH = os.path.join(DATA_DIR, "baseline.csv")

FEATURES_COLS = [
    "cpu_percent",
    "memory_mb",
    "memory_percent",
    "num_threads",
    "num_connections",
]


def ensure_datadir():
    os.makedirs(DATA_DIR, exist_ok=True)


def collect_snapshot():
    rows = []

    for proc in psutil.process_iter(
        attrs=["pid", "name", "cpu_percent", "memory_percent", "num_threads"]
    ):
        try:
            info = proc.info

            try:
                num_connections = len(proc.net_connections(kind="inet"))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                num_connections = 0

            try:
                rss_mb = proc.memory_info().rss / (1024 * 1024)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                rss_mb = 0.0

            rows.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu_percent": info["cpu_percent"] or 0.0,
                    "memory_mb": round(rss_mb, 2),
                    "memory_percent": info["memory_percent"] or 0.0,
                    "num_threads": info["num_threads"] or 0,
                    "num_connections": num_connections,
                }
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return pd.DataFrame(rows)


def print_snapshot(df):
    """Print a process snapshot as a formatted table."""
    # Print column headers
    print(
        f"\n{'PID':<8} {'Name':<20} {'CPU%':<8} {'Mem MB':<10} "
        f"{'Threads':<9} {'Conns'}"
    )
    print("-" * 63)
    # Print up to 20 rows of process data
    for _, row in df.head(20).iterrows():
        print(
            f"{row['pid']:<8} {str(row['name'])[:19]:<20} "
            f"{row['cpu_percent']:<8.1f} {row['memory_mb']:<10.1f} "
            f"{row['num_threads']:<9} {row['num_connections']}"
        )
    if len(df) > 20:
        print(f"... and {len(df) - 20} more processes")
    print(f"\nTotal: {len(df)} processes")


def prime_cpu():
    """Prime CPU percentages so the next reading is accurate."""
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(1)


def collect_baseline(num_snapshots=3, interval=2):
    """Collect multiple snapshots to build a baseline dataset."""
    ensure_datadir()
    print(f"Collecting {num_snapshots} snapshots ({interval}s apart)...")
    print("This teaches the model what 'normal' looks like on your machine.\n")

    prime_cpu()

    all_data = []
    for i in range(num_snapshots):
        print(f"  Snapshot {i + 1}/{num_snapshots}...")
        snapshot = collect_snapshot()
        all_data.append(snapshot)
        if i < num_snapshots - 1:
            time.sleep(interval)

    baseline = pd.concat(all_data, ignore_index=True)
    baseline.to_csv(BASELINE_PATH, index=False)
    print(f"\nBaseline saved: {len(baseline)} process samples")
    print(f"Location: {BASELINE_PATH}")


def train_model(contamination=0.05):
    """Train an Isolation Forest on the baseline data."""
    if not os.path.exists(BASELINE_PATH):
        print("No baseline data found. Run: python3 syswatch.py baseline")
        sys.exit(1)

    baseline = pd.read_csv(BASELINE_PATH)
    X = baseline[FEATURES_COLS].fillna(0)

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)

    ensure_datadir()
    joblib.dump(model, MODEL_PATH)
    print(f"Model trained on {len(X)} samples (contamination={contamination})")
    print(f"Saved to {MODEL_PATH}")


def scan():
    """Scan current processes and flag anomalies."""
    if not os.path.exists(MODEL_PATH):
        print("No trained model found. Run:")
        print("  python3 syswatch.py baseline")
        print("  python3 syswatch.py train")
        sys.exit(1)

    model = joblib.load(MODEL_PATH)

    prime_cpu()

    snapshot = collect_snapshot()
    X = snapshot[FEATURES_COLS].fillna(0)

    predictions = model.predict(X)
    scores = model.score_samples(X)

    snapshot["anomaly"] = predictions
    snapshot["score"] = scores.round(4)

    anomalies = snapshot[snapshot["anomaly"] == -1].sort_values("score")
    normal_count = len(snapshot[snapshot["anomaly"] == 1])
    print(f"\nScanned {len(snapshot)} processes")
    print(f"Normal: {normal_count}  |  Anomalies: {len(anomalies)}\n")

    if len(anomalies) > 0:
        print("ANOMALIES DETECTED:")
        print("-" * 72)
        print(
            f"{'PID':<8} {'Name':<20} {'CPU%':<8} {'Mem MB':<10} "
            f"{'Threads':<9} {'Score'}"
        )
        print("-" * 72)
        for _, row in anomalies.iterrows():
            print(
                f"{row['pid']:<8} {str(row['name'])[:19]:<20} "
                f"{row['cpu_percent']:<8.1f} {row['memory_mb']:<10.1f} "
                f"{row['num_threads']:<9} {row['score']:.4f}"
            )
    else:
        print("No anomalies detected. Everything looks normal.")


def analyze():
    """Run AI-powered system analysis using a local model."""
    print("Collecting system data...\n")
    system_info = collect_system_info()

    prompt = f"""You are a linux system security and performance expert.
Analyze the following system data and provide a report covering:

1. SECURITY THREATS: Suspicious processes, unusual network
   connections, open ports that should not be exposed, and
   any signs of malware or unauthorized access.
2. WHY THE COMPUTER IS SLOW: Which processes are consuming
   the most CPU and memory, and whether that usage is normal.
3. DISK SPACE: What is consuming storage and what can be
   safely cleaned up.
4. RECOMMENDATIONS: Specific commands the user can run to
   fix each issue, improve performance, and harden security.

Be specific. Name exact processes, ports, and paths.
Give exact terminal commands for every recommendation.

SYSTEM DATA:
{system_info}
"""

    print("Analyzing with local AI (this may take a moment)...\n")
    print("=" * 60)
    print("AI SYSTEM ANALYSIS REPORT")
    print("=" * 60)

    # Stream the AI response for real-time output
    stream = ollama_chat(
        model="llama3.2:latest",
        messages=[{"role": "user", "content": prompt}],
        stream=True,
    )
    for chunk in stream:
        print(chunk["message"]["content"], end="", flush=True)

    print("\n" + "=" * 60)


def collect_system_info():
    """Collect comprehensive system information for AI analysis."""
    info = []

    # Disk usage per partition
    info.append("=== DISK USAGE ===")
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            info.append(
                f"  {part.mountpoint}: "
                f"{usage.used / (1024**3):.1f}GB / "
                f"{usage.total / (1024**3):.1f}GB "
                f"({usage.percent}% full)"
            )
        except PermissionError:
            continue
            # Memory breakdown
    mem = psutil.virtual_memory()
    info.append("\n=== MEMORY ===")
    info.append(
        f"  Total: {mem.total / (1024**3):.1f}GB  "
        f"Used: {mem.used / (1024**3):.1f}GB  "
        f"Available: {mem.available / (1024**3):.1f}GB  "
        f"({mem.percent}% used)"
    )

    # Top 10 CPU consumers
    prime_cpu()
    snapshot = collect_snapshot()
    top_cpu = snapshot.nlargest(10, "cpu_percent")
    info.append("\n=== TOP 10 CPU CONSUMERS ===")
    for _, row in top_cpu.iterrows():
        info.append(
            f"  PID {row['pid']} {str(row['name'])[:20]} "
            f"CPU={row['cpu_percent']:.1f}%"
        )


if __name__ == "__main__":
    collect_baseline()
    train_model()
    scan()
