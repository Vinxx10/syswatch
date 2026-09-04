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


if __name__ == "__main__":
    # First call to cpu_percent always returns 0.0, so prime it
    prime_cpu()
    snapshot = collect_snapshot()
    print_snapshot(snapshot)


def collect_baseline(num_snapshots=3, interval=2):
    """Collect multiple snapshots to build a baseline dataset."""
    ensure_data_dir()
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
