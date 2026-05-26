#!/usr/bin/env python3
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path


CONFIG_PATH = Path("/etc/netspecter/config.json")
DB_PATH = Path("/var/lib/netspecter/netspecter.db")
SLOTS = {
    1: [12],
    2: [8, 18],
    3: [7, 13, 19],
    4: [7, 11, 15, 19],
    5: [6, 10, 14, 18, 22],
}


def scheduled_runs():
    try:
        config = json.loads(CONFIG_PATH.read_text())
        return min(5, max(0, int(config.get("scheduled_speedtests_per_day", 0) or 0)))
    except Exception:
        return 0


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=30000")
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS speed_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source TEXT NOT NULL,
            latency_ms REAL,
            download_mbps REAL,
            upload_mbps REAL,
            result_text TEXT,
            success INTEGER DEFAULT 0
        )
        """
    )
    con.commit()
    return con


def parse_value(pattern, output):
    match = re.search(pattern, output or "", re.IGNORECASE)
    return float(match.group(1)) if match else None


def run_test():
    env = os.environ.copy()
    env.setdefault("HOME", "/root")
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("LC_ALL", "C.UTF-8")
    success = False
    try:
        result = subprocess.run(
            ["/usr/bin/speedtest", "--accept-license", "--accept-gdpr"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
            env=env,
        )
        output = (result.stdout or "").strip() or "Speed test returned no output."
        success = result.returncode == 0
        if not success:
            output = f"Speed test failed (exit {result.returncode}).\n{output}"
    except Exception as error:
        output = f"Scheduled speed test could not run: {error}"
    return (
        output,
        parse_value(r"Latency:\s*([0-9.]+)\s*ms", output),
        parse_value(r"Download:\s*([0-9.]+)\s*Mbps", output),
        parse_value(r"Upload:\s*([0-9.]+)\s*Mbps", output),
        success,
    )


def main():
    runs = scheduled_runs()
    if runs == 0:
        return
    now = datetime.now()
    due = sum(1 for hour in SLOTS[runs] if now.hour >= hour)
    if due == 0:
        return
    con = connect_db()
    completed = con.execute(
        "SELECT COUNT(*) FROM speed_tests WHERE source='scheduled' AND substr(ts, 1, 10)=?",
        (now.strftime("%Y-%m-%d"),),
    ).fetchone()[0]
    if completed >= due:
        con.close()
        return
    output, latency, download, upload, success = run_test()
    con.execute(
        """
        INSERT INTO speed_tests (ts, source, latency_ms, download_mbps, upload_mbps, result_text, success)
        VALUES (?, 'scheduled', ?, ?, ?, ?, ?)
        """,
        (now.strftime("%Y-%m-%d %H:%M:%S"), latency, download, upload, output, 1 if success else 0),
    )
    con.commit()
    con.close()


if __name__ == "__main__":
    main()
