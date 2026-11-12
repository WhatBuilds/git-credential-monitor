#!/usr/bin/env python3
"""Install a persistent per-user background schedule. Run without sudo/Administrator."""
import argparse
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import sys
from monitor import reminder_minutes

LABEL = "com.whatbytes.github-credential-monitor"


def command(args, required=True):
    r = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if required and r.returncode:
        raise RuntimeError("scheduler command failed")


def unit_quote(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def install(config):
    script = Path(__file__).resolve().with_name("monitor.py")
    config = config.expanduser().resolve()
    if not config.is_file() or not script.is_file():
        raise RuntimeError("missing files")
    settings = json.loads(config.read_text())
    if not settings.get("slack_webhook"):
        raise RuntimeError("set slack_webhook in config before scheduling")
    reminder_minutes(settings)
    interval = settings.get("scan_interval_minutes", 1)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 1 <= interval <= 1439:
        raise ValueError("scan_interval_minutes must be an integer between 1 and 1439")
    args = [sys.executable, str(script), "--config", str(config)]
    system = platform.system()
    if system != "Windows" and os.geteuid() == 0:
        raise RuntimeError("run as employee, not root")
    if system == "Darwin":
        folder = Path.home() / "Library/LaunchAgents"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / (LABEL + ".plist")
        content = dict(Label=LABEL, ProgramArguments=args, StartInterval=interval * 60,
                       RunAtLoad=True, ProcessType="Background",
                       LimitLoadToSessionType="Aqua",
                       EnvironmentVariables={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        with path.open("wb") as f:
            plistlib.dump(content, f)
        os.chmod(path, 0o600)
        domain = f"gui/{os.getuid()}"
        command(["launchctl", "bootout", domain, str(path)], required=False)
        command(["launchctl", "enable", f"{domain}/{LABEL}"])
        command(["launchctl", "bootstrap", domain, str(path)])
    elif system == "Linux":
        folder = Path.home() / ".config/systemd/user"
        folder.mkdir(parents=True, exist_ok=True)
        service = ("[Unit]\nDescription=GitHub credential presence monitor\n\n[Service]\n"
                   "Type=oneshot\nExecStart=" + " ".join(unit_quote(x) for x in args) +
                   "\nSuccessExitStatus=1 2\nTimeoutStartSec=120\nUMask=0077\n" +
                   "Environment=" + unit_quote("PATH=" + os.environ.get("PATH", "/usr/bin:/bin")) + "\n")
        bus = f"/run/user/{os.getuid()}/bus"
        if Path(bus).exists():
            service += "Environment=" + unit_quote("DBUS_SESSION_BUS_ADDRESS=unix:path=" + bus) + "\n"
        (folder / (LABEL + ".service")).write_text(service)
        (folder / (LABEL + ".timer")).write_text(
            "[Unit]\nDescription=Scan GitHub credential presence\n\n[Timer]\n"
            f"OnStartupSec=10\nOnUnitActiveSec={interval}min\nAccuracySec=1s\n\n[Install]\nWantedBy=timers.target\n")
        command(["systemctl", "--user", "daemon-reload"])
        command(["systemctl", "--user", "enable", LABEL + ".timer"])
        command(["systemctl", "--user", "restart", LABEL + ".timer"])
    elif system == "Windows":
        # Current logged-on user; never SYSTEM. No webhook in task arguments.
        command(["schtasks", "/Create", "/TN", "WhatBytes GitHub Credential Monitor",
                 "/SC", "MINUTE", "/MO", str(interval), "/IT", "/TR",
                 subprocess.list2cmdline(args), "/F"])
    else:
        raise RuntimeError("unsupported operating system")
    print(f"Installed persistent per-user schedule: scan every {interval} minute(s), "
          f"remind every {reminder_minutes(settings):g} minute(s).")
    print("Starts automatically after restart when you log in. No terminal needs to stay open. Keep this folder in place.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    options = parser.parse_args()
    try:
        install(options.config)
    except Exception:
        print("Schedule installation failed. Check configuration, employee session and scheduler availability.", file=sys.stderr)
        sys.exit(1)
