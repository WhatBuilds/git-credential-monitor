#!/usr/bin/env python3
"""Per-user GitHub credential inventory with confirmed macOS cleanup. Python 3.10+.

No credential-helper execution, token validation, or secret reporting.
Use --dry-run first. See README.md for coverage and deployment limits.
"""
import argparse
import ctypes
import datetime as dt
import getpass
import hashlib
import json
import netrc
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit
import urllib.request
from keychain_remediation import Keychain, KeychainError
from api_logging import log_scan, outcome
from report_format import slack_payload

MAX_FILE = 4 * 1024 * 1024
TOKEN = re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_])")
ENV_KEYS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")


def reminder_minutes(config):
    # Preserve the duration of older configs until they are migrated.
    if "reminder_minutes" in config:
        value = config["reminder_minutes"]
    elif "reminder_hours" in config:
        hours = config["reminder_hours"]
        if isinstance(hours, bool) or not isinstance(hours, (int, float)):
            raise ValueError("reminder_hours must be numeric")
        value = hours * 60
    else:
        value = 15
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= value <= 525600:
        raise ValueError("reminder_minutes must be between 1 and 525600")
    return value


def employee_label(config, local_user):
    label = config.get("employee")
    return label.strip() if isinstance(label, str) and label.strip() else local_user


def run(argv, timeout=25, cwd=None):
    # Never use shell=True or print command output/errors; these can contain secrets.
    return subprocess.run(argv, capture_output=True, text=True, errors="replace",
                          timeout=timeout, cwd=cwd, stdin=subprocess.DEVNULL)


def host_match(value, hosts):
    value = str(value).lower()
    return any(re.search(r"(?<![a-z0-9.-])" + re.escape(h) + r"(?![a-z0-9.-])", value)
               for h in hosts)


def url_credential(value, hosts):
    try:
        u = urlsplit(value.strip())
        return (u.scheme in ("http", "https") and u.hostname in hosts
                and (u.password is not None or bool(u.username and TOKEN.search(u.username))))
    except ValueError:
        return False


class Scan:
    def __init__(self, config):
        self.config = config
        self.hosts = {"github.com", *[h.lower() for h in config.get("github_hosts", [])]}
        self.findings = []
        self.checks = []

    def finding(self, source, kind, count=1):
        # Only fixed source labels leave the detector. No raw store metadata/paths.
        if not any(f["source"] == source and f["kind"] == kind for f in self.findings):
            self.findings.append(dict(source=source, kind=kind, count=count))

    def check(self, source, status="checked", reason=None):
        item = dict(source=source, status=status)
        if reason:
            item["reason"] = reason  # Caller supplies fixed text only.
        if item not in self.checks:
            self.checks.append(item)

    def read(self, path, source):
        try:
            if path.stat().st_size > MAX_FILE:
                self.check(source, "incomplete", "file exceeds 4 MiB inspection limit")
                return None
            with path.open("rb") as f:
                data = f.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                self.check(source, "incomplete", "file exceeds inspection limit")
                return None
            return data.decode("utf-8", errors="replace")
        except FileNotFoundError:
            self.check(source, "absent")
        except (OSError, ValueError):
            self.check(source, "incomplete", "file unreadable")
        return None

    def file(self, path, source, mode="generic"):
        text = self.read(Path(path).expanduser(), source)
        if text is None:
            return
        matches = 0
        if mode == "git-store":
            matches = sum(url_credential(line, self.hosts) for line in text.splitlines())
        elif mode == "gh":
            # Conservative presence test, not a YAML loader. Covers current GH CLI
            # hosts.yml including nested users. Never evaluates YAML tags.
            for line in text.splitlines():
                m = re.match(r"\s*oauth_token\s*:\s*(.*?)\s*$", line)
                if m and m[1].strip("\"'").lower() not in ("", "null", "~", "{}"):
                    matches += 1
        else:
            matches = len(TOKEN.findall(text))
        if matches:
            self.finding(source, "plaintext credential present", matches)
        self.check(source)

    def netrc_file(self, path, source):
        text = self.read(path, source)
        if text is None:
            return
        try:
            parsed = netrc.netrc(str(path))
            matches = sum(bool(password) and (host.lower() in self.hosts or host == "default")
                          for host, (_, _, password) in parsed.hosts.items())
            if matches:
                self.finding(source, "netrc credential for GitHub or default host present", matches)
            self.check(source)
        except Exception:
            self.check(source, "incomplete", "netrc file could not be parsed")

    def git_config(self, repo=None, index=None):
        source = "Git user/system configuration" if repo is None else f"Repository {index} configuration"
        if not shutil.which("git"):
            self.check(source, "incomplete", "git not installed or not on scheduler PATH")
            return
        args = ["git"]
        if repo:
            args += ["-C", str(Path(repo).expanduser().resolve())]
        # --file avoids inheriting the caller's current repository by accident.
        # Query system/global separately below, including Git's include processing.
        scopes = ["--system", "--global"] if repo is None else ["--local"]
        for scope in scopes:
            try:
                r = run(args + ["config", scope, "--includes", "--null", "--get-regexp",
                                r"^(credential\..*|remote\..*\.(url|pushurl)|url\..*\.(insteadof|pushinsteadof)|http\..*extraheader|http\.extraheader)$"])
                if r.returncode not in (0, 1):
                    self.check(source, "incomplete", "Git configuration query failed")
                    continue
                for record in r.stdout.split("\0"):
                    if "\n" not in record:
                        continue
                    key, value = record.split("\n", 1)
                    if TOKEN.search(value) or TOKEN.search(key) or url_credential(value, self.hosts):
                        self.finding(source, "credential embedded in Git configuration")
                    if "extraheader" in key and re.search(r"(?i)authorization\s*:", value):
                        self.finding(source, "authorization header configured (review host scope)")
                    if key.endswith(".helper"):
                        self.helper(value, source, repo)
                    if key.endswith(".credentialstore") and value.strip().lower() in ("gpg", "dpapi", "cache"):
                        self.check(source, "incomplete", "configured additional credential store is not inspected")
                self.check(source)
            except (OSError, subprocess.SubprocessError):
                self.check(source, "incomplete", "Git configuration query unavailable")

    def helper(self, value, source, repo):
        value = value.strip()
        if not value:
            return
        # Never execute a configured helper: it may be an arbitrary shell command.
        try:
            parts = shlex.split(value, posix=True)
        except ValueError:
            self.check(source, "incomplete", "credential helper could not be interpreted")
            return
        name = parts[0] if parts else ""
        # Recognize the CLI's standard helper without executing it or assuming
        # that its presence proves a stored token exists.
        helper_name = name.lstrip("!").replace("\\", "/").rsplit("/", 1)[-1]
        if helper_name in ("gh", "gh.exe") and parts[1:] == ["auth", "git-credential"]:
            self.check(source, "incomplete", "GitHub CLI credential helper is configured; not executed")
            return
        if name in ("store", "git-credential-store"):
            path = None
            for i, p in enumerate(parts[1:], 1):
                if p.startswith("--file="):
                    path = p[7:]
                elif p == "--file" and i + 1 < len(parts):
                    path = parts[i + 1]
            if path:
                p = Path(path).expanduser()
                if not p.is_absolute():
                    if repo:
                        p = Path(repo).expanduser() / p
                    else:
                        self.check(source, "incomplete", "relative credential-store path requires repository context")
                        return
                self.file(p, source + " custom credential-store file", "git-store")
        elif name in ("osxkeychain", "wincred", "manager", "manager-core", "libsecret"):
            pass
        elif name in ("cache", "git-credential-cache"):
            self.check(source, "incomplete", "Git in-memory credential cache is not inspected")
        else:
            self.check(source, "incomplete", "custom credential helper is configured; not executed")

    def mac(self):
        source = "macOS Keychain search list (metadata)"
        try:
            # Explicitly NO -d, -g or -w: never request secret data.
            r = run(["/usr/bin/security", "dump-keychain"], timeout=40)
            if r.returncode:
                self.check(source, "incomplete", "keychain metadata query failed")
                return
            matches = 0
            for record in re.split(r"(?m)^keychain:", r.stdout):
                if not re.search(r'class: "(?:genp|inet)"', record):
                    continue
                attrs = re.findall(r'^\s*"(?:svce|srvr|labl|desc)"[^=]*=(.*)$', record, re.M)
                if any(host_match(a, self.hosts) or "github" in a.lower() for a in attrs):
                    matches += 1
            if matches:
                self.finding(source, "GitHub-related credential entry present", matches)
            self.check(source)
        except (OSError, subprocess.SubprocessError):
            self.check(source, "incomplete", "keychain metadata query unavailable or timed out")

    def windows(self):
        source = "Windows Credential Manager (target metadata)"
        try:
            from ctypes import wintypes as w
            class Credential(ctypes.Structure):
                _fields_ = [("Flags", w.DWORD), ("Type", w.DWORD), ("TargetName", w.LPWSTR),
                            ("Comment", w.LPWSTR), ("LastWritten", w.FILETIME),
                            ("CredentialBlobSize", w.DWORD), ("CredentialBlob", ctypes.c_void_p),
                            ("Persist", w.DWORD), ("AttributeCount", w.DWORD),
                            ("Attributes", ctypes.c_void_p), ("TargetAlias", w.LPWSTR),
                            ("UserName", w.LPWSTR)]
            adv = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
            ptr = ctypes.POINTER(Credential)
            entries = ctypes.POINTER(ptr)()
            count = w.DWORD()
            enum = adv.CredEnumerateW
            enum.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.POINTER(ctypes.POINTER(ptr))]
            enum.restype = w.BOOL
            adv.CredFree.argtypes = [ctypes.c_void_p]
            adv.CredFree.restype = None
            if not enum(None, 0, ctypes.byref(count), ctypes.byref(entries)):
                if ctypes.get_last_error() == 1168:  # ERROR_NOT_FOUND
                    self.check(source)
                else:
                    self.check(source, "incomplete", "credential metadata enumeration denied/unavailable")
                return
            try:
                matches = 0
                for i in range(count.value):
                    # CredEnumerate allocates credential structures including blobs;
                    # never access/dereference CredentialBlob, UserName or Comment.
                    target = entries[i].contents.TargetName or ""
                    if host_match(target, self.hosts) or "github" in target.lower():
                        matches += 1
                if matches:
                    self.finding(source, "GitHub-related credential entry present", matches)
                self.check(source)
            finally:
                adv.CredFree(entries)
        except Exception:
            self.check(source, "incomplete", "credential metadata enumeration failed")

    def linux(self):
        source = "Linux Secret Service (metadata)"
        try:
            # Bounded subprocess: D-Bus may stall. The worker only emits counts/status.
            r = run([sys.executable, str(Path(__file__).resolve()), "--linux-worker",
                     json.dumps(sorted(self.hosts))], timeout=35)
            result = json.loads(r.stdout) if r.returncode == 0 else {}
            if result.get("count"):
                self.finding(source, "GitHub-related credential entry present", result["count"])
            if result.get("status") == "checked":
                self.check(source)
            else:
                self.check(source, "incomplete", "Secret Service unavailable, locked, or optional dependency missing")
        except (ValueError, OSError, subprocess.SubprocessError):
            self.check(source, "incomplete", "Secret Service query failed or timed out")

    def scan(self):
        home = Path.home()
        xdg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
        self.file(home / ".git-credentials", "Default Git credential file", "git-store")
        self.file(xdg / "git/credentials", "XDG Git credential file", "git-store")
        self.netrc_file(home / ".netrc", "User .netrc file")
        self.netrc_file(home / "_netrc", "User _netrc file")
        gh_dirs = {home / ".config/gh", xdg / "gh"}
        if os.environ.get("APPDATA"):
            gh_dirs.add(Path(os.environ["APPDATA"]) / "GitHub CLI")
            gh_dirs.add(Path(os.environ["APPDATA"]) / "gh")
        if os.environ.get("GH_CONFIG_DIR"):
            gh_dirs.add(Path(os.environ["GH_CONFIG_DIR"]))
        for i, directory in enumerate(sorted(gh_dirs, key=str), 1):
            self.file(directory / "hosts.yml", f"GitHub CLI hosts file {i}", "gh")
        self.git_config()
        for i, repo in enumerate(self.config.get("repositories", []), 1):
            self.git_config(repo, i)
        for i, path in enumerate(self.config.get("extra_files", []), 1):
            self.file(path, f"Additional configured file {i}")
        for key in ENV_KEYS:
            if os.environ.get(key):
                self.finding("Scanner process environment", key + " is set (persistence not established)")
        self.check("Scanner process environment")
        if os.environ.get("GCM_CREDENTIAL_STORE", "").lower() in ("gpg", "dpapi", "cache"):
            self.check("GCM environment-selected store", "incomplete", "additional credential store is not inspected")
        system = platform.system()
        if system == "Darwin":
            self.mac()
        elif system == "Windows":
            self.windows()
        elif system == "Linux":
            self.linux()
        else:
            self.check("OS credential store", "incomplete", "unsupported operating system")
        local_user = getpass.getuser()
        return dict(timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),
                    employee=employee_label(self.config, local_user), device=socket.gethostname(),
                    local_user=local_user, os=system,
                    findings=self.findings, checks=self.checks,
                    coverage="incomplete" if any(c["status"] == "incomplete" for c in self.checks)
                    else "configured checks completed")


def linux_worker(hosts):
    count, complete = 0, True
    try:
        import secretstorage
        connection = secretstorage.dbus_init()
        try:
            collections = list(secretstorage.get_all_collections(connection))
            if not collections:
                complete = False
            for collection in collections:
                try:
                    if collection.is_locked():
                        complete = False
                    for item in collection.get_all_items():
                        attrs = item.get_attributes()
                        # Account/username alone is not evidence of GitHub storage.
                        values = [v for k, v in attrs.items() if k.lower() not in ("account", "username", "user")]
                        values.append(item.get_label())
                        if any(host_match(v, hosts) or "github" in str(v).lower() for v in values):
                            count += 1
                except Exception:
                    complete = False
        finally:
            connection.close()
    except Exception:
        complete = False
    print(json.dumps(dict(count=count, status="checked" if complete else "incomplete")))




class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def notify(webhook, payload):
    u = urlsplit(webhook)
    if (u.scheme != "https" or u.hostname not in ("hooks.slack.com", "hooks.slack-gov.com")
            or u.username or u.password or u.port not in (None, 443)
            or not u.path.startswith("/services/")):
        raise ValueError("invalid Slack webhook")
    body = json.dumps(payload).encode()
    req = urllib.request.Request(webhook, data=body, headers={"Content-Type": "application/json"})
    # No redirects, response/error bodies, request debugging, or URL logging.
    with urllib.request.build_opener(NoRedirect()).open(req, timeout=15) as response:
        if response.status != 200 or response.read(64).strip() != b"ok":
            raise RuntimeError("Slack did not acknowledge notification")


def local_dialog(message, action="OK"):
    # All metadata is passed as argv, never executable AppleScript source.
    script = '''on run argv
        activate
        set answer to display dialog (item 1 of argv) with title "GitHub credential monitor" buttons {"Later", item 2 of argv} default button "Later" with icon caution giving up after 45
        if gave up of answer then return "dismissed"
        if button returned of answer is (item 2 of argv) then return "confirmed"
        return "dismissed"
    end run'''
    result = run(["/usr/bin/osascript", "-e", script, message, action], timeout=50)
    if result.returncode:
        raise RuntimeError("local alert unavailable")
    return result.stdout.strip() == "confirmed"


def local_notify(_webhook, report, hosts=None):
    """Offer deletion only for the exact Keychain items shown and confirmed."""
    if not report["findings"]:
        return
    hosts = hosts or {"github.com"}
    keychain = Keychain()
    candidates = [item for item in keychain.items() if any(
        host_match(item[field], hosts) or "github" in item[field].lower()
        for field in ("service", "server", "label", "description"))]
    if not candidates:
        local_dialog("No removable GitHub-related Keychain entries were found. "
                     "Other detected credentials need review in their original file, environment, "
                     "or application. For GitHub CLI authentication, use gh auth logout.")
        return
    # Keep the entire confirmation readable; unlisted items are never deleted.
    selected = candidates[:10]
    def display(value):
        return "".join(c if c.isprintable() else " " for c in value)[:160] or "(not specified)"
    lines = [f"{i}. {display(item['service'] or item['server'] or item['label'])}"
             f"\n   Account: {display(item['account'])}"
             for i, item in enumerate(selected, 1)]
    message = ("Delete these GitHub-related Keychain entries?\n\n" + "\n".join(lines) +
               "\n\nThis removes the listed saved credentials and may sign you out of GitHub apps. "
               "It does not revoke tokens on GitHub or remove credentials from files/environment variables.")
    if len(candidates) > len(selected):
        message += f"\n{len(candidates) - len(selected)} additional entries are not included in this deletion."
    if not local_dialog(message, "Delete listed entries"):
        return
    failures = []
    for index, item in enumerate(selected, 1):
        try:
            keychain.delete(item)
        except KeychainError as error:
            failures.append(f"Entry {index}: macOS status {error.status}")
        except Exception:
            failures.append(f"Entry {index}: unexpected local deletion error")
    if failures:
        print("Keychain cleanup: " + "; ".join(failures), file=sys.stderr)
    # Verify removal using exact references, never by broad account/service matches.
    remaining = {item['reference'] for item in keychain.items()}
    removed = sum(item['reference'] not in remaining for item in selected)
    local_dialog(f"{removed} of {len(selected)} listed entries are no longer in Keychain.\n"
                 f"{len(selected) - removed} remain. The monitor will rescan now."
                 + ("\n\n" + "\n".join(failures) if failures else ""))
    if failures or removed != len(selected):
        raise RuntimeError("Some Keychain entries could not be removed")


def deliver(report, config, state_path, webhook, force=False, sender=None):
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}
    content = dict(findings=sorted(report["findings"], key=lambda f: (f["source"], f["kind"])),
                   incomplete=[c for c in report["checks"] if c["status"] == "incomplete"])
    digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
    issues = bool(content["findings"] or content["incomplete"])
    now = time.time()
    due = (force or (issues and (digest != state.get("digest") or
           now - state.get("sent_at", 0) >= reminder_minutes(config) * 60))
           or (not issues and state.get("had_issues", False)))
    if not due:
        return False
    if sender is None:
        notify(webhook, slack_payload(report, resolved=not issues and state.get("had_issues", False)))
    else:
        sender(webhook, report)
    # Only acknowledge after delivery succeeds; failures retry next scheduled run.
    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = state_path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(dict(digest=digest, sent_at=now, had_issues=issues), f)
    os.replace(temp, state_path)
    return True


def scheduled_report(report, config, config_path):
    """Log every scan and alert Slack for findings or incomplete verification."""
    failed = False
    folder = config_path.expanduser().resolve().parent
    try:
        log_scan(report, config, folder / "api-outbox")
        print("Scheduled scan queued for API logging; available backlog delivery attempted.")
    except Exception:
        print("API logging failed; saved events will retry on the next scheduled run. Check API settings and local storage.", file=sys.stderr)
        failed = True
    try:
        state = folder / "monitor-scheduled-state.json"
        if outcome(report) != "pass":
            webhook = os.environ.get("GITHUB_MONITOR_SLACK_WEBHOOK") or config.get("slack_webhook")
            if not webhook:
                raise ValueError("Slack webhook required for failed verification")
            sent = deliver(report, config, state, webhook)
            print("Failure alert delivered." if sent else "Duplicate failure alert suppressed.")
        else:
            # Reset suppression silently, so a recurrence triggers a fresh alert.
            state.unlink(missing_ok=True)
            print("Verification passed; scheduled Slack alert skipped.")
    except Exception:
        print("Scheduled Slack delivery/state update failed; retry on the next scan.", file=sys.stderr)
        failed = True
    return failed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="print sanitized inventory; never send Slack or update state")
    mode.add_argument("--local-alert", action="store_true", help="show the macOS cleanup dialog now without Slack or reminder suppression")
    mode.add_argument("--scheduled", action="store_true", help="log every scan to the API; alert Slack for findings or incomplete verification")
    mode.add_argument("--force-alert", action="store_true", help="bypass Slack and local reminder suppression; send report even with no findings")
    p.add_argument("--linux-worker", help=argparse.SUPPRESS)
    a = p.parse_args()
    if a.linux_worker:
        linux_worker(json.loads(a.linux_worker))
        return 0
    if not a.config:
        p.error("--config is required")
    try:
        config = json.loads(a.config.expanduser().read_text())
        reminder_minutes(config)  # Validate before any notifications or cleanup.
        report = Scan(config).scan()
        if a.dry_run:
            print(json.dumps(dict(report, outcome=outcome(report)), indent=2))
        elif a.local_alert:
            if platform.system() != "Darwin":
                print("Local cleanup dialogs require macOS.", file=sys.stderr)
                return 3
            if not report["findings"]:
                print("No findings detected; no cleanup dialog needed.")
            else:
                try:
                    local_notify(None, report, {"github.com", *config.get("github_hosts", [])})
                except Exception:
                    print("Local alert or cleanup could not complete; check the desktop session and Keychain permissions.", file=sys.stderr)
                    return 3
                report = Scan(config).scan()
        else:
            # Capture the detected state before a user can remove findings locally.
            scheduled_failed = scheduled_report(report, config, a.config) if a.scheduled else False
            scheduled_scan = report if a.scheduled else None
            if platform.system() == "Darwin" and config.get("local_alerts", True):
                local_state = a.config.expanduser().resolve().with_name("monitor-local-state.json")
                # Local prompts concern findings, not unsupported inspection methods.
                local_report = dict(report, checks=[])
                try:
                    deliver(local_report, config, local_state, None, force=a.force_alert,
                            sender=lambda webhook, value: local_notify(
                                webhook, value, {"github.com", *config.get("github_hosts", [])}))
                except Exception:
                    print("Local alert or cleanup could not complete; check the desktop session and Keychain permissions.", file=sys.stderr)
                # Include successful or partial cleanup in Slack and the exit status.
                report = Scan(config).scan()
            if a.scheduled:
                return 3 if scheduled_failed else (2 if scheduled_scan["coverage"] == "incomplete"
                                                  else (1 if scheduled_scan["findings"] else 0))
            webhook = os.environ.get("GITHUB_MONITOR_SLACK_WEBHOOK") or config.get("slack_webhook")
            if not webhook:
                print("No Slack webhook configured. Use --dry-run or configure reporting.", file=sys.stderr)
                return 3
            state = a.config.expanduser().resolve().with_name("monitor-state.json")
            try:
                sent = deliver(report, config, state, webhook, a.force_alert)
                print("Report delivered." if sent else "Scan completed; duplicate/empty alert suppressed.")
            except Exception:
                print("Slack delivery or state update failed; no successful delivery state recorded. Check connectivity/configuration.", file=sys.stderr)
                return 3
        return 2 if report["coverage"] == "incomplete" else (1 if report["findings"] else 0)
    except Exception:
        # Never print exception strings: filesystem paths/URLs might contain secrets.
        print("Scan/configuration failed. Check config syntax, paths and permissions.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
