import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock
import monitor as m

FAKE_TOKEN = "ghp_" + "A" * 36


class MonitorTests(unittest.TestCase):
    def test_windows_child_commands_do_not_open_console(self):
        with patch.object(m.sys, "platform", "win32"), \
             patch.object(m.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True), \
             patch.object(m.subprocess, "run") as command:
            m.run(["git", "config", "--global", "--list"])
            self.assertEqual(command.call_args.kwargs["creationflags"], 0x08000000)
            self.assertTrue(command.call_args.kwargs["capture_output"])
        with patch.object(m.sys, "platform", "darwin"), patch.object(m.subprocess, "run") as command:
            m.run(["git", "--version"])
            self.assertEqual(command.call_args.kwargs["creationflags"], 0)

    def test_windowless_main_handles_missing_output_streams(self):
        with patch.object(m.sys, "stdout", None), patch.object(m.sys, "stderr", None), \
             patch.object(m.sys, "argv", ["monitor.py", "--config", "/nonexistent/monitor-config.json"]):
            try:
                self.assertEqual(m.main(), 3)
                self.assertIsNotNone(m.sys.stdout)
                self.assertIsNotNone(m.sys.stderr)
            finally:
                if m.sys.stdout is not None:
                    m.sys.stdout.close()
                if m.sys.stderr is not None:
                    m.sys.stderr.close()

    def test_employee_label_optional_with_override(self):
        for config in ({}, {"employee": ""}, {"employee": "   "}, {"employee": None}):
            self.assertEqual(m.employee_label(config, "rahul"), "rahul")
        self.assertEqual(m.employee_label({"employee": " Rahul Sharma "}, "rahul"), "Rahul Sharma")

    def test_host_boundaries(self):
        self.assertTrue(m.host_match("git:https://github.com", {"github.com"}))
        self.assertFalse(m.host_match("https://github.com.evil.test", {"github.com"}))
        self.assertFalse(m.host_match("notgithub.com", {"github.com"}))

    def test_username_only_is_not_credential(self):
        self.assertFalse(m.url_credential("https://alice@github.com/org/repo", {"github.com"}))
        self.assertTrue(m.url_credential("https://alice:secret@github.com", {"github.com"}))
        self.assertTrue(m.url_credential("https://" + FAKE_TOKEN + "@github.com", {"github.com"}))
        self.assertFalse(m.url_credential("https://alice:secret@github.com.evil.test", {"github.com"}))

    def test_plaintext_report_never_contains_token_or_secret_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / (FAKE_TOKEN + ".txt")
            p.write_text("https://alice:" + FAKE_TOKEN + "@github.com\n")
            scan = m.Scan({"employee": "Example employee"})
            scan.file(p, "Default Git credential file", "git-store")
            self.assertEqual(len(scan.findings), 1)
            output = json.dumps([scan.findings, scan.checks])
            self.assertNotIn(FAKE_TOKEN, output)
            self.assertNotIn(tmp, output)

    def test_gh_token_not_empty_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "hosts.yml"
            scan = m.Scan({"employee": "Example"})
            p.write_text("github.com:\n    user: alice\n    oauth_token: ''\n")
            scan.file(p, "GH file", "gh")
            self.assertEqual(scan.findings, [])
            p.write_text("github.com:\n    users:\n        alice:\n            oauth_token: " + FAKE_TOKEN)
            scan.file(p, "GH file", "gh")
            self.assertEqual(len(scan.findings), 1)

    def test_netrc_without_secret_reporting(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / ".netrc"
            p.write_text("machine github.com login alice password " + FAKE_TOKEN + "\n")
            scan = m.Scan({"employee": "Example"})
            scan.netrc_file(p, "User .netrc file")
            self.assertEqual(len(scan.findings), 1)
            self.assertNotIn(FAKE_TOKEN, json.dumps([scan.findings, scan.checks]))

    def test_unreadable_and_oversize_not_clean(self):
        scan = m.Scan({"employee": "Example"})
        with patch.object(Path, "stat", side_effect=PermissionError):
            scan.file(Path("unused"), "Test file")
        self.assertEqual(scan.checks[0]["status"], "incomplete")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "large"
            with p.open("wb") as f:
                f.truncate(m.MAX_FILE + 1)
            scan.file(p, "Large file")
            self.assertEqual(scan.checks[-1]["status"], "incomplete")

    def test_never_execute_custom_helper(self):
        scan = m.Scan({"employee": "Example"})
        with patch.object(m, "run") as command:
            scan.helper("!echo " + FAKE_TOKEN, "Git config", None)
            command.assert_not_called()
        self.assertEqual(scan.checks[0]["status"], "incomplete")
        self.assertNotIn(FAKE_TOKEN, json.dumps(scan.checks))

    def test_mac_metadata_only_and_certificates_excluded(self):
        fixture = ('keychain: "login"\nclass: "genp"\nattributes:\n'
                   '    "svce"<blob>="gh:github.com"\n'
                   'keychain: "login"\nclass: "cert"\nattributes:\n'
                   '    "labl"<blob>="github.com"\n')
        scan = m.Scan({"employee": "Example"})
        with patch.object(m, "run", return_value=subprocess.CompletedProcess([], 0, fixture, "")) as cmd:
            scan.mac()
            self.assertEqual(cmd.call_args.args[0], ["/usr/bin/security", "dump-keychain"])
        self.assertEqual(scan.findings[0]["count"], 1)

    def test_mac_detects_fork_and_github_app_keychain_metadata(self):
        fixture = ('keychain: "login"\nclass: "genp"\nattributes:\n'
                   '    "svce"<blob>="fork:https://github.com.example.accesstoken"\n'
                   'keychain: "login"\nclass: "genp"\nattributes:\n'
                   '    "svce"<blob>="GitHub - https://api.github.com"\n')
        scan = m.Scan({})
        with patch.object(m, "run", return_value=subprocess.CompletedProcess([], 0, fixture, "")):
            scan.mac()
        self.assertEqual(scan.findings[0]["count"], 2)
        self.assertNotIn("example.accesstoken", json.dumps(scan.findings))

    def report(self, issues=True):
        return dict(timestamp="now", employee="Example", device="device", local_user="user", os="Linux",
                    findings=[dict(source="Store", kind="Credential present", count=1)] if issues else [],
                    checks=[], coverage="configured checks completed")

    def test_github_cli_helper_notice_does_not_execute_or_claim_token(self):
        scan = m.Scan({})
        with patch.object(m, "run") as command:
            scan.helper("!/opt/homebrew/bin/gh auth git-credential", "Git user/system configuration", None)
            command.assert_not_called()
        self.assertEqual(scan.findings, [])
        self.assertEqual(scan.checks[0]["status"], "incomplete")
        self.assertIn("GitHub CLI", scan.checks[0]["reason"])
        report = self.report(False)
        report.update(checks=scan.checks, coverage="incomplete", os="Darwin")
        payload = m.slack_payload(report)
        rendered = json.dumps(payload, ensure_ascii=False)
        self.assertIn("Verification failed — credentials may remain", payload["text"])
        self.assertIn("This result is FAIL", rendered)
        self.assertIn("Fork", rendered)
        self.assertIn("saved by other apps", rendered)
        self.assertNotIn("No credentials detected", rendered)
        self.assertIn("gh auth logout", rendered)
        self.assertIn("Limited: configured Git helpers were not executed", rendered)
        self.assertNotIn("*Incomplete checks*", rendered)
        self.assertEqual(report["coverage"], "incomplete")

    def test_custom_helper_does_not_receive_github_cli_logout_guidance(self):
        scan = m.Scan({})
        scan.helper("!gh auth git-credential; echo unsafe", "Git config", None)
        report = self.report(False)
        report.update(checks=scan.checks, coverage="incomplete")
        rendered = json.dumps(m.slack_payload(report))
        self.assertNotIn("gh auth logout", rendered)
        self.assertIn("Git authentication helper", rendered)
        report["checks"].append(dict(source="Keychain", status="incomplete", reason="Query failed"))
        self.assertIn("checks incomplete", m.slack_payload(report)["text"])
        report["findings"] = self.report()["findings"]
        self.assertIn("Credentials found", m.slack_payload(report)["text"])

    def test_slack_status_and_incomplete_coverage(self):
        report = self.report(False)
        self.assertIn("No findings in configured checks", m.slack_payload(report)["text"])
        self.assertIn("Findings cleared", m.slack_payload(report, resolved=True)["text"])
        report["checks"] = [dict(source="Store", status="incomplete", reason="Locked")]
        payload = m.slack_payload(report, resolved=True)
        self.assertIn("checks incomplete", payload["text"])
        self.assertIn("Locked", json.dumps(payload))
        report["findings"] = self.report()["findings"]
        self.assertIn("Credentials found", m.slack_payload(report)["text"])

    def test_slack_dynamic_values_cannot_be_mentions(self):
        report = self.report()
        report["employee"] = "<!channel> *name* <https://example.com>"
        payload = m.slack_payload(report)
        field = payload["blocks"][2]["fields"][0]
        self.assertEqual(field["type"], "plain_text")
        self.assertIn(report["employee"], field["text"])
        self.assertNotIn(report["employee"], payload["text"])

    def test_large_slack_report_respects_limits_and_discloses_omissions(self):
        report = self.report()
        report["employee"] = "x" * 4000
        report["findings"] *= 100
        report["checks"] = [dict(source="Store", status="incomplete", reason="x" * 4000)] * 100
        payload = m.slack_payload(report)
        self.assertLessEqual(len(payload["blocks"]), 50)
        for block in payload["blocks"]:
            if "text" in block:
                self.assertLessEqual(len(block["text"]["text"]), 150 if block["type"] == "header" else 3000)
            for field in block.get("fields", []) + block.get("elements", []):
                self.assertLessEqual(len(field["text"]), 2000)
        self.assertIn("82 additional finding groups omitted", json.dumps(payload))
        self.assertIn("82 additional incomplete checks omitted", json.dumps(payload))

    def test_notify_sends_authenticated_text_only(self):
        payload = m.slack_payload(self.report())
        with patch.object(m.urllib.request, "build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b"ok"
            m.notify({"slack_api_url": "https://slack.example.test/send", "slack_api_token": "dummy"}, payload)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(json.loads(request.data), {"text": payload["text"]})
            self.assertEqual(request.get_header("Authorization"), "Bearer dummy")
            self.assertEqual(request.method, "POST")

    def test_duplicate_checks_are_collapsed(self):
        scan = m.Scan({})
        for _ in range(2):
            scan.helper("!custom-command", "Git user/system configuration", None)
        self.assertEqual(len(scan.checks), 1)
        scan.helper("!custom-command", "Repository 1 configuration", None)
        self.assertEqual(len(scan.checks), 2)

    def keychain_item(self, reference=b"exact-item", service="gh:github.com"):
        return dict(reference=reference, kind="kSecClassGenericPassword", service=service,
                    server="", label="", description="", account="example")

    def test_local_deletion_requires_confirmation_and_exact_item(self):
        item = self.keychain_item()
        other = self.keychain_item(b"other", "unrelated.example")
        for confirmed in (False, True):
            with patch.object(m, "Keychain") as factory, patch.object(m, "local_dialog", return_value=confirmed) as dialog:
                keychain = factory.return_value
                keychain.items.side_effect = [[item, other], [other]]
                m.local_notify(None, self.report())
                self.assertIn("gh:github.com", dialog.call_args_list[0].args[0])
                self.assertEqual(dialog.call_args_list[0].args[1], "Delete listed entries")
                if confirmed:
                    keychain.delete.assert_called_once_with(item)
                else:
                    keychain.delete.assert_not_called()
        with patch.object(m, "Keychain") as factory:
            m.local_notify(None, self.report(False))
            factory.assert_not_called()

    def test_local_deletion_failure_and_verification(self):
        item = self.keychain_item()
        with patch.object(m, "Keychain") as factory, patch.object(m, "local_dialog", return_value=True) as dialog:
            keychain = factory.return_value
            keychain.items.return_value = [item]
            keychain.delete.side_effect = OSError
            with self.assertRaises(RuntimeError):
                m.local_notify(None, self.report())
            self.assertIn("1 remain", dialog.call_args.args[0])

    def test_keychain_failure_displays_only_safe_error_codes(self):
        item = self.keychain_item()
        with patch.object(m, "Keychain") as factory, patch.object(m, "local_dialog", return_value=True) as dialog, \
             patch("builtins.print") as output:
            keychain = factory.return_value
            keychain.items.return_value = [item]
            keychain.delete.side_effect = m.KeychainError("Keychain deletion", -25293)
            with self.assertRaises(RuntimeError):
                m.local_notify(None, self.report())
            self.assertIn("Entry 1: macOS status -25293", dialog.call_args.args[0])
            self.assertNotIn(item["account"], output.call_args.args[0])
            self.assertNotIn(item["service"], output.call_args.args[0])

    def test_local_dialog_timeout_and_script_injection(self):
        message = '" & do shell script "unsafe"'
        for output in ("dismissed", "confirmed"):
            with patch.object(m, "run", return_value=subprocess.CompletedProcess([], 0, output, "")) as command:
                self.assertEqual(m.local_dialog(message, "Delete listed entries"), output == "confirmed")
                argv = command.call_args.args[0]
                self.assertNotIn(message, argv[2])
                self.assertEqual(argv[3], message)
                self.assertIn('if gave up of answer then return "dismissed"', argv[2])

    def test_local_deletion_never_includes_unlisted_entries(self):
        items = [self.keychain_item(str(i).encode()) for i in range(11)]
        with patch.object(m, "Keychain") as factory, patch.object(m, "local_dialog", return_value=True) as dialog:
            keychain = factory.return_value
            keychain.items.side_effect = [items, items[10:]]
            m.local_notify(None, self.report())
            self.assertEqual(keychain.delete.call_count, 10)
            self.assertNotIn(items[10], [call.args[0] for call in keychain.delete.call_args_list])
            self.assertIn("1 additional entries", dialog.call_args_list[0].args[0])

    def test_native_delete_query_uses_exact_reference_only(self):
        from keychain_remediation import Keychain
        keychain = Keychain.__new__(Keychain)
        keychain.cf = Mock()
        keychain.cf.CFDataCreate.return_value = 11
        keychain.cf.CFArrayCreate.return_value = 12
        keychain.sec = Mock()
        keychain.sec.SecItemDelete.return_value = 0
        keychain.constant = Mock(return_value=13)
        keychain.callbacks = Mock(return_value=14)
        keychain.dictionary = Mock(return_value=15)
        keychain.delete(self.keychain_item())
        keychain.cf.CFDataCreate.assert_called_once_with(None, b"exact-item", 10)
        keychain.dictionary.assert_called_once_with([('kSecClass', 13), ('kSecMatchItemList', 12)])
        keychain.sec.SecItemDelete.assert_called_once_with(15)
        with self.assertRaises(ValueError):
            keychain.delete(self.keychain_item(b""))

    def test_explicit_local_alert_bypasses_state_and_never_sends_slack(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(json.dumps({"local_alerts": False}))
            with patch.object(m.Scan, "scan", side_effect=[self.report(), self.report(False)]), \
                 patch.object(m.platform, "system", return_value="Darwin"), \
                 patch.object(m, "local_notify") as local, patch.object(m, "notify") as slack, \
                 patch.object(m.sys, "argv", ["monitor.py", "--config", str(config), "--local-alert"]):
                self.assertEqual(m.main(), 0)
                local.assert_called_once()
                slack.assert_not_called()
            self.assertFalse((Path(tmp) / "monitor-local-state.json").exists())
            self.assertFalse((Path(tmp) / "monitor-state.json").exists())

    def test_force_alert_bypasses_both_reminders(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(json.dumps({"slack_api_url": "unused"}))
            with patch.object(m.Scan, "scan", return_value=self.report()), \
                 patch.object(m.platform, "system", return_value="Darwin"), \
                 patch.object(m, "deliver") as deliver, patch.object(m, "log_scan"), patch("builtins.print"), \
                 patch.object(m.sys, "argv", ["monitor.py", "--config", str(config), "--force-alert"]):
                self.assertEqual(m.main(), 1)
                self.assertTrue(deliver.call_args_list[0].kwargs["force"])
                self.assertTrue(deliver.call_args_list[1].args[4])

    def test_local_delivery_throttles_and_retries_failures(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, "local_notify") as alert:
            state = Path(tmp) / "local-state.json"
            alert.side_effect = OSError
            with self.assertRaises(OSError):
                m.deliver(self.report(), {}, state, None, sender=alert)
            self.assertFalse(state.exists())
            alert.side_effect = None
            self.assertTrue(m.deliver(self.report(), {}, state, None, sender=alert))
            self.assertFalse(m.deliver(self.report(), {}, state, None, sender=alert))
            with patch.object(m.time, "time", return_value=m.time.time() + 86401):
                self.assertTrue(m.deliver(self.report(), {}, state, None, sender=alert))

    def test_minute_reminders_and_legacy_config(self):
        self.assertEqual(m.reminder_minutes({}), 15)
        self.assertEqual(m.reminder_minutes({"reminder_hours": 2}), 120)
        self.assertEqual(m.reminder_minutes({"reminder_hours": 2, "reminder_minutes": 3}), 3)
        for value in (0, -1, True, "5", None, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                m.reminder_minutes({"reminder_minutes": value})
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, "notify") as notify:
            state = Path(tmp) / "state.json"
            config = {"reminder_minutes": 2}
            with patch.object(m.time, "time", return_value=1000):
                self.assertTrue(m.deliver(self.report(), config, state, "unused"))
            with patch.object(m.time, "time", return_value=1119):
                self.assertFalse(m.deliver(self.report(), config, state, "unused"))
            with patch.object(m.time, "time", return_value=1120):
                self.assertTrue(m.deliver(self.report(), config, state, "unused"))
            self.assertEqual(notify.call_count, 2)

    def test_delivery_dedup_and_resolution(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, "notify") as notify:
            state = Path(tmp) / "state.json"
            cfg = {"reminder_hours": 24}
            self.assertTrue(m.deliver(self.report(), cfg, state, "unused"))
            self.assertFalse(m.deliver(self.report(), cfg, state, "unused"))
            self.assertTrue(m.deliver(self.report(False), cfg, state, "unused"))
            self.assertFalse(m.deliver(self.report(False), cfg, state, "unused"))
            self.assertEqual(notify.call_count, 2)

    def test_delivery_failure_does_not_acknowledge(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, "notify", side_effect=OSError):
            state = Path(tmp) / "state.json"
            with self.assertRaises(OSError):
                m.deliver(self.report(), {}, state, "unused")
            self.assertFalse(state.exists())

    def test_dry_run_never_notifies_or_writes_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(json.dumps({"employee": "Example"}))
            with patch.object(m.Scan, "scan", return_value=self.report()), patch.object(m, "notify") as notify, \
                 patch.object(m.sys, "argv", ["monitor.py", "--config", str(config), "--dry-run"]), \
                 patch("builtins.print"):
                self.assertEqual(m.main(), 1)
                notify.assert_not_called()
            self.assertFalse((Path(tmp) / "monitor-state.json").exists())

    def test_slack_api_rejects_invalid_endpoint(self):
        for bad in ("http://example.test/send", "https://user:pass@example.test/send",
                    "https://example.test/send#fragment", ""):
            with self.assertRaises(ValueError):
                m.notify({"slack_api_url": bad, "slack_api_token": "dummy"}, {"text": "example"})

    def test_linux_missing_worker_is_incomplete(self):
        scan = m.Scan({"employee": "Example"})
        with patch.object(m, "run", side_effect=subprocess.TimeoutExpired("worker", 35)):
            scan.linux()
        self.assertEqual(scan.checks[0]["status"], "incomplete")

    def test_linux_retries_once_then_succeeds(self):
        bad = subprocess.CompletedProcess([], 0, stdout='{"status": "incomplete", "count": 0}')
        good = subprocess.CompletedProcess([], 0, stdout='{"status": "checked", "count": 0}')
        scan = m.Scan({"employee": "Example"})
        with patch.object(m, "run", side_effect=[bad, good]) as run, \
                patch.object(m.time, "sleep") as sleep:
            scan.linux()
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(m.LINUX_RETRY_DELAY)
        self.assertEqual(scan.checks[0]["status"], "checked")

    def test_linux_retry_gives_up_after_one_attempt(self):
        bad = subprocess.CompletedProcess([], 0, stdout='{"status": "incomplete", "count": 0}')
        scan = m.Scan({"employee": "Example"})
        with patch.object(m, "run", return_value=bad) as run, patch.object(m.time, "sleep"):
            scan.linux()
        self.assertEqual(run.call_count, 2)
        self.assertEqual(scan.checks[0]["status"], "incomplete")


class EditorSessionTests(unittest.TestCase):
    SESSION_KEY = 'secret://{"extensionId":"vscode.github-authentication","key":"github.auth"}'

    def editor(self, root, name, rows):
        import sqlite3
        db = Path(root) / name / "User/globalStorage/state.vscdb"
        db.parent.mkdir(parents=True)
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
        con.executemany("INSERT INTO ItemTable VALUES (?, ?)", rows)
        con.commit()
        con.close()
        return (name, Path(root) / name)

    @staticmethod
    def envelope(nbytes):
        return json.dumps({"type": "Buffer", "data": [200] * nbytes})

    def test_signed_in_editor_is_reported_without_secret_or_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            value = self.envelope(400).replace("200", "123", 1) + FAKE_TOKEN
            d = self.editor(tmp, "Code", [(self.SESSION_KEY, value), ("vscode.github", "{}")])
            scan = m.Scan({})
            scan.editors([d])
            self.assertEqual(scan.findings, [dict(source="Editor GitHub sign-in (Code)",
                                                  kind="editor holds a GitHub sign-in that Git can use", count=1)])
            output = json.dumps([scan.findings, scan.checks])
            self.assertNotIn(FAKE_TOKEN, output)
            self.assertNotIn(tmp, output)

    def test_signed_out_editor_and_other_extension_secrets_are_not_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            dirs = [self.editor(tmp, "Code", [(self.SESSION_KEY, self.envelope(33))]),
                    self.editor(tmp, "Cursor", [('secret://{"extensionId":"other.ext","key":"github.auth"}',
                                                 self.envelope(400))])]
            scan = m.Scan({})
            scan.editors(dirs)
            self.assertEqual(scan.findings, [])
            self.assertEqual([c["status"] for c in scan.checks], ["checked", "checked"])

    def test_missing_editor_is_silent_and_corrupt_database_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "Windsurf/User/globalStorage/state.vscdb"
            bad.parent.mkdir(parents=True)
            bad.write_bytes(b"not a database" * 100)
            scan = m.Scan({})
            scan.editors([("Code", Path(tmp) / "Code"), ("Windsurf", Path(tmp) / "Windsurf")])
            self.assertEqual(scan.findings, [])
            self.assertEqual(scan.checks, [dict(source="Editor GitHub sign-in (Windsurf)", status="incomplete",
                                                reason="editor state database unreadable or locked")])


def fake_openssh_key(cipher=b"none", key_type=b"ssh-ed25519"):
    """Header-accurate OpenSSH key with dummy contents (not a usable key)."""
    import base64, struct

    def s(b):
        return struct.pack(">I", len(b)) + b
    kdf = b"none" if cipher == b"none" else b"bcrypt"
    blob = (b"openssh-key-v1\0" + s(cipher) + s(kdf) + s(b"") + struct.pack(">I", 1)
            + s(s(key_type) + s(b"P" * 32)) + s(b"SECRET-MATERIAL" * 8))
    body = base64.b64encode(blob).decode()
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(body[i:i + 70] for i in range(0, len(body), 70))
            + "\n-----END OPENSSH PRIVATE KEY-----\n").encode()


class SshKeyTests(unittest.TestCase):
    def test_key_state_classification(self):
        self.assertEqual(m.ssh_key_state(fake_openssh_key()), "unencrypted")
        self.assertEqual(m.ssh_key_state(fake_openssh_key(b"aes256-ctr")), "encrypted")
        self.assertEqual(m.ssh_key_state(fake_openssh_key(key_type=b"sk-ssh-ed25519@openssh.com")), "hardware")
        self.assertEqual(m.ssh_key_state(b"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n"),
                         "unencrypted")
        self.assertEqual(m.ssh_key_state(b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
                                         b"DEK-Info: AES-128-CBC,00\n\nMIIE\n-----END RSA PRIVATE KEY-----\n"),
                         "encrypted")
        self.assertEqual(m.ssh_key_state(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMII\n-----END"), "encrypted")
        self.assertEqual(m.ssh_key_state(b"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"), "unencrypted")
        self.assertEqual(m.ssh_key_state(b"PuTTY-User-Key-File-2: ssh-rsa\nEncryption: aes256-cbc\n"), "encrypted")
        self.assertEqual(m.ssh_key_state(b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"),
                         "unknown")
        self.assertIsNone(m.ssh_key_state(b""))
        self.assertIsNone(m.ssh_key_state(b"ssh-ed25519 AAAA user@host"))

    def identities(self, config, hosts=("github.com",)):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".ssh").mkdir()
            (Path(tmp) / ".ssh/config").write_text(config)
            lines = m.ssh_config_lines(Path(tmp) / ".ssh/config", Path(tmp) / ".ssh")
            paths, keychain, unexpanded = m.ssh_github_identities(lines, set(hosts), Path(tmp), "me")
            return [p.relative_to(tmp).as_posix() for p in paths], keychain, unexpanded

    def test_defaults_without_config_and_unrelated_hosts_ignored(self):
        paths, _, _ = self.identities("Host bastion\n  IdentityFile ~/.ssh/bastion\n")
        self.assertIn(".ssh/id_ed25519", paths)
        self.assertNotIn(".ssh/bastion", paths)

    def test_configured_identity_replaces_defaults(self):
        paths, _, _ = self.identities("Host github.com\n  IdentityFile ~/.ssh/gh_key\n  IdentitiesOnly yes\n")
        self.assertEqual(paths, [".ssh/gh_key"])

    def test_alias_wildcard_negation_keychain_and_tokens(self):
        paths, keychain, unexpanded = self.identities(
            "Host *\n  UseKeychain yes\n"
            "Host gh-work\n  HostName github.com\n  IdentityFile %d/.ssh/work\n"
            "Host * !github.com\n  IdentityFile ~/.ssh/not_for_github\n"
            "Host github.com\n  IdentityFile ~/.ssh/%r_key\n")
        self.assertIn(".ssh/work", paths)
        self.assertIn(".ssh/not_for_github", paths)  # Applies to gh-work alias.
        self.assertTrue(keychain)
        self.assertTrue(unexpanded)

    def test_defaults_resolved_per_destination(self):
        paths, _, _ = self.identities(
            "Host github.com\n IdentityFile ~/.ssh/protected\n",
            hosts=("github.com", "ssh.github.com"))
        self.assertIn(".ssh/protected", paths)
        self.assertIn(".ssh/id_ed25519", paths)

    def test_alias_inherits_other_matching_blocks(self):
        paths, _, _ = self.identities(
            "Host gh-work\n HostName github.com\n"
            "Host gh-*\n IdentityFile ~/.ssh/work\n")
        self.assertIn(".ssh/work", paths)

    def test_identity_none_suppresses_defaults(self):
        paths, _, _ = self.identities("Host *\n IdentityFile none\n")
        self.assertEqual(paths, [])
        paths, _, _ = self.identities(
            "Host *\n IdentityFile none\n IdentityFile ~/.ssh/explicit\n")
        self.assertEqual(paths, [".ssh/explicit"])

    def test_conditional_nested_include_and_parent_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir()
            (ssh_dir / "excluded").write_text("Host *\n IdentityFile ~/.ssh/unrelated\n")
            (ssh_dir / "nested").write_text("Host *\n IdentityFile ~/.ssh/nested_key\n")
            (ssh_dir / "included").write_text(
                "Include nested\nHost unrelated\n IdentityFile ~/.ssh/also_unrelated\n")
            (ssh_dir / "config").write_text(
                "Host unrelated\n Include excluded\n"
                "Host github.com\n Include included\n IdentityFile ~/.ssh/github\n")
            paths, _, _ = m.ssh_github_identities(
                m.ssh_config_lines(ssh_dir / "config", ssh_dir), {"github.com"}, home, "me")
            self.assertEqual([p.name for p in paths], ["nested_key", "github"])

    def test_scan_detects_default_key_for_second_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            ssh_dir = Path(tmp) / ".ssh"
            ssh_dir.mkdir()
            (ssh_dir / "config").write_text("Host github.com\n IdentityFile ~/.ssh/protected\n")
            (ssh_dir / "protected").write_bytes(fake_openssh_key(b"aes256-ctr"))
            (ssh_dir / "id_ed25519").write_bytes(fake_openssh_key())
            scan = m.Scan({})
            scan.ssh(home=tmp, user="me")
            self.assertEqual(len(scan.findings), 1)
            self.assertEqual(scan.findings[0]["count"], 1)

    def test_empty_agent_is_successfully_checked(self):
        scan = m.Scan({})
        with patch.object(m.platform, "system", return_value="Linux"), \
             patch.dict(m.os.environ, {"SSH_AUTH_SOCK": "/tmp/agent"}), \
             patch.object(m.shutil, "which", return_value="/usr/bin/ssh-add"), \
             patch.object(m, "run", return_value=Mock(returncode=1, stdout="")):
            scan.ssh_agent()
        self.assertEqual(scan.findings, [])
        self.assertEqual(scan.checks, [dict(source="SSH agent", status="checked")])

    def test_agent_errors_mark_scan_incomplete(self):
        for failure in (OSError("private details"), m.subprocess.TimeoutExpired("ssh-add", 10)):
            with self.subTest(failure=type(failure).__name__):
                scan = m.Scan({})
                with patch.object(m.platform, "system", return_value="Linux"), \
                     patch.dict(m.os.environ, {"SSH_AUTH_SOCK": "/tmp/agent"}), \
                     patch.object(m.shutil, "which", return_value="/usr/bin/ssh-add"), \
                     patch.object(m, "run", side_effect=failure):
                    scan.ssh_agent()
                self.assertTrue(any(c["status"] == "incomplete" for c in scan.checks))
                self.assertNotIn("private details", json.dumps(scan.checks))

    def test_scan_reports_counts_never_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            ssh_dir = Path(tmp) / ".ssh"
            ssh_dir.mkdir()
            (ssh_dir / "id_ed25519").write_bytes(fake_openssh_key())
            (ssh_dir / "id_rsa").write_bytes(fake_openssh_key(b"aes256-ctr"))
            (ssh_dir / "id_ecdsa_sk").write_bytes(fake_openssh_key(key_type=b"sk-ecdsa-sha2-nistp256@openssh.com"))
            (ssh_dir / "unrelated_server").write_bytes(fake_openssh_key())
            scan = m.Scan({})
            scan.ssh(home=tmp, user="me")
            self.assertEqual(scan.findings, [dict(source="SSH keys used for GitHub",
                                                  kind="SSH private key without a passphrase is offered to GitHub",
                                                  count=1)])
            self.assertEqual(scan.checks, [dict(source="SSH keys used for GitHub", status="checked")])
            output = json.dumps([scan.findings, scan.checks])
            for leaked in ("id_ed25519", tmp, "SECRET"):
                self.assertNotIn(leaked, output)

    def test_agent_counts_keys_without_reporting_them(self):
        listed = Mock(returncode=0, stdout="256 SHA256:abc me@laptop (ED25519)\n3072 SHA256:def x (RSA)\n")
        scan = m.Scan({})
        with patch.object(m.platform, "system", return_value="Linux"), \
             patch.dict(m.os.environ, {"SSH_AUTH_SOCK": "/tmp/agent"}), \
             patch.object(m.shutil, "which", return_value="/usr/bin/ssh-add"), \
             patch.object(m, "run", return_value=listed):
            scan.ssh_agent()
        self.assertEqual(scan.findings[0]["count"], 2)
        self.assertNotIn("SHA256", json.dumps(scan.findings))
        scan = m.Scan({})
        with patch.object(m.platform, "system", return_value="Linux"), \
             patch.dict(m.os.environ, {"SSH_AUTH_SOCK": "/tmp/agent"}), \
             patch.object(m.shutil, "which", return_value="/usr/bin/ssh-add"), \
             patch.object(m, "run", return_value=Mock(returncode=2, stdout="")):
            scan.ssh_agent()
        self.assertEqual(scan.findings, [])
        self.assertTrue(any(c["status"] == "incomplete" for c in scan.checks))


if __name__ == "__main__":
    unittest.main()
