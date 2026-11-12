import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock
import monitor as m

FAKE_TOKEN = "ghp_" + "A" * 36


class MonitorTests(unittest.TestCase):
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

    def report(self, issues=True):
        return dict(timestamp="now", employee="Example", device="device", local_user="user", os="Linux",
                    findings=[dict(source="Store", kind="Credential present", count=1)] if issues else [],
                    checks=[], coverage="configured checks completed")

    def test_slack_status_and_incomplete_coverage(self):
        report = self.report(False)
        self.assertIn("No findings in configured checks", m.slack_payload(report)["text"])
        self.assertIn("Findings cleared", m.slack_payload(report, resolved=True)["text"])
        report["checks"] = [dict(source="Store", status="incomplete", reason="Locked")]
        payload = m.slack_payload(report, resolved=True)
        self.assertIn("Checks incomplete", payload["text"])
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

    def test_notify_serializes_block_payload(self):
        payload = m.slack_payload(self.report())
        with patch.object(m.urllib.request, "build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b"ok"
            m.notify("https://hooks.slack.com/services/test", payload)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(json.loads(request.data), payload)

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
            config.write_text(json.dumps({"slack_webhook": "unused"}))
            with patch.object(m.Scan, "scan", return_value=self.report()), \
                 patch.object(m.platform, "system", return_value="Darwin"), \
                 patch.object(m, "deliver") as deliver, patch("builtins.print"), \
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

    def test_webhook_allowlist(self):
        for bad in ("http://hooks.slack.com/services/a", "https://evil.test/services/a",
                    "https://hooks.slack.com.evil.test/services/a"):
            with self.assertRaises(ValueError):
                m.notify(bad, "example")

    def test_linux_missing_worker_is_incomplete(self):
        scan = m.Scan({"employee": "Example"})
        with patch.object(m, "run", side_effect=subprocess.TimeoutExpired("worker", 35)):
            scan.linux()
        self.assertEqual(scan.checks[0]["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
