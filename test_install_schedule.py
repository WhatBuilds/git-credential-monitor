import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch
import install_schedule as scheduler


class ScheduleTests(unittest.TestCase):
    def install(self, root, system, interval=2):
        config = root / 'config.json'
        config.write_text(json.dumps({'slack_webhook': 'unused', 'reminder_minutes': 3,
                                      'scan_interval_minutes': interval}))
        with patch.object(scheduler.Path, 'home', return_value=root), \
             patch.object(scheduler.platform, 'system', return_value=system), \
             patch.object(scheduler.os, 'geteuid', return_value=501, create=True), \
             patch.object(scheduler, 'command') as command, patch('builtins.print'):
            scheduler.install(config)
        return command

    def test_macos_persists_login_start_and_interval_and_enables_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = self.install(root, 'Darwin')
            path = root / 'Library/LaunchAgents' / (scheduler.LABEL + '.plist')
            content = plistlib.loads(path.read_bytes())
            self.assertTrue(content['RunAtLoad'])
            self.assertEqual(content['StartInterval'], 120)
            self.assertEqual(content['LimitLoadToSessionType'], 'Aqua')
            self.assertEqual(content['ProgramArguments'][-1], str((root / 'config.json').resolve()))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual([c.args[0][1] for c in command.call_args_list], ['bootout', 'enable', 'bootstrap'])
            self.install(root, 'Darwin', 4)
            self.assertEqual(plistlib.loads(path.read_bytes())['StartInterval'], 240)

    def test_linux_timer_is_enabled_and_restarted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = self.install(root, 'Linux')
            timer = (root / '.config/systemd/user' / (scheduler.LABEL + '.timer')).read_text()
            self.assertIn('OnUnitActiveSec=2min', timer)
            self.assertIn('WantedBy=timers.target', timer)
            self.assertIn(['systemctl', '--user', 'enable', scheduler.LABEL + '.timer'],
                          [c.args[0] for c in command.call_args_list])
            self.assertEqual(command.call_args.args[0], ['systemctl', '--user', 'restart', scheduler.LABEL + '.timer'])

    def test_windows_task_uses_configured_minutes(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = self.install(Path(tmp), 'Windows')
            args = command.call_args.args[0]
            self.assertEqual(args[args.index('/MO') + 1], '2')
            self.assertIn('/IT', args)

    def test_invalid_interval_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for value in (0, -1, True, 1.5, '2', 1440):
                with self.assertRaises(ValueError):
                    self.install(Path(tmp), 'Darwin', value)


if __name__ == '__main__':
    unittest.main()
