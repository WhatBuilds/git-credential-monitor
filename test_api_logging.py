import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import api_logging as api
import monitor as m


def report(findings=False, incomplete=False):
    return dict(timestamp='2026-11-12T00:00:00+00:00', employee='Example', device='test',
                local_user='example', os='Linux',
                coverage='incomplete' if incomplete else 'configured checks completed',
                findings=[dict(source='Store', kind='Credential present', count=1)] if findings else [],
                checks=[dict(source='Helper', status='incomplete', reason='Not inspected')] if incomplete else [])


class LoggingTests(unittest.TestCase):
    config = {'logging_api_url': 'https://logs.example.test/scans', 'logging_api_token': 'dummy'}

    def test_outcomes_and_metadata_allowlist(self):
        for found, incomplete, expected in ((False, False, 'pass'), (True, False, 'fail'),
                                            (False, True, 'incomplete'), (True, True, 'fail')):
            r = report(found, incomplete)
            r['private_reference'] = 'private'
            event = api.event_for(r)
            self.assertEqual(event['outcome'], expected)
            self.assertNotIn('private', json.dumps(event))
            self.assertEqual(event['mode'], 'scheduled')

    def test_five_field_contract_and_incomplete_is_not_pass(self):
        from report_format import report_log
        for found, incomplete in ((False, False), (True, False), (False, True), (True, True)):
            r = report(found, incomplete)
            payload = api.api_payload(api.event_for(r))
            self.assertEqual(set(payload), {'user_name', 'device', 'status', 'log', 'scanned_at'})
            self.assertEqual(payload['status'], 'fail' if found or incomplete else 'pass')
            self.assertEqual(payload['user_name'], r['employee'])
            self.assertEqual(payload['device'], r['device'])
            self.assertEqual(payload['scanned_at'], r['timestamp'])
            self.assertEqual(payload['log'], report_log(r))
            for block in m.slack_payload(r)['blocks']:
                if 'text' in block:
                    self.assertIn(block['text']['text'].strip('*'), payload['log'])
                for field in block.get('fields', []) + block.get('elements', []):
                    self.assertIn(field['text'], payload['log'])

    def test_helper_only_warning_is_api_fail_and_alerts_slack(self):
        r = report()
        r.update(coverage='incomplete', checks=[dict(source='Git config', status='incomplete',
                 reason='GitHub CLI credential helper is configured; not executed')])
        self.assertEqual(api.api_payload(api.event_for(r))['status'], 'fail')
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'log_scan'), patch.object(m, 'notify') as slack, patch('builtins.print'):
            self.assertFalse(m.scheduled_report(r, dict(self.config, slack_webhook='unused'), Path(tmp) / 'config.json'))
            slack.assert_called_once()
            self.assertIn('Verification failed', slack.call_args.args[1]['text'])

    def test_queue_retries_with_stable_event_id_and_no_token_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(api, 'post_event', side_effect=OSError) as post:
            with self.assertRaises(OSError):
                api.log_scan(report(), self.config, tmp)
            pending = list(Path(tmp).glob('*.json'))
            self.assertEqual(len(pending), 1)
            previous = json.loads(pending[0].read_text())
            self.assertNotIn('dummy', pending[0].read_text())
            post.side_effect = None
            api.log_scan(report(True), self.config, tmp)
            self.assertEqual(post.call_args_list[1].args[1]['event_id'], previous['event_id'])
            self.assertEqual(list(Path(tmp).glob('*.json')), [])

    def test_http_payload_and_auth(self):
        event = api.event_for(report())
        with patch.object(api.urllib.request, 'build_opener') as opener, patch.dict(api.os.environ, {}, clear=True):
            opener.return_value.open.return_value.__enter__.return_value.status = 201
            api.post_event(self.config, event)
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(json.loads(req.data), api.api_payload(event))
            self.assertEqual(req.get_header('Authorization'), 'Bearer dummy')
            self.assertEqual(req.get_header('Idempotency-key'), event['event_id'])
            self.assertEqual(req.method, 'POST')

    def test_named_api_key_environment_variable(self):
        with patch.object(api.urllib.request, 'build_opener') as opener, \
             patch.dict(api.os.environ, {'CREDENTIAL_MONITOR_API_KEY': 'environment-test-key'}, clear=True):
            opener.return_value.open.return_value.__enter__.return_value.status = 201
            api.post_event(self.config, api.event_for(report(), mode='force-alert'))
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.get_header('Authorization'), 'Bearer environment-test-key')

    def test_force_alert_api_failure_still_sends_slack(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps(dict(self.config, slack_webhook='unused', local_alerts=False)))
            with patch.object(m.Scan, 'scan', return_value=report(True)), \
                 patch.object(m, 'log_scan', side_effect=OSError), patch.object(m, 'notify') as slack, \
                 patch.object(m.sys, 'argv', ['monitor.py', '--config', str(path), '--force-alert']), patch('builtins.print'):
                self.assertEqual(m.main(), 3)
                slack.assert_called_once()

    def test_invalid_endpoints_and_non_success_keep_event(self):
        for url in ('', 'http://example.test', 'https://user:pass@example.test', 'https://example.test/#x'):
            with self.assertRaises(ValueError):
                api.validate_api({'logging_api_url': url})
        with tempfile.TemporaryDirectory() as tmp, patch.object(api.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.status = 302
            with self.assertRaises(RuntimeError):
                api.log_scan(report(), self.config, tmp)
            self.assertEqual(len(list(Path(tmp).glob('*.json'))), 1)

    def test_scheduled_alerts_findings_and_incomplete_verification(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'log_scan') as log, patch.object(m, 'notify') as slack, patch('builtins.print'):
            path = Path(tmp) / 'config.json'
            config = dict(self.config, slack_webhook='unused')
            self.assertFalse(m.scheduled_report(report(True), config, path))
            self.assertFalse(m.scheduled_report(report(), config, path))
            self.assertFalse(m.scheduled_report(report(False, True), config, path))
            self.assertEqual(log.call_count, 3)
            self.assertEqual(slack.call_count, 2)
            self.assertFalse(m.scheduled_report(report(True), config, path))
            self.assertEqual(slack.call_count, 3)  # Changed failed verification triggers a new alert.

    def test_api_failure_does_not_block_slack(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'log_scan', side_effect=OSError), patch.object(m, 'notify') as slack, patch('builtins.print'):
            self.assertTrue(m.scheduled_report(report(True), dict(self.config, slack_webhook='unused'), Path(tmp) / 'config.json'))
            slack.assert_called_once()

    def test_scheduled_cli_on_all_platforms(self):
        for system in ('Darwin', 'Linux', 'Windows'):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'config.json'
                path.write_text(json.dumps(dict(self.config, slack_webhook='unused', local_alerts=False)))
                with patch.object(m.platform, 'system', return_value=system), patch.object(m.Scan, 'scan', return_value=report()), \
                     patch.object(m, 'log_scan') as log, patch.object(m, 'notify') as slack, \
                     patch.object(m.sys, 'argv', ['monitor.py', '--config', str(path), '--scheduled']), patch('builtins.print'):
                    self.assertEqual(m.main(), 0)
                    log.assert_called_once()
                    slack.assert_not_called()

    def test_manual_modes_for_pass_and_fail_log_only_force_alert(self):
        for found in (False, True):
            for mode in ('--dry-run', '--force-alert'):
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / 'config.json'
                    path.write_text(json.dumps({'slack_webhook': 'unused', 'local_alerts': False}))
                    with patch.object(m.Scan, 'scan', return_value=report(found)), patch.object(m, 'log_scan') as log, \
                         patch.object(m, 'notify') as slack, patch.object(m.sys, 'argv', ['monitor.py', '--config', str(path), mode]), patch('builtins.print'):
                        self.assertEqual(m.main(), int(found))
                        self.assertEqual(slack.call_count, int(mode == '--force-alert'))
                        self.assertEqual(log.call_count, int(mode == '--force-alert'))
                        if mode == '--force-alert':
                            self.assertEqual(log.call_args.kwargs['mode'], 'force-alert')
                            self.assertEqual(log.call_args.args[0], report(found))


if __name__ == '__main__':
    unittest.main()
