"""Durable, sanitized scheduled-scan logging. No credential values are accepted."""
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit
import urllib.request
import uuid
from report_format import report_log


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_api(config):
    endpoint = config.get('logging_api_url', '')
    url = urlsplit(endpoint)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment:
        raise ValueError('logging_api_url must be an HTTPS endpoint without embedded credentials')
    token = config.get('logging_api_token', '')
    if not isinstance(token, str) or '\r' in token or '\n' in token:
        raise ValueError('invalid logging API token')
    return endpoint


def outcome(report):
    if report['findings']:
        return 'fail'
    if report['coverage'] == 'incomplete':
        return 'incomplete'
    return 'pass'


def event_for(report):
    # Explicit allowlist keeps future local-only metadata out of remote logging.
    inventory = {key: report[key] for key in (
        'timestamp', 'employee', 'device', 'local_user', 'os', 'coverage')}
    inventory['findings'] = [{key: f[key] for key in ('source', 'kind', 'count')}
                             for f in report['findings']]
    inventory['checks'] = [{key: c[key] for key in ('source', 'status', 'reason') if key in c}
                           for c in report['checks']]
    return dict(schema_version=1, event_id=str(uuid.uuid4()), mode='scheduled',
                outcome=outcome(report), report=inventory)


def api_payload(event):
    """Five business fields; the stable event UUID travels in the HTTP header."""
    report = event['report']
    return {
        'user_name': report['employee'],
        'device': report['device'],
        'status': 'pass' if outcome(report) == 'pass' else 'fail',
        'log': report_log(report),
        'scanned_at': report['timestamp'],
    }


def post_event(config, event):
    endpoint = validate_api(config)
    headers = {'Content-Type': 'application/json', 'Idempotency-Key': event['event_id']}
    token = os.environ.get('GITHUB_MONITOR_API_TOKEN') or config.get('logging_api_token')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(endpoint, data=json.dumps(api_payload(event)).encode(), headers=headers, method='POST')
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError('Logging API did not acknowledge event')


def log_scan(report, config, directory):
    """Queue every scan, then retry up to five oldest events. Failures stay queued."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    event = event_for(report)
    path = directory / f"{time.time_ns():020d}-{event['event_id']}.json"
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(event, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    validate_api(config)
    for pending in sorted(directory.glob('*.json'))[:5]:
        post_event(config, json.loads(pending.read_text()))
        pending.unlink()
