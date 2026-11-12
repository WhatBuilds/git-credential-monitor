# Credential scan logging API

Implement this endpoint in your other project:

```http
POST /api/v1/credential-monitor/logs
Content-Type: application/json
Authorization: Bearer <configured-token>
Idempotency-Key: <scan-event-uuid>
```

Configured endpoint: `https://whatscripts.whatbytes.club/api/v1/credential-monitor/logs`.
The endpoint is hosted in the separate API project. Bearer authentication is optional on the client, but
configure a token if your endpoint requires it.

## Request body: five fields

| Field | Type | Meaning |
| --- | --- | --- |
| `user_name` | string | Configured employee name, falling back to the OS username. |
| `device` | string | Device hostname, for example `rahul-macbook`. OS and local username are also included in the log. |
| `status` | `pass` or `fail` | `pass` only when no credentials are found and all configured checks complete. Findings **or incomplete checks** produce `fail`; the log explains why. |
| `log` | string / database TEXT | Text equivalent of the Slack report: identity, coverage, findings, counts, incomplete checks and next steps. |
| `scanned_at` | ISO 8601 timestamp with timezone | Time the device performed the scan, not when a queued event reaches the server. |

Example (log shortened here; see [the full request example](examples/api-request.json)):

```json
{
  "user_name": "Rahul Sharma",
  "device": "rahul-macbook",
  "status": "fail",
  "log": "GitHub credential monitor\n\nCredentials found\n\nmacOS Keychain search list (metadata)\nGitHub-related credential entry present • Count: 4",
  "scanned_at": "2026-11-12T12:00:00+00:00"
}
```

The same text formatter builds Slack and API log content. The log uses Slack's
existing per-section limits and explicitly identifies omitted entries in large
reports. It is not a dump of credential values or raw Keychain metadata. Passing
scans have log text too, even though scheduled runs do not send them to Slack.

The wire body contains exactly these five fields. Event identity is in the
`Idempotency-Key` header, not an extra body column. API `fail` includes incomplete
checks so an incomplete scan cannot be stored as a pass. Scheduled Slack alerts
trigger for detected credentials or incomplete verification; both have API status `fail`.

## Server behavior

1. Authenticate the request if bearer authentication is enabled.
2. Require the five fields above and a UUID `Idempotency-Key`. Validate `status`
   against `pass`/`fail` and parse `scanned_at` as a timezone-aware timestamp.
3. Insert the row transactionally, using the header UUID as a unique event ID.
4. Return `201 Created` after the insert commits. On a retry of an existing event,
   return `200 OK` without inserting a duplicate row.
5. Return a non-2xx response if validation, authentication, or storage fails.
   The monitor retains the event and retries on a later scheduled or force-alert run.

Example success response (the monitor only checks the HTTP status):

```json
{
  "id": "941094d1-276f-4da1-b742-44fdd8e912da",
  "stored": true
}
```

Use a unique database constraint for idempotency; checking for a row and then
inserting without a constraint can create duplicates under concurrent requests.
You can return `409 Conflict` if an existing UUID is reused with a different body.
Do not redirect this endpoint: the monitor deliberately rejects redirects.

## Optional PostgreSQL table

There are five business columns, plus an event ID and server receipt timestamp:

```sql
CREATE TABLE credential_monitor_logs (
    id UUID PRIMARY KEY, -- from Idempotency-Key; preserve it on retries
    user_name TEXT NOT NULL,
    device TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pass', 'fail')),
    log TEXT NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX credential_monitor_logs_device_time
    ON credential_monitor_logs (device, scanned_at DESC);
```

Use parameterized SQL or your ORM to insert request values. Do not store the
Authorization header in this table.

## Monitor configuration

```json
{
  "logging_api_url": "https://whatscripts.whatbytes.club/api/v1/credential-monitor/logs",
  "logging_api_token": "YOUR_API_TOKEN"
}
```

Merge these fields into `config.json`. The token is an API token for your project,
not a GitHub credential. Then install/update the schedule:

```sh
python3 install_schedule.py --config config.json
```

On Windows, use `py -3` instead of `python3`. Each scheduled or `--force-alert` run queues an event
locally before delivery. Retries reuse its UUID, including when a response was
lost after the server committed the record. Do not use `scanned_at` or device name
alone as a unique key; multiple legitimate scans can share those values.
