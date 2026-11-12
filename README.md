# GitHub credential presence monitor

A per-user scanner for WhatBytes. Detects GitHub-related credential entries and
common plaintext token locations. On macOS, a local dialog can delete explicitly
confirmed Keychain entries. Scanning is read-only; the monitor never executes a
credential helper, validates tokens against GitHub, or reports secret values. It is a credential-storage policy monitor, not a malware detector.

## Quick start

Requires Python 3.10+ and Git installed on the employee's device. Extract this
folder to a permanent location in the employee's profile. Do not run as root,
Administrator, SYSTEM or a different employee. Do not commit the real config.

On macOS/Ubuntu:

```sh
cp config.example.json config.json
chmod 600 config.json
```

On Windows PowerShell:

```powershell
Copy-Item config.example.json config.json
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls .\config.json /inheritance:r /grant:r "*$($sid):(F)"
```

Edit `config.json` locally using a text editor:

```json
{
  "employee": "",
  "slack_webhook": "PASTE_YOUR_SLACK_INCOMING_WEBHOOK_HERE",
  "github_hosts": [],
  "reminder_minutes": 15,
  "scan_interval_minutes": 1,
  "repositories": [],
  "extra_files": []
}
```

The `employee` field is optional. If omitted, null, empty or whitespace-only,
the report uses the current OS username (for example, `rahul`). A nonempty name
overrides this label. Run the scanner and installer as the employee so the
detected username and inspected credential stores belong to that person.

Create an Incoming Webhook for your chosen Slack channel and paste its HTTPS
URL into the config. No GitHub credential is needed to run this monitor. The
webhook itself is a Slack posting credential: protect the config and distribute
it privately. Each endpoint receives this posting capability; for stronger fleet
control, replace direct webhook delivery with an authenticated central collector.

First inspect the report without sending anything:

```sh
python3 monitor.py --config config.json --dry-run
```

Then send a deliberate enrollment/pilot report:

```sh
python3 monitor.py --config config.json --force-alert
```

On Windows, use `py -3` instead of `python3`. If Python opens the Microsoft Store,
install a real Python interpreter first. The scheduler records the absolute path
of the interpreter used to run the installer.

### Ubuntu dependency

The OS keyring adapter needs SecretStorage. With the Ubuntu system Python:

```sh
sudo apt-get install python3-secretstorage
```

Run the scanner as the logged-in employee, without sudo. A graphical Secret
Service provider and the employee's D-Bus session must be available. No keyring
is unlocked by the scanner. Missing dependencies, locked collections and timeouts
produce incomplete checks, not a clean result. macOS and Windows need no Python
packages beyond the standard library.

## Install the persistent background schedule

After reviewing the dry-run and receiving the pilot Slack message:

```sh
python3 install_schedule.py --config config.json
```

Windows:

```powershell
py -3 install_schedule.py --config config.json
```

This installs a persistent background schedule for the current user. It survives
restart and resumes when that user logs in; no terminal needs to stay open.
On macOS it runs at installation/login and every `scan_interval_minutes`
(default 1). `reminder_minutes` (default 15) controls repeat notifications for
unchanged findings, independently of scan frequency. Reminders are delivered on
the first scan after they become due. Re-run the installer after changing the
scan interval. Reminder changes take effect on the next scan.

Existing configs using `reminder_hours` remain supported with their original
duration; `reminder_minutes` takes precedence. The example and local config use
minutes. macOS uses a logged-in user LaunchAgent so dialogs and the user's Keychain
are accessible; it does not perform interactive cleanup before login.

This installs only for the current user:

| OS | Schedule | Behavior |
| --- | --- | --- |
| macOS | LaunchAgent `com.whatbytes.github-credential-monitor` | At user login/load, then every configured scan interval while the session runs |
| Ubuntu | systemd user service and timer of the same name | After user manager starts, then every configured scan interval |
| Windows | Task Scheduler task `WhatBytes GitHub Credential Monitor` | Every configured scan interval while the employee is logged on |

The folder, interpreter and config must stay at their installed locations.
Sleeping, offline or logged-out devices do not provide continuous coverage.
Delivery failures retry on the next scheduled run; no separate durable event
queue is included. Findings that disappear before a successful retry may be lost.
Do not edit config or move files while a scan is running.

To check the schedule:

```sh
# macOS
launchctl print "gui/$(id -u)/com.whatbytes.github-credential-monitor"

# Ubuntu
systemctl --user status com.whatbytes.github-credential-monitor.timer
journalctl --user -u com.whatbytes.github-credential-monitor.service
```

```powershell
# Windows
schtasks /Query /TN "WhatBytes GitHub Credential Monitor" /V /FO LIST
```

The installer captures PATH for macOS/Linux so it can find the existing Git
installation. Rerun it if the Python or Git installation changes. It does not
copy arbitrary token environment variables into the scheduler.

## What is checked

| Source | Method | Limit |
| --- | --- | --- |
| macOS file-based keychains in the user's search list | `security dump-keychain` metadata; never `-d`, `-g` or `-w` | Matches generic/internet password entries with GitHub-related service/server/label metadata; not all app-sandbox/iCloud/data-protection keychain items are visible |
| Windows Credential Manager | `CredEnumerateW`, inspect target names only | Windows allocates credential structures that can include blobs; code never accesses the blob fields. Other app vaults/DPAPI files are not covered |
| Ubuntu Secret Service | SecretStorage collections, labels and attributes | Never calls `get_secret()` or unlocks a store; standalone KDE Wallet, pass/GPG stores and other backends are not covered |
| Git plaintext files | `~/.git-credentials`, `$XDG_CONFIG_HOME/git/credentials` | Matches configured GitHub hosts and authentication components locally |
| netrc files | `~/.netrc` and `~/_netrc` | Flags password entries for GitHub hosts or a default host; a default-host entry requires review and might be unrelated |
| Git helper custom `store --file` | Inspect discoverable configured file | Relative user/system paths require a repository context. Complex shell/path expressions are not evaluated |
| GitHub CLI | Common `hosts.yml` locations, including `GH_CONFIG_DIR` visible to the process | Flags nonempty `oauth_token` fields, including nested users; conservative text inspection, not a full YAML parser |
| Git configuration | System/global, includes, plus configured repositories | Flags recognizable GitHub tokens, authenticated remote URLs and Authorization extraheaders; extraheaders may belong to another service and require review |
| Process environment | Presence of GH_TOKEN, GITHUB_TOKEN, GH_ENTERPRISE_TOKEN, GITHUB_ENTERPRISE_TOKEN | Only the scanner's inherited environment; presence does not establish persistence. Does not inspect other processes or all shell sessions |
| Additional files | Recognizable GitHub token patterns | Opt-in paths only; no recursive filesystem search, history, browser or process-memory scanning |

Keychain/credential manager entries are **potential stored credential entries**:
metadata alone does not establish whether a token is nonempty, valid, expired,
revoked or malicious. Broad GitHub-related labels can produce false positives.
The scanner intentionally does not use a token to find its owner, scopes or validity.

Set `github_hosts` to any GitHub Enterprise Server hostnames, without schemes or
paths. Add absolute repository paths to `repositories` to inspect their local Git
config and remote URLs. Add known `.env` or shell configuration file paths to
`extra_files` if you want the limited token-pattern check there. Windows JSON
paths need doubled backslashes or forward slashes.

Example additional settings:

```json
{
  "github_hosts": ["github.company.example"],
  "repositories": ["/Users/rahul/projects/client-api"],
  "extra_files": ["/Users/rahul/.zshrc", "/Users/rahul/projects/client-api/.env"]
}
```

These are fields to merge into the full config, not a replacement config. Raw
paths, entry labels, GitHub account names, token values, snippets and token hashes
are not sent. Numbered labels identify repositories/files by their position in
the locally held config. A local report includes the configured employee label
(or the current OS username when no label is configured),
hostname, OS username, OS, timestamp, fixed source labels, counts and coverage.
Employee identity is configured or derived from the local username; this is not
verified HR identity. Use managed enrollment if you need
trusted identity. Findings are policy alerts, not proof of compromise.

## Local macOS alerts

To open the cleanup dialog immediately without sending Slack or waiting for the
reminder interval, run:

```sh
python3 monitor.py --config config.json --local-alert
```

This explicit command also works when scheduled local alerts are disabled.
`--force-alert` bypasses both Slack and enabled local alert reminder suppression.


On macOS, detected findings show a dialog listing up to ten matching Keychain
entries and their accounts, with a **Delete listed entries** button. Clicking it
deletes only those exact items using macOS persistent item references. **Later**
or the 45-second timeout leaves them untouched. Additional entries are explicitly
excluded from the current deletion. The result dialog reports removal/failure
counts, and a fresh scan updates Slack even after partial deletion.

Names, accounts and item references stay local and in memory; no password values
are requested. macOS may require permission to remove protected entries. Deletion
may sign the user out; it does not revoke tokens on GitHub, run CLI logout, or
remove credentials stored in files/environment variables. If no removable Keychain
entries are found, the dialog provides manual guidance.

A logged-in graphical session is required. Set `"local_alerts": false` in config
to disable local dialogs and cleanup. Other operating systems use Slack only.

Local alerts use their own `monitor-local-state.json` beside the config, so Slack
failures do not cause repeated dialogs. Changed findings trigger a prompt;
unchanged findings follow `reminder_minutes` (15 by default). Incomplete checks
alone do not trigger a dialog. Dry runs never show dialogs or change state.
Local alert failures do not prevent Slack delivery. Identical check warnings
are collapsed by source, status and reason; custom helpers remain unexecuted.

## Slack behavior and state

Reports use a status heading, compact employee/device fields, and separate findings
and incomplete-check sections. Each finding shows its source, type and count.
Long reports show up to 18 entries per section with an explicit omitted count;
use `--dry-run` locally for full details. Dynamic values render as plain text,
so employee/device names cannot trigger Slack mentions.

Run `--dry-run` to inspect JSON without network requests or state changes.
Normal runs send one grouped report when findings/incomplete checks change, a
reminder after 15 minutes (configurable), and a resolution when previously reported
issues disappear and the configured checks complete. An initially empty report
is silent unless `--force-alert` is supplied. Identical entries are aggregated by
source/type/count: replacing a token at the same location is not a new finding.

Incomplete scans generate alerts too. New findings can be delivered alongside an
incomplete check. There is never a claim that the whole device is clean.

`monitor-state.json`, beside the config, stores only a report-structure digest,
last acknowledged notification time and previous issue status. It contains no
token values or hashes derived from token values. Delete it to reset suppression.
The next scan may send a fresh alert. Avoid overlapping manual invocations using
the same config; scheduled instances use the OS scheduler's single-job behavior.

For manual runs, `GITHUB_MONITOR_SLACK_WEBHOOK` can override the config webhook.
The schedule installer requires a config webhook because desktop schedulers
generally do not inherit an interactive terminal's environment.

Exit codes: `0` configured checks completed without findings, `1` findings,
`2` incomplete coverage (possibly with findings), `3` configuration/delivery
failure. Task Scheduler may show `0x1` or `0x2` for a successful scan with findings
or incomplete coverage. systemd treats exit codes 1 and 2 as expected.

## Employee remediation / Git without persistent credential storage

Review the reported source locally and remove its stored GitHub entries using
Keychain Access, Windows Credential Manager, Ubuntu's Passwords and Keys, or the
application that created them. Keychain entries can also be deleted through the local macOS confirmation dialog. Do not paste
tokens into Slack or into shell commands. Never email credential-store exports.

For a single HTTPS operation, bypass all configured credential helpers with an
empty helper setting and enter the PAT interactively at Git's password prompt:

```sh
git -c credential.helper= pull
git -c credential.helper= push
```

Run inside the appropriate repository. This uses the existing remote. Check that
the remote itself contains no embedded token and no Authorization extraheader is
configured; these commands do not remove those or existing stored credentials.
Use a terminal without a token-returning `GIT_ASKPASS`/`SSH_ASKPASS` integration.
If your IDE injects an authentication prompt/helper, use a plain terminal and
review its Git authentication settings. For an explicit terminal-only prompt on
macOS/Ubuntu, this per-command form also clears askpass hooks:

```sh
env -u GIT_ASKPASS -u SSH_ASKPASS GIT_TERMINAL_PROMPT=1 git -c core.askPass= -c credential.helper= pull
```

To apply a no-helper override to all GitHub.com HTTPS operations for the current
user (a configuration change, not performed by the monitor):

```sh
git config --global --replace-all credential.https://github.com.helper ""
```

Repository-local, conditional or application-supplied configuration may override
this. Test actual pull/push behavior in your environment; the per-command empty
helper setting is the clearest check. Do not rely on a global `--unset` alone:
another scope can still provide a helper. Avoid `gh auth login` if the company
policy forbids persisted GitHub CLI credentials. SSH authentication is a separate
policy and is outside this monitor's coverage.

Removing a credential locally does not revoke an already stolen copy. For an
affected employee, revoke/rotate exposed PAT/OAuth credentials and investigate
the device before entering new credentials. Manual PAT entry reduces persistent
credential storage; malware in the employee's session can still capture entered
credentials or manipulate Git. This tool does not prevent all future attacks.

## Uninstall

macOS:

```sh
launchctl bootout "gui/$(id -u)/com.whatbytes.github-credential-monitor"
rm ~/Library/LaunchAgents/com.whatbytes.github-credential-monitor.plist
```

Ubuntu:

```sh
systemctl --user disable --now com.whatbytes.github-credential-monitor.timer
rm ~/.config/systemd/user/com.whatbytes.github-credential-monitor.service
rm ~/.config/systemd/user/com.whatbytes.github-credential-monitor.timer
systemctl --user daemon-reload
```

Windows PowerShell:

```powershell
schtasks /Delete /TN "WhatBytes GitHub Credential Monitor" /F
```

After stopping the schedule, delete the extracted folder and local config if no
longer needed. Rotate the Slack webhook if an endpoint or config is compromised.

## Validation and rollout

Run the bundled synthetic tests from this folder:

```sh
python3 -m unittest -v
```

Fourteen automated checks cover optional employee-name fallback, host matching, absence of raw tokens/paths in
findings, GitHub CLI and netrc plaintext detection, unreadable/oversized files, helper
non-execution, macOS metadata parsing, alert suppression and resolution, failed
delivery retry state, dry-run isolation, webhook allowlisting, and Linux timeout
handling. These tests use fixtures/mocks; they do not establish native OS API
compatibility or Slack delivery.

Pilot with one device per OS before fleet rollout: inspect dry-run coverage,
create a harmless dummy GitHub-labelled store entry through the native UI,
confirm the presence alert, remove the dummy entry, confirm resolution, and test
after login/reboot. Use dummy values only, never production tokens in tests.
Check locked-store/offline behavior and scheduler permissions. Native macOS and
Windows behavior and live Slack delivery were not verified in the build
environment. Linux Secret Service integration also needs an employee-session
pilot. Some endpoint products may flag keychain metadata enumeration; handle
that through your existing managed deployment process.

This is not tamper resistant and has no central heartbeat inventory. A stopped
or modified agent can become silent. For reliable organization-wide coverage,
deploy via your endpoint management system and independently monitor task/agent
health.

## Reference documentation

- https://git-scm.com/docs/gitcredentials
- https://git-scm.com/docs/git-credential-store
- https://cli.github.com/manual/gh_auth_login
- https://cli.github.com/manual/gh_help_environment
- https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/configuration.md
- https://secretstorage.readthedocs.io/en/latest/collection.html
- https://secretstorage.readthedocs.io/en/latest/item.html
- https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew
- https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
- https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
