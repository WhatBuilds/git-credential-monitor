"""Shared Slack layout and API log text; no delivery or platform dependencies."""

def slack_payload(report, resolved=False):
    """Build a bounded Block Kit report; dynamic values remain plain text."""
    findings = report["findings"]
    incomplete = [c for c in report["checks"] if c["status"] == "incomplete"]
    helper_reasons = {
        "custom credential helper is configured; not executed",
        "GitHub CLI credential helper is configured; not executed",
    }
    helper_checks = [c for c in incomplete if c.get("reason") in helper_reasons]
    helper_only = bool(incomplete) and len(helper_checks) == len(incomplete)
    gh_helper = any(c.get("reason") == "GitHub CLI credential helper is configured; not executed"
                    for c in helper_checks)
    if findings:
        status = "⚠️ Credentials found"
    elif helper_only:
        status = "⚠️ Verification failed — credentials may remain"
    elif incomplete:
        status = "⚠️ Verification failed — checks incomplete"
    elif resolved:
        status = "✅ Findings cleared in configured checks"
    else:
        status = "✅ No findings in configured checks"
    summary = (f"{len(findings)} finding groups • {len(helper_checks)} unverified Git helper checks"
               if helper_only else f"{len(findings)} finding groups • {len(incomplete)} checks needing attention")
    coverage = "Limited: configured Git helpers were not executed" if helper_only else report["coverage"]

    def plain(value, limit=3000):
        value = str(value)
        if len(value) > limit:
            value = value[:limit - 1] + "…"
        return {"type": "plain_text", "text": value, "emoji": False}

    def section(value):
        return {"type": "section", "text": plain(value)}

    blocks = [
        {"type": "header", "text": plain("GitHub credential monitor", 150)},
        section(f"{status}\n{summary}"),
        {"type": "section", "fields": [
            plain(f"{label}\n{coverage if key == 'coverage' else report[key]}", 2000)
            for label, key in (("Employee", "employee"), ("Device", "device"),
                               ("Local user", "local_user"), ("OS", "os"),
                               ("Time (UTC)", "timestamp"), ("Coverage", "coverage"))
        ]},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": "*Findings*"}},
    ]
    # Reserve room for both categories and the footer within Slack's 50 blocks.
    for finding in findings[:18]:
        blocks.append(section(f"{finding['source']}\n{finding['kind']} • Count: {finding['count']}"))
    if len(findings) > 18:
        blocks.append(section(f"{len(findings) - 18} additional finding groups omitted. Review the local dry-run report for full details."))
    if not findings:
        blocks.append(section(
            "No credential matches were confirmed in the inspected locations, but verification is incomplete. "
            "This result is FAIL; stored credentials may still remain."
            if incomplete else
            "No matching credentials found in inspected locations; this is not a device safety verdict."))
    if incomplete:
        blocks.extend([
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "*Git configuration to review*" if helper_only else "*What needs attention*"}},
        ])
        for check in incomplete[:18]:
            reason = check.get('reason', 'Check could not be completed')
            if reason in helper_reasons:
                label = "GitHub CLI authentication helper" if reason.startswith("GitHub CLI") else "Git authentication helper"
                reason = (f"{label} is still configured and was not executed. "
                          "The monitor cannot verify whether it can supply credentials. "
                          "Treat this as a failed verification until the remaining configuration and credential stores are reviewed.")
            blocks.append(section(f"{check['source']}\n{reason}"))
        if len(incomplete) > 18:
            blocks.append(section(f"{len(incomplete) - 18} additional incomplete checks omitted. Review the local dry-run report for full details."))
    if findings:
        blocks.append(section("Next step: Remove stored entries locally according to company policy."))
    if helper_checks:
        guidance = ("gh auth logout handles GitHub CLI authentication; it does not establish that credentials "
                    "saved by other apps have been removed. " if gh_helper else
                    "Removing Git helper configuration does not establish that saved credentials have been removed. ")
        if report["os"] == "Darwin":
            guidance += ("Review GitHub-related Keychain entries, including those saved by Fork and other Git clients. "
                         "Remove the intended entries using the monitor's confirmation dialog or Keychain Access. ")
        else:
            guidance += "Review credentials saved by other Git clients in the OS credential store as well. "
        guidance += ("Remove unneeded helper settings separately, then rerun with --dry-run. "
                     "Deleting helper settings alone does not delete or revoke tokens.")
        blocks.append(section("What you can do\n" + guidance))
    if incomplete and not helper_only:
        blocks.append(section("Next step: Review the checks needing attention locally and rerun the monitor."))
    blocks.append({"type": "context", "elements": [plain("No credential values collected in this report.", 2000)]})
    # Only fixed labels and numeric totals enter the notification fallback.
    return {"text": f"GitHub credential monitor — {status}. {summary}",
            "blocks": blocks, "unfurl_links": False, "unfurl_media": False}



def report_log(report):
    """Text equivalent of the Slack report, including its visible size limits."""
    sections = []
    for block in slack_payload(report)["blocks"]:
        text = block.get("text")
        if text:
            sections.append(text["text"].strip("*") if text["type"] == "mrkdwn" else text["text"])
        sections.extend(field["text"] for field in block.get("fields", []))
        sections.extend(element["text"] for element in block.get("elements", []))
    return "\n\n".join(sections)
