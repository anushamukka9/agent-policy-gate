# agent-policy-gate

A deny-by-default policy gate that sits between an AI agent's decisions and
its tools. Every tool call is checked against a policy written as plain
data, each check returns one of three decisions (allow, deny, or
needs-approval), and every decision, allow or deny, is written to an audit
log as a JSON line.

This is the companion code for the tutorial
**[Put a Policy Gate in Front of Your AI Agent's Tools](https://anushamukka.com/posts/put-a-policy-gate-in-front-of-your-ai-agent/)**,
extended past the tutorial: approval flows, rate limits, YAML/JSON policy
files, and a decorator for gating your own tool functions.

## The idea in thirty seconds

Agent tutorials show you how to define tools. They rarely show you how to
restrain them. This project puts a gate in the dispatch path:

```
model decision -> evaluate(tool, args) -> allow / deny / needs_approval (+ reason)
                                              |                |
                                         tool runs (or not)   approver callback
                                              |                resolves it
                                         audit.log (JSON lines)
```

- **Policy as data** (`POLICY` dict, or a JSON/YAML file): read it in one
  screen; change rules without touching logic. Anything not listed is
  denied. Deny by default.
- **Three decisions, not two**: `needs_approval` covers tools that are too
  dangerous for a yes/no rule and too useful to ban. The approver callback
  resolves it; with no approver the call is denied, because failing open
  would make approval meaningless.
- **One dispatch path**: `dispatch()` is the only way to reach a tool. New
  tools inherit the gate for free.
- **The gate never throws**: unknown tools, missing arguments, and bad
  argument types produce a deny with a reason, not an exception.
- **Audit everything**: each decision lands in `audit.log` with a UTC
  timestamp, the tool, its args, the decision, and the human-readable
  reason.
- **Rate limits**: per-tool rolling-window budgets; only calls that would
  actually run consume budget.

## Prerequisites

- Python 3.10 or newer.
- Nothing to install for the gate itself: standard library only,
  deliberately, so the gate is the easiest part of your agent to read.
- PyYAML only if you want to load `.yaml`/`.yml` policy files
  (`pip install pyyaml`). JSON policy files need nothing.

## Quickstart

```bash
python3 policy_gate.py
```

You should see three `ALLOW` lines and four `DENY` lines, each with a
reason, followed by `wrote 7 decisions to audit.log`. Inspect the log:

```bash
cat audit.log
```

Then try the examples:

```bash
python3 examples/01_allowed_vs_denied.py   # allowlists vs denylists vs deny-by-default
python3 examples/02_approval_flow.py       # the approval flow (needs PyYAML)
python3 examples/03_rate_limits.py         # rolling-window rate limits
python3 examples/04_custom_tool.py         # gate your own functions with @gated
python3 examples/05_load_policy.py         # load and validate JSON/YAML policies
```

## The policy, as data

```python
POLICY = {
    "read_file": {
        "allowed_prefixes": ["/tmp/work/"],
        "blocked_paths": ["/tmp/work/secrets/"],   # denylist beats allowlist
    },
    "run_shell": {
        "allowed_commands": ["ls", "cat", "wc", "head", "tail", "grep"],
        "blocked_patterns": [r"\brm\s+-rf\b", r";", r"&&", r"\|\|", r"`", r"\$\("],
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
```

Rule keys and what they do:

| Rule | Meaning |
|---|---|
| `allowed_prefixes` | Path prefixes the tool may touch. |
| `blocked_paths` | Paths denied even inside an allowed prefix. The denylist wins. |
| `allowed_commands` | First words of shell commands that may run. |
| `blocked_patterns` | Regexes matched against the command (or, for generic tools, every string arg). A hit denies. |
| `max_command_length` | Longest shell command accepted. |
| `allowed_recipients` | Regexes matched against the `to` address. A hit allows. |
| `blocked_recipients` | Regexes matched against the `to` address. A hit denies, even on an allowed domain. |
| `required_args` | Argument names that must be present and non-empty. |
| `needs_approval` | `true`: every call to this tool returns `needs_approval`. |
| `approval_patterns` | Regexes matched against string args. A hit returns `needs_approval`. |
| `rate_limit` | `{"max_calls": N, "window_seconds": S}`: at most N allowed calls per rolling window. |
| `allowed` | `true`: for tools with no bespoke rule logic, permit the call (still subject to `required_args`, approval, and rate limits). |

Deny rules are checked before allow rules, so a blocked path or pattern
always wins. A call that fails every rule is denied with the reason
`no rule matched`.

## API reference

```python
from policy_gate import (
    evaluate, check_call, dispatch, gated, register_tool,
    load_policy, validate_policy, set_policy,
    reset_rate_limits, flush_audit, Decision,
)

# Three-state decision. Never throws.
d = evaluate("send_email", {"to": "teammate@internal.example.com"})
d.decision   # "allow" | "deny" | "needs_approval"
d.reason     # "recipient domain is allowlisted"

# Legacy boolean form. Approval maps to allowed=False (fail closed).
allowed, reason = check_call("send_email", {"to": "..."})

# The single choke point. Returns the tool's result, or "DENIED: <reason>".
dispatch("read_file", {"path": "/tmp/work/notes.txt"})

# Approval: the callback takes the Decision and returns True/False.
dispatch("publish_release", {"version": "2.4.0"},
         approver=lambda decision: ask_a_human(decision))

# Gate a plain function. Registers it and returns a wrapper that goes
# through dispatch(). Without a policy entry it is denied by default.
def summarize_file(args):
    return summarize(args["path"])

gated_summarize = gated("summarize_file")(summarize_file)
register_tool("summarize_file", summarize_file, {"allowed": True})

# Register a tool with its policy entry (validated before storing).
register_tool("summarize_file", summarize_file,
              {"allowed": True, "required_args": ["path"]})

# Policies from files: JSON needs nothing, YAML needs PyYAML.
policy = load_policy("examples/policies/team_policy.yaml")
validate_policy(policy)   # raises ValueError on anything malformed
set_policy(policy)        # swap the live policy (validated first)

# Rate-limit bookkeeping.
reset_rate_limits()

# Audit log: a list of dicts; flush_audit() writes JSON lines.
flush_audit("audit.log")
```

## Examples

The `examples/` directory holds runnable scripts, each self-contained:

- `01_allowed_vs_denied.py` - a batch of calls showing allowlists,
  denylists, and deny-by-default for unknown tools.
- `02_approval_flow.py` - loads `policies/team_policy.yaml` and shows an
  approval granted, an approval refused, and the fail-closed default when
  no approver is configured.
- `03_rate_limits.py` - a 3-calls-per-2-seconds budget: three allows, two
  denials, then the budget refills.
- `04_custom_tool.py` - the `@gated` decorator: denied before a policy
  entry exists, allowed after.
- `05_load_policy.py` - loading JSON and YAML policies, and the
  validation errors you get from a malformed policy.

`examples/policies/` holds a sample `team_policy.yaml` and a smaller
`policy.json` you can copy as a starting point.

## Run the tests

```bash
python3 -m pytest
```

66 tests plus 9 subtests covering: prefix confinement (including the
`/tmp/workevil` sibling-prefix bypass), shell metacharacter blocking,
command allowlisting, recipient allowlisting, blocked paths and
recipients, max command length, required arguments, deny-by-default for
unknown tools, the gate never throwing on bad input, denied calls never
reaching the tool, the three-state decision, the approval flow (granted,
refused, and no-approver fail-closed), rate-limit budgets and refills,
JSON/YAML policy loading, policy validation errors, the `@gated`
decorator, and the audit log format. (`python3 -m unittest discover -s
tests` works too.)

## Layout

```
policy_gate.py            the gate: policy, evaluate, dispatch, decorator,
                          rate limits, audit log, policy loading, demo
examples/                 runnable scripts (01-05) plus policies/
tests/test_policy_gate.py the original tutorial test suite (unittest)
tests/test_policy_ext.py  tests for the extended features (unittest)
requirements.txt          optional dependencies (PyYAML for YAML policies)
```

## Production notes

Honest limits, from building this:

- The gate checks the envelope, not the letter. It cannot catch prompt
  injection smuggled inside otherwise-allowed arguments.
- The regex blocklist is a second layer, not the defense; the command
  allowlist does the real work. If you find yourself writing ever-longer
  regexes, you need an argument parser, not a longer blocklist.
- Rate limits are per-process memory. Several agent replicas need a
  shared store (Redis, a database row) instead of the in-memory dict.
- Approval is only as good as the approver callback. The default, no
  approver, denies: that is the safe choice, not a missing feature.
- The audit log records decisions, not intent. Keep the reasons specific;
  "denied" tells you nothing six weeks later.
- Past about fifty lines of policy, graduate to a real policy language
  ([Rego](https://www.openpolicyagent.org/docs/)/[Open Policy Agent](https://www.openpolicyagent.org/)
  or [Cedar](https://www.cedarpolicy.com/)).

## License

MIT. See [LICENSE](LICENSE).
