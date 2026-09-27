# agent-policy-gate

A deny-by-default policy gate that sits between an AI agent's decisions and
its tools. Every tool call is checked against a policy written as plain data,
and every decision, allow or deny, is written to an audit log as a JSON line.

This is the companion code for the tutorial
**[Put a Policy Gate in Front of Your AI Agent's Tools](https://anushamukka.com/posts/put-a-policy-gate-in-front-of-your-ai-agent/)**
— the implementation there, packaged so you can run it and read the tests.

## The idea in thirty seconds

Agent tutorials show you how to define tools. They rarely show you how to
restrain them. This project puts a gate in the dispatch path:

```
model decision -> check_call(tool, args) -> allow/deny + reason -> tool runs (or not)
                                                        |
                                                  audit.log (JSON lines)
```

- **Policy as data** (`POLICY` dict): read it in one screen; change rules
  without touching logic. Anything not listed is denied. Deny by default.
- **One dispatch path**: `dispatch()` is the only way to reach a tool. New
  tools inherit the gate for free.
- **The gate never throws**: unknown tools and missing arguments produce a
  deny with a reason, not an exception.
- **Audit everything**: each decision lands in `audit.log` with a UTC
  timestamp, the tool, its args, the decision, and the human-readable reason.

## Prerequisites

- Python 3.10 or newer. No packages to install: standard library only,
  deliberately, so the gate is the easiest part of your agent to read.

## Run it

```bash
python3 policy_gate.py
```

You should see three `ALLOW` lines and four `DENY` lines, each with a reason,
followed by `wrote 7 decisions to audit.log`. Inspect the log:

```bash
cat audit.log
```

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

24 tests covering: prefix confinement (including the `/tmp/workevil`
sibling-prefix bypass), shell metacharacter blocking, command allowlisting,
recipient allowlisting, deny-by-default for unknown tools, the gate never
throwing on bad input, denied calls never reaching the tool, and the audit
log format.

## Layout

```
policy_gate.py            the gate: policy, check_call, dispatch, audit log, demo
tests/test_policy_gate.py the test suite (unittest, stdlib only)
requirements.txt          no third-party dependencies
```

## Where this breaks (from the tutorial)

- A policy cannot catch prompt injection smuggled inside otherwise-allowed
  arguments. The gate checks the envelope, not the letter.
- The regex blocklist is a second layer, not the defense; the command
  allowlist does the real work. If you find yourself writing ever-longer
  regexes, you need an argument parser, not a longer blocklist.
- High-stakes tools want a third decision, "needs human approval." Not built
  here; the most useful upgrade for a real deployment.
- Past about fifty lines of policy, graduate to a real policy language
  ([Rego](https://www.openpolicyagent.org/docs/)/[Open Policy Agent](https://www.openpolicyagent.org/)
  or [Cedar](https://www.cedarpolicy.com/)).

## License

MIT. See [LICENSE](LICENSE).
