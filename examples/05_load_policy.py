"""Example 5: loading and validating policy files.

Policies live in files (JSON or YAML) so they can be reviewed and diffed
apart from the code. load_policy() reads either format and validates it
before returning; a malformed policy raises instead of silently gating
the wrong things.

Run from the repo root:  python3 examples/05_load_policy.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_gate import load_policy, validate_policy

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    for name in ("policies/policy.json", "policies/team_policy.yaml"):
        path = os.path.join(HERE, name)
        try:
            policy = load_policy(path)
        except ImportError as e:
            print("%-28s skipped: %s" % (name, e))
            continue
        print("%-28s OK: %d tools (%s)" % (name, len(policy),
                                           ", ".join(sorted(policy))))

    print()
    print("Validation catches mistakes early:")
    try:
        validate_policy({"run_shell": {"allowlist_commands": ["ls"]}})
    except ValueError as e:
        print("  unknown rule key ->", e)
    try:
        validate_policy({"send_email": {"allowed_recipients": ["([bad"]}})
    except ValueError as e:
        print("  bad regex      ->", e)
    try:
        validate_policy({"read_file": {"rate_limit": {"max_calls": 0,
                                                      "window_seconds": 60}}})
    except ValueError as e:
        print("  bad rate limit ->", e)


if __name__ == "__main__":
    main()
