"""Example 2: the approval flow.

Loads a YAML policy where sending email always needs approval and
publishing a release always needs approval, then shows the three ways
an approval decision resolves: approved, denied by the operator, and
denied because nobody is there to approve.

The approver here is a canned callback. In a real agent it would page
a human (a chat prompt, a web UI button, a CLI confirm). The gate does
not care how the answer arrives, only that it is explicit.

Run from the repo root:  python3 examples/02_approval_flow.py
Needs PyYAML for the YAML policy:  pip install pyyaml
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_gate import dispatch, evaluate, load_policy, register_tool, set_policy

HERE = os.path.dirname(os.path.abspath(__file__))


def publish_release(args):
    return "released version %s (stubbed)" % args["version"]


def main():
    set_policy(load_policy(os.path.join(HERE, "policies", "team_policy.yaml")))
    register_tool("publish_release", publish_release)

    print("Decision first, execution second:")
    d = evaluate("publish_release", {"version": "2.4.0"})
    print("  evaluate ->", d.decision, "|", d.reason)

    def approver(decision):
        print("  approval requested: %s" % decision.reason)
        # A real approver would ask a human. This one rubber-stamps
        # emails and refuses releases, to show both outcomes.
        return decision.tool != "publish_release"

    print()
    print("Approved by the operator:")
    print("  ->", dispatch("send_email", {"to": "boss@internal.example.com",
                                          "subject": "weekly notes"},
                           approver=approver))
    print()
    print("Denied by the operator:")
    print("  ->", dispatch("publish_release", {"version": "2.4.0"},
                           approver=approver))
    print()
    print("No approver configured (fails closed):")
    print("  ->", dispatch("publish_release", {"version": "2.4.1"}))


if __name__ == "__main__":
    main()
