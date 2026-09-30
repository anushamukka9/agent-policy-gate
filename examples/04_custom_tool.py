"""Example 4: gating your own tool functions.

The @gated decorator registers a plain function as a tool and returns a
wrapper whose calls go through dispatch(). Before the tool has a policy
entry it is denied by default; after register_tool() adds one, calls run.

Run from the repo root:  python3 examples/04_custom_tool.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_gate import gated, register_tool


def summarize_file(args):
    return "summary of %s (stubbed)" % args["path"]


gated_summarize = gated("summarize_file")(summarize_file)

print("Before a policy entry exists (deny by default):")
print("  ->", gated_summarize({"path": "/tmp/work/notes.txt"}))

register_tool(
    "summarize_file",
    summarize_file,
    {"allowed": True, "required_args": ["path"]},
)

print()
print("After the policy entry is registered:")
print("  ->", gated_summarize({"path": "/tmp/work/notes.txt"}))
print("  ->", gated_summarize({}))
