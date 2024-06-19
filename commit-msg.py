#!/usr/bin/env python
"""
Python script to enforce conventional commits as a commit message Git hook.

Move this script to `.git/hooks/commit-msg` and customize the constants `TYPES`,
`SCOPES`, and `SCOPE_REQUIRED` according to your project's needs.

Gone are the days of scrolling `git log` to check what scopes you have used in the past
in order to use the "correct" scope for your Conventional Commits.

To find the short list of your already used types and scopes (assuming your Git log) is
complient with conventional commits, try this:

```bash
git log --no-merges --oneline | awk ' { print $2 } ' | sort | uniq
```
"""

import re
import sys
from typing import Literal

VERSION = "0.1.1"

COMMIT_REGEX = re.compile(r"^([a-z]+)(?:\(([a-z|_|-|\/]+)\))?:(.*)$")

TYPES = {"fix", "feat", "docs", "style", "refactor", "test", "chore", "revert"}
SCOPES = {"deps", "ci/cd", "packaging", "python", "git"}
SCOPE_REQUIRED = True

# fmt: off
validation_result = Literal[
	"passing",
	"failing", 
	"type_failing", 
	"scope_failing", 
    "scope_required"
]
# fmt: on


def validate(
    msg: str, types: set[str], scopes: set[str], scope_required: bool
) -> validation_result:
    match = re.match(COMMIT_REGEX, msg)
    if not match:
        return "failing"
    type, scope, msg = match.groups()
    if type not in types:
        return "type_failing"
    if not scope and scope_required:
        return "scope_required"
    if scope and scope not in scopes:
        return "scope_failing"
    return "passing"


def test_validate() -> None:
    assert validate("fix: foobar", {"fix"}, set(), False) == "passing"
    assert validate("fix: foobar", {"feat"}, set(), False) == "type_failing"
    assert validate("feat: foobar", {"feat"}, set(), True) == "scope_required"
    assert validate("feat(foobar): foobar", {"feat"}, {"api"}, False) == "scope_failing"
    assert validate("fix -- foobar", {"feat"}, set(), False) == "failing"
    assert validate("Feat: foobar", {"feat"}, set(), True) == "failing"
    assert validate("feat(FooBar): foobar", {"feat"}, {"FooBar"}, True) == "failing"
    assert (
        validate(
            "feat(ci/cd): added ruff format --check to ci/cd",
            {"feat"},
            {"ci/cd"},
            scope_required=True,
        )
        == "passing"
    )


def main() -> int:
    # Check script is being called correctly
    if len(sys.argv) != 2:
        print(".git/hooks/commit-msg: Unexpected number of arguments.", file=sys.stderr)
        return 1

    # Get commit message
    try:
        with open(sys.argv[1], "r") as f:
            msg = f.read().strip()
    except FileNotFoundError:
        print(".git/hooks/commit-msg: File not found.", file=sys.stderr)
        return 1

    # Validate commit message
    validation = validate(msg, TYPES, SCOPES, SCOPE_REQUIRED)
    if validation == "passing":
        return 0
    if validation == "failing":
        print(
            ".git/hooks/commit-msg: Bad commit format. Please use `type(scope): description`",
            file=sys.stderr,
        )
        return 1
    if validation == "type_failing":
        print(
            f".git/hooks/commit-msg: Bad commit msg type. Allowed types are {TYPES}",
            file=sys.stderr,
        )
        return 1
    if validation == "scope_failing":
        print(
            f".git/hooks/commit-msg: Bad commit msg scope. Allowed scopes are {SCOPES}",
            file=sys.stderr,
        )
        return 1
    if validation == "scope_required":
        print(
            f".git/hooks/commit-msg: A scope is required. Allowed scopes are {SCOPES}",
            file=sys.stderr,
        )
        return 1
    raise NotImplementedError


if __name__ == "__main__":
    exit(main())
