#!/usr/bin/env python
"""
Python script to enforce conventional commits as a commit message Git hook.
"""

import re
import sys
from pathlib import Path
from subprocess import CalledProcessError, run
from typing import Literal, Set

VERSION = "0.1.4"
REMOTE_PATH = (
    "https://raw.githubusercontent.com/bpshaver/commit-msg.py/main/commit-msg.py"
)

COMMIT_REGEX = re.compile(r"^([a-z]+)(?:\(([a-z|_|\-|\/]+)\))?:(.*)$")

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
    msg: str, types: Set[str], scopes: Set[str], scope_required: bool
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


def git_root() -> Path:
    git_root = run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        check=True,
        text=True,
    )
    return Path(git_root.stdout[:-1])


def setup() -> int:
    print("-- SETTING UP COMMIT-MSG.PY", file=sys.stderr)
    # Check that we're in a Git repo
    try:
        _ = run(["git", "status"], capture_output=True, check=True)
    except CalledProcessError:
        print("commit-msg.py: not a git repository.", file=sys.stderr)
        return 1

    # Check if we're installing or if we're updating
    hook_path = git_root() / ".git/hooks/commit-msg"
    if hook_path.exists():
        return update(hook_path)
    else:
        return install(hook_path)


def update(hook_path: Path):
    print("-- UPDATING COMMIT-MSG.PY", file=sys.stderr)
    raise NotImplementedError


def install(hook_path: Path):
    print("-- INSTALLING COMMIT-MSG.PY", file=sys.stderr)
    # This script must write itself into a file but it can't use the __file__ variable
    # TODO: Figure out a better way to do this
    try:
        curl = run(
            ["curl", "-s", REMOTE_PATH], capture_output=True, check=True, text=True
        )
    except CalledProcessError:
        print(
            "commit-msg.py: error downloading commit-msg.py. Install manually.",
            file=sys.stderr,
        )
        return 1

    with hook_path.open("w") as f:
        f.write(curl.stdout)

    try:
        run(["chmod", "+x", hook_path], capture_output=True, check=True, text=True)
    except CalledProcessError:
        print(
            "commit-msg.py: error making .git/hooks/commit-msg executable.",
            file=sys.stderr,
        )
        return 1

    print("-- FINISHED INSTALLING COMMIT-MSG.PY", file=sys.stderr)
    print(hook_path, file=sys.stdout)
    return 0


def main() -> int:
    # Setup mode is triggered if the script is run via stdin
    if __file__ == "<stdin>":
        return setup()

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


# Unit Tests
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


def test_git_root() -> None:
    gr = git_root()

    assert gr.exists() and gr.name == "commit-msg.py"
