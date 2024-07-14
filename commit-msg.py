#!/usr/bin/env python
"""
Python script to enforce conventional commits as a commit message Git hook.

commit-msg.py
"""

import re
import sys
from pathlib import Path
from subprocess import CalledProcessError, run
from typing import Literal, Set

VERSION = "0.2.2"
REMOTE_PATH = (
    "https://raw.githubusercontent.com/bpshaver/commit-msg.py/main/commit-msg.py"
)

COMMIT_REGEX = re.compile(r"^([a-z]+)(?:\(([a-z|_|\-|\/]+)\))?:(.*)$")

## User Config
## Don't remove type annotations

TYPES: Set[str] = {
    "fix",
    "feat",
    "docs",
    "style",
    "refactor",
    "test",
    "chore",
    "revert",
}
SCOPES: Set[str] = {"deps", "ci/cd", "packaging", "python", "git"}
SCOPE_REQUIRED: bool = True

##
##

# fmt: off
validation_result = Literal[
	"passing",
	"failing", 
	"type_failing", 
	"scope_failing", 
    "scope_required"
]
# fmt: on


def debug(msg: str) -> None:
    if not msg.endswith("."):
        msg = msg + "."
    print(
        f"-- {msg.upper()}",
        file=sys.stderr,
    )


def error(msg: str) -> None:
    if not msg.endswith("."):
        msg = msg + "."
    print(
        f".git/hooks/commit-msg: {msg}",
        file=sys.stderr,
    )


def setup_error(msg: str) -> None:
    if not msg.endswith("."):
        msg = msg + "."
    print(
        f"commit-msg.py: {msg}",
        file=sys.stderr,
    )


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
    debug("SETTING UP COMMIT-MSG.PY")
    # Check that we're in a Git repo
    try:
        _ = run(["git", "status"], capture_output=True, check=True)
    except CalledProcessError:
        setup_error("not a git repository. Set up manually.")
        return 1

    # Check if we're installing or if we're updating
    hook_path = git_root() / ".git/hooks/commit-msg"
    if hook_path.exists():
        return update(hook_path)
    else:
        return install(hook_path)


def get_source() -> str:
    # This script must write itself into a file but it can't use the __file__ variable
    curl = run(["curl", "-s", REMOTE_PATH], capture_output=True, check=True, text=True)
    return curl.stdout


def versions_compatible(current_contents: str, source: str) -> bool:
    debug("CHECKING VERSION COMPATIBILITY")
    if "\ncommit-msg.py\n" not in current_contents:
        setup_error("it looks like you're not running commit-msg.py. Update manually.")
        return False
    else:
        version_ptn = r'\nVERSION = "((\d+)\.(\d+)\.(\d+))"\n'
        old_version = re.search(version_ptn, current_contents)
        new_version = re.search(version_ptn, source)

        if not old_version:
            setup_error(
                "unable to retrieve current version of commit-msg.py. Update manually.",
            )
            return False
        if not new_version:
            setup_error(
                "unable to retrieve new version of commit-msg.py. Update manually.",
            )
            return False

        old_version_str, old_major, old_minor, old_patch = old_version.groups()
        new_version_str, new_major, new_minor, new_patch = new_version.groups()
        if new_version_str == old_version_str:
            setup_error("already up-to-date.")
            return False
        elif new_major == old_major and (
            new_minor > old_minor or (new_minor == old_minor and new_patch > old_patch)
        ):
            return True
        else:
            setup_error(
                f"new version {old_version_str} not compatible with existing version {new_version_str}. Update manually"
            )
            return False


def swap_out_config(current_contents: str, source: str) -> str:
    debug("PRESERVING CONFIGURATION LINES")
    config_ptn = r"(TYPES: +Set\[str\] += +{[^}]+}\n+SCOPES: +Set\[str\] += +{[^}]*}\n+SCOPE_REQUIRED: +bool += +True|False)"
    match1 = re.search(config_ptn, current_contents)
    match2 = re.search(config_ptn, source)
    if match1 is not None and match2 is not None:
        (current_config,) = match1.groups()
        (source_config,) = match2.groups()
        source = source.replace(source_config, current_config)
        return source
    else:
        setup_error("error getting config lines to swap over. Update manually.")
        return ""


def update(hook_path: Path) -> int:
    debug("UPDATING COMMIT-MSG.PY")

    try:
        source = get_source()
    except CalledProcessError:
        setup_error(
            "error downloading commit-msg.py. Update manually.",
        )
        return 1

    with hook_path.open() as f:
        current_contents = f.read()
    if versions_compatible(current_contents, source):
        new_source = swap_out_config(current_contents, source)
        if new_source:
            with hook_path.open("w") as f:
                f.write(new_source)
        else:
            return 1
    else:
        return 1

    debug("FINISHED UPDATING COMMIT-MSG.PY")
    print(hook_path, file=sys.stdout)
    return 0


def existing_scopes() -> Set[str]:
    scopes = set()
    result = run(
        "git log --no-merges --oneline".split(), capture_output=True, check=True
    )
    for line in result.stdout.decode().split("\n"):
        match = re.match(r"[a-z|0-9]{7} [a-z]+\(([a-z|_|\-|\/]+)\): ", line)
        if match:
            scopes.add(match.group(1))
    return scopes


def install(hook_path: Path) -> int:
    debug("INSTALLING COMMIT-MSG.PY")

    try:
        source = get_source()
    except CalledProcessError:
        setup_error("error downloading commit-msg.py. Install manually.")

    debug("INFERRING EXISTING SCOPES")
    scopes = existing_scopes()
    if not scopes:
        scopes_str = "SCOPES: Set[str] = set()"
    else:
        scopes_str = (
            "SCOPES: Set[str] = {"
            + ", ".join(['"' + scope + '"' for scope in scopes])
            + "}"
        )

    scopes_ptn = r"SCOPES: +Set\[str\] += +({.+})"

    source = re.sub(scopes_ptn, scopes_str, source)

    with hook_path.open("w") as f:
        f.write(source)

    try:
        run(["chmod", "+x", hook_path], capture_output=True, check=True, text=True)
    except CalledProcessError:
        setup_error(
            "error making .git/hooks/commit-msg executable. Install manually.",
        )
        return 1

    debug("FINISHED INSTALLING COMMIT-MSG.PY")
    print(hook_path, file=sys.stdout)
    return 0


def main() -> int:
    # Setup mode is triggered if the script is run via stdin
    if __file__ == "<stdin>":
        return setup()

    # Check script is being called correctly
    if len(sys.argv) != 2:
        error("Unexpected number of arguments.")
        return 1

    # Get commit message
    try:
        with open(sys.argv[1], "r") as f:
            msg = f.read().strip()
    except FileNotFoundError:
        error("File not found.")
        return 1

    # Validate commit message
    validation = validate(msg, TYPES, SCOPES, SCOPE_REQUIRED)
    if validation == "passing":
        return 0
    if validation == "failing":
        error(
            "Bad commit format. Please use `type(scope): description`",
        )
        return 1
    if validation == "type_failing":
        error(
            f"Bad commit msg type. Allowed types are {TYPES}",
        )
        return 1
    if validation == "scope_failing":
        error(
            f"Bad commit msg scope. Allowed scopes are {SCOPES}",
        )
        return 1
    if validation == "scope_required":
        error(
            f"A scope is required. Allowed scopes are {SCOPES}",
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


def test_versions_compatible() -> None:
    current_contents = '\n\ncommit-msg.py\nVERSION = "1.1.0"\n'
    source = '\n\ncommit-msg.py\nVERSION = "1.2.1"\n'

    assert versions_compatible(current_contents, source)


def test_swap_out_configs() -> None:
    def fix(s: str) -> str:
        """Strip the test> prefix which exists so these lines are ignored by the regular
        runtime behavior of the script."""
        return s.replace("test>", "")

    old = fix("""
    test>old stuff...         
    test>TYPES: Set[str] = {"fix", "feat"}
    test>SCOPES: Set[str] = {"thing1", "thing2"}
    test>SCOPE_REQUIRED: bool = True
    test>old stuff...
    """)
    new = fix("""
    test>new stuff...         
    test>TYPES: Set[str] = {"fix", "feat", "docs", "style", "refactor", "test", "chore", "revert"}
    test>SCOPES: Set[str] = {"deps", "ci/cd", "packaging", "python", "git"}
    test>SCOPE_REQUIRED: bool = True
    test>new stuff...
    """)

    updated = swap_out_config(old, new)

    assert updated == fix("""
    test>new stuff...         
    test>TYPES: Set[str] = {"fix", "feat"}
    test>SCOPES: Set[str] = {"thing1", "thing2"}
    test>SCOPE_REQUIRED: bool = True
    test>new stuff...
    """)
