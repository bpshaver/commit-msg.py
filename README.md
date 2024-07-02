# `commit-msg.py`

Python script to enforce conventional commits as a commit message Git hook.

## Requirements

- Python 3

## Installation

`curl -s https://raw.githubusercontent.com/bpshaver/commit-msg.py/main/commit-msg.py | python`

Or manually move `commit-msg.py` to `.git/hooks/commit-msg`

## Configuration

The script is meant to be edited.

- Customize the constants `TYPES`, `SCOPES`, and `SCOPE_REQUIRED` according to your project's needs.
- If Git fails to run the script using a Python interpreter, you may need to adjust the shebang.

## Tips

- To find the short list of your already used types and scopes (assuming your Git log is compliant with
  conventional commits), try `git log --no-merges --oneline | awk ' { print $2 } ' | sort | uniq`
