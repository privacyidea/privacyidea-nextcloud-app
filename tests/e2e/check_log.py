"""Reads nextcloud.log (one JSON entry per line) on stdin and reports entries
that concern the privacyIDEA app. Used by run.sh.

Entries of level 3 (error) or 4 (fatal) make the script exit with 1. Warnings
(level 2) and PHP deprecation notices from the app's own files are printed, but
do not fail the run.
"""
import json
import os
import sys
from typing import Any

IN_ACTIONS = os.environ.get('GITHUB_ACTIONS') == 'true'


def concerns_app(entry: dict[str, Any]) -> bool:
    if entry.get('app') == 'privacyidea':
        return True
    # Match the message and exception only: the request URL contains
    # "privacyidea" for every entry that the login challenge page writes.
    text = entry.get('message', '') + json.dumps(entry.get('exception', ''))
    return 'privacyidea' in text.lower()


def report(kind: str, entry: dict[str, Any]) -> None:
    message = ' '.join(entry.get('message', '').split())[:500]
    exception = entry.get('exception')
    if isinstance(exception, dict) and exception.get('File'):
        message += ' (%s:%s)' % (exception['File'], exception.get('Line', '?'))
    if IN_ACTIONS:
        print('::%s title=Nextcloud log::%s' % (kind, message))
    else:
        print('%s: %s' % (kind.upper(), message))


def main() -> int:
    errors = 0
    seen = set()
    for line in sys.stdin:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not concerns_app(entry):
            continue
        level = entry.get('level', 0)
        message = entry.get('message', '')
        if level >= 3:
            kind = 'error'
        elif level == 2 or ('deprecated' in message.lower() and 'custom_apps/privacyidea' in message):
            kind = 'warning'
        else:
            continue
        if (kind, message) in seen:
            continue
        seen.add((kind, message))
        report(kind, entry)
        errors += kind == 'error'
    print('Nextcloud log: %d error(s) from the app' % errors)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
