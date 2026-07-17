#!/usr/bin/env python3
# Render the streamed Nextcloud JSON log (one object per line) as readable
# lines. Pass an app-id substring as the first argument to show only that app
# (e.g. "privacyidea"); with no argument, every app is shown.
import sys
import json

app_filter = sys.argv[1] if len(sys.argv) > 1 else ""
levels = {0: "DEBUG", 1: "INFO", 2: "WARN", 3: "ERROR", 4: "FATAL"}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        entry = json.loads(line)
    except ValueError:
        continue
    app = entry.get("app", "")
    if app_filter and app_filter not in app:
        continue
    level = levels.get(entry.get("level"), entry.get("level"))
    message = entry.get("message", "")
    if not isinstance(message, str):
        message = json.dumps(message)
    print(f"{entry.get('time', '')} [{level}] [{app}] {message}", flush=True)
