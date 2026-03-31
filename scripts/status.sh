#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# status.sh – Shared status log library.  Source this file; do not execute it.
#
# Writes a human-readable status.log to /data/certs/status.log so the current
# state is visible directly in the mounted cert directory without digging into
# the .logs/ subdirectory.
#
# Format:
#   2026-03-17 10:43:07 | OK      | CERT    | Certificate issued – expires 2026-06-15
#   2026-03-17 10:43:12 | OK      | UPLOAD  | HTTPS cert uploaded to cppm.sinemalab.com
#   2026-03-17 10:43:12 | OK      | UPLOAD  | RADIUS cert uploaded to cppm.sinemalab.com
#   2026-03-17 10:43:12 | OK      | TRUST   | 6 LE CA certs verified in trust list (2 uploaded)
#   2026-03-17 14:00:01 | INFO    | RENEW   | Cert not due for renewal – 89 days remaining
#   2026-03-17 15:00:00 | FAILED  | UPLOAD  | ClearPass API returned HTTP 401
# ─────────────────────────────────────────────────────────────────────────────

STATUS_LOG="/data/certs/status.log"

# status_write LEVEL CATEGORY MESSAGE
#   LEVEL:    OK | INFO | FAILED | WARN
#   CATEGORY: CERT | UPLOAD | TRUST | RENEW | STARTUP
status_write() {
    local level="$1"
    local category="$2"
    local message="$3"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    # Pad level and category for aligned columns
    printf '%s | %-6s | %-7s | %s\n' \
        "$ts" "$level" "$category" "$message" \
        >> "$STATUS_LOG" 2>/dev/null || true
}

# Write the status header line the first time (empty file or new day)
status_init() {
    mkdir -p "$(dirname "$STATUS_LOG")"
    if [[ ! -f "$STATUS_LOG" ]]; then
        {
            echo "# ClearPass Certificate Manager – Status Log"
            echo "# $(date '+%Y-%m-%d %H:%M:%S') – Log initialised"
            echo "# Columns: TIMESTAMP | LEVEL | CATEGORY | MESSAGE"
            echo "#"
        } >> "$STATUS_LOG"
    fi
}

# Always call init when this file is sourced
status_init
