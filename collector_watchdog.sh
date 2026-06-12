#!/bin/bash

DB="/var/lib/netspecter/netspecter.db"
SERVICE="netspecter-collector.service"
MAX_AGE=120
UPDATE_STATE="/var/lib/netspecter/update_state"

restart_collector() {
    logger "NetSpecter watchdog: $1"
    systemctl restart "$SERVICE"
}

if [ -f "$UPDATE_STATE" ]; then
    STATE=$(awk '{print $1}' "$UPDATE_STATE" 2>/dev/null)
    STAMP=$(awk '{print $2}' "$UPDATE_STATE" 2>/dev/null)
    NOW=$(date +%s)
    if [ "$STATE" = "running" ] && echo "$STAMP" | grep -Eq '^[0-9]+$' && [ $((NOW - STAMP)) -lt 900 ]; then
        logger "NetSpecter watchdog: update in progress, skipping collector restart"
        exit 0
    fi
fi

if [ ! -f "$DB" ]; then
    restart_collector "database missing, restarting collector"
    exit 0
fi

AGE=$(sqlite3 "$DB" "
SELECT ROUND((julianday('now','localtime') - julianday(updated_at)) * 86400, 0)
FROM collector_heartbeat
WHERE id=1;
" 2>/dev/null)

if ! echo "$AGE" | grep -Eq '^[0-9]+$'; then
    logger "NetSpecter watchdog: no collector heartbeat, restarting"
    systemctl restart "$SERVICE"
    exit 0
fi

if [ "$AGE" -gt "$MAX_AGE" ]; then
    logger "NetSpecter watchdog: collector stale for ${AGE}s, restarting"
    systemctl restart "$SERVICE"
fi
