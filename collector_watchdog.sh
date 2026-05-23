#!/bin/bash

DB="/var/lib/netspecter/netspecter.db"
SERVICE="netspecter-collector"
MAX_AGE=120

AGE=$(sqlite3 "$DB" "
SELECT ROUND((julianday('now','localtime') - julianday(updated_at)) * 86400, 0)
FROM collector_heartbeat
WHERE id=1;
")

if [ -z "$AGE" ] || [ "$AGE" = "" ] || [ "$AGE" = "NULL" ]; then
    logger "NetSpecter watchdog: no collector heartbeat, restarting"
    systemctl restart "$SERVICE"
    exit 0
fi

if [ "$AGE" -gt "$MAX_AGE" ]; then
    logger "NetSpecter watchdog: collector stale for ${AGE}s, restarting"
    systemctl restart "$SERVICE"
fi
