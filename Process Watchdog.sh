#!/bin/bash

prev_count=0
interval=5

# Colors and formatting
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'   # No Color
BOLD='\033[1m'
BLINK='\033[5m'

while true; do
    current_count=$(ss -plant | tail -n +2 | wc -l)

    if [ "$current_count" -ne "$prev_count" ]; then
        echo -e "${BLINK}${BOLD}${RED}⚠️ CONNECTION COUNT CHANGED: ${YELLOW}${prev_count} → ${current_count}${NC}"
        prev_count=$current_count
    fi

    sleep "$interval"
done
