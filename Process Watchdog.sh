#!/bin/bash

prev_count=0
interval=5

# colors
RED='\033[1;31m'
NC='\033[0m'  # No color

while true; do
    current_count=$(ss -plant | tail -n +2 | wc -l)

    if [ "$current_count" -ne "$prev_count" ]; then
        echo -e "${RED}⚠️ CONNECTION COUNT CHANGED: $prev_count → $current_count${NC>

        prev_count=$current_count
    fi

    sleep "$interval"
done