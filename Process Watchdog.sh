#!/bin/bash

prev_count=0
interval=5
notice_number=1

# colors and formatting
red='\033[1;31m'
yellow='\033[1;33m'
nc='\033[0m'   # no color
bold='\033[1m'
blink='\033[5m'


while true; do
    current_count=$(ss -plant | tail -n +2 | wc -l)

    if [ "$current_count" -ne "$prev_count" ]; then
        echo -e "${blink}${bold}${red}hey... something changed (notice #${notice_number}):${nc} ${yellow}${prev_count} → ${current_count}${nc}"
        prev_count=$current_count
        ((notice_number++))
    fi

    sleep "$interval"
done
