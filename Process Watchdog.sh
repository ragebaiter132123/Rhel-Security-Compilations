#!/bin/bash

prev_count=0
interval=5
notice_number=1

# colors and formatting
red='\033[1;31m'
yellow='\033[1;93m'
green='\033[1;92m'
nc='\033[0m'   # no color
bold='\033[1m'


while true; do
    current_count=$(ss -plant | tail -n +2 | wc -l)

    if [ "$current_count" -ne "$prev_count" ]; then
        echo -e "${bold}${red}Process Count Change, ${green}[NOTICE_${notice_number}]:${nc} ${yellow}${prev_count} → ${current_count}${nc}"
        prev_count=$current_count
        ((notice_number++))
    fi

    sleep "$interval"
done