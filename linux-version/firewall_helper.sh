#!/bin/bash

# firewall_helper.sh
# Helper script for managing iptables rules

ACTION=$1
IP=$2

if [ -z "$ACTION" ] || [ -z "$IP" ]; then
    echo "Usage: firewall_helper.sh [block|unblock] <ip>"
    exit 1
fi

if [ "$ACTION" == "block" ]; then
    sudo iptables -A OUTPUT -d "$IP" -j DROP
    echo "[+] Blocked $IP"

elif [ "$ACTION" == "unblock" ]; then
    sudo iptables -D OUTPUT -d "$IP" -j DROP
    echo "[+] Unblocked $IP"

else
    echo "Invalid action. Use block or unblock."
fi
