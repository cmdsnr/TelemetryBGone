#!/usr/bin/env python3

import subprocess
import socket
import os

BLOCK_FILE = "blocked_records_linux.txt"
HELPER_SCRIPT = "./firewall_helper.sh"


def get_active_connections():
    result = subprocess.run(
        ["ss", "-tnp"],
        capture_output=True,
        text=True
    )
    return result.stdout.splitlines()


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def block_ip(ip):
    subprocess.run([HELPER_SCRIPT, "block", ip])
    with open(BLOCK_FILE, "a") as f:
        f.write(ip + "\n")


def undo_blocks():
    if not os.path.exists(BLOCK_FILE):
        print("No blocked records found.")
        return

    with open(BLOCK_FILE, "r") as f:
        for ip in f:
            ip = ip.strip()
            subprocess.run([HELPER_SCRIPT, "unblock", ip])

    os.remove(BLOCK_FILE)


def analyze_connections():
    print("[+] Active TCP Connections:\n")
    connections = get_active_connections()
    for line in connections:
        print(line)


def main():
    print("=== TelemetryBGone Linux Edition ===")
    print("1. Analyze connections")
    print("2. Undo blocks")
    print("0. Exit")

    choice = input("Select option: ")

    if choice == "1":
        analyze_connections()

    elif choice == "2":
        undo_blocks()

    else:
        return


if __name__ == "__main__":
    main()
