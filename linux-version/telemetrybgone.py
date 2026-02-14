#!/usr/bin/env python3

import subprocess
import socket
import os
import sys

BLOCK_FILE = "blocked_records_linux.txt"


def get_active_connections():
    """
    Uses ss to retrieve active TCP connections.
    """
    result = subprocess.run(
        ["ss", "-tnp"],
        capture_output=True,
        text=True
    )
    return result.stdout.splitlines()


def resolve_host(host):
    """
    Resolve hostname to IPv4 address.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def block_ip(ip):
    """
    Block outbound traffic to IP using iptables.
    """
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
    with open(BLOCK_FILE, "a") as f:
        f.write(ip + "\n")


def undo_blocks():
    """
    Remove previously added iptables rules.
    """
    if not os.path.exists(BLOCK_FILE):
        print("No blocked records found.")
        return

    with open(BLOCK_FILE, "r") as f:
        for ip in f:
            ip = ip.strip()
            print(f"[+] Unblocking {ip}")
            subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])

    os.remove(BLOCK_FILE)


def main():
    print("=== TelemetryBGone Linux Edition ===")
    print("1. Analyze connections")
    print("2. Undo blocks")
    print("0. Exit")

    choice = input("Select option: ")

    if choice == "1":
        connections = get_active_connections()
        print("[+] Active TCP connections:")
        for line in connections:
            print(line)

    elif choice == "2":
        undo_blocks()

    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
