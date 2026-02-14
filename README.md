# TelemetryBGone

A Windows-based C++ system utility that analyzes outbound DNS activity, identifies Windows service-generated connections, and programmatically manages Windows Firewall rules to control specific outbound traffic.

---

## Overview

TelemetryBGone is a low-level Windows networking and system utility written in C++ using native Windows APIs.

The tool:

- Enumerates running processes
- Inspects active TCP connections
- Resolves DNS records
- Identifies connections initiated by `svchost.exe`
- Dynamically creates or removes Windows Firewall outbound rules
- Maintains a rollback mechanism for restoring previous firewall states

This project was built to explore:

- Windows networking internals
- Firewall rule automation via COM interfaces
- DNS resolution using WinDNS
- TCP connection inspection using IP Helper API
- Process enumeration with ToolHelp32
- System-level programming in C++

---

## Technical Architecture

### 1. Process Management

Uses:

- `CreateToolhelp32Snapshot`
- `Process32First`
- `Process32Next`
- `OpenProcess`
- `QueryFullProcessImageName`
- `TerminateProcess`

Functionality:

- Enumerates all running processes
- Identifies system vs non-system processes
- Safely manages process shutdown where required

---

### 2. DNS Inspection

Uses:

- `DnsQuery_A`
- `DnsRecordListFree`
- `WinDNS.h`
- `inet_ntoa`

The tool:

- Queries DNS A records
- Extracts resolved IPv4 addresses
- Converts between ANSI and wide-character formats
- Maps domain names to active outbound connections

---

### 3. TCP Connection Analysis

Uses:

- `GetExtendedTcpTable`
- `MIB_TCPTABLE_OWNER_PID`
- `iphlpapi.h`

Purpose:

- Enumerates active TCP connections
- Matches remote IP addresses to DNS-resolved domains
- Identifies owning process IDs
- Determines whether traffic originates from `svchost.exe`

---

### 4. Windows Firewall Automation

Uses:

- `INetFwPolicy2`
- `INetFwRules`
- `INetFwRule`
- COM (`CoCreateInstance`)
- `NetFwPolicy2`

Capabilities:

- Programmatically creates outbound block rules
- Targets specific resolved IP addresses
- Enables/disables firewall rules dynamically
- Removes previously added rules
- Supports full rollback functionality

---

### 5. Record Tracking and Rollback

The tool:

- Saves blocked DNS records to `blockedRecords.txt`
- Allows complete undo via rule removal
- Ensures system recoverability

---

## Core Workflow

1. Capture DNS cache using:
