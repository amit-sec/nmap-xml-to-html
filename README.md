# nmap-xml-to-html 🔍

Convert Nmap XML output into a modern, interactive HTML security report.

nmap-xml-to-html transforms raw Nmap XML scan data into a clean, structured, and presentation-ready HTML report suitable for security assessments and infrastructure reviews.

---

## Overview

Nmap is powerful, but its default output is not always suitable for reporting or executive review.

This tool provides:

- Executive summary dashboard
- Host-level breakdown
- Top services and port statistics
- Unique open ports (TCP / UDP)
- Service exposure matrix
- Vulnerability script output display
- CSV export of open ports
- One-click IP:PORT copy
- Zero external Python dependencies

Designed for:

- Red Teams
- Penetration Testers
- SOC Analysts
- Security Consultants
- Infrastructure Audits

---

## Example Workflow

### 1️⃣ Generate Nmap XML

nmap -sC -sV -O -p- --script vuln -oX scan.xml 10.10.10.0/24

### 2️⃣ Generate HTML Report

python nmap2html.py -i scan.xml

### 3️⃣ Open the Generated Report

scan.html

Open it in your browser.

---

## Build Windows Executable

This project can be converted into a standalone Windows executable using PyInstaller.

### Install PyInstaller

pip install pyinstaller

### Build Using Spec File

pyinstaller --clean nmap2html.spec

Output:

dist/nmap2html.exe

The executable runs without requiring Python on the target machine.

---

## Features Breakdown

### Executive Summary
- Total hosts
- Hosts up / down
- Open / filtered / closed ports
- Services count
- Scan metadata

### Host Intelligence
- OS detection
- MAC address & vendor
- Uptime & last boot
- Hop distance
- Per-port script output

### Exposure Analysis
- Unique TCP & UDP ports
- Top services chart
- Top open ports chart
- Service matrix (which IP exposes what)
- Risk-based port highlighting

### Export Capabilities
- CSV export of all open ports
- Clipboard copy of IP:PORT list

---

## Legal Notice

⚠ This tool is intended for authorized security testing only.
Do not scan networks without proper permission.

---

## Development Transparency

This project was developed by Amit Prajapati with assistance from Claude AI (Anthropic) for code structuring, optimization, and UI refinement.

All architecture decisions, feature logic, and security considerations were manually reviewed and validated.

---

## License

MIT License
