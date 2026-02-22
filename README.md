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

```bash
nmap -sC -sV -O -p- --script vuln -oX scan.xml 10.10.10.0/24
