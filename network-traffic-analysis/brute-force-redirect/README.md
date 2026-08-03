# Security Incident Investigation: Brute Force Attack Leading to Malicious Redirect

## Overview
This case study investigates a real-world attack pattern: a former employee used a brute force attack to compromise a website's administrative account, injected malicious JavaScript into the site, and redirected visitors to a fake copy of the site containing malware. The investigation combines packet capture analysis (tcpdump) with source code review to reconstruct the full incident timeline and identify the network protocol involved.

## Contents
- [`Security_Incident_Report_Brute_Force_Redirect.pdf`](./Security_Incident_Report_Brute_Force_Redirect.pdf) — Full incident report: protocol identification, incident documentation, and remediation recommendation.
- [`tcpdump_traffic_log.pdf`](./tcpdump_traffic_log.pdf) — Raw tcpdump packet capture log used as evidence for the investigation.
- [`tcpdump-reference.md`](./tcpdump-reference.md) — Reference notes on reading tcpdump output and essential command-line usage.

## Key Findings
- Identified **HTTP** (application layer) as the protocol carrying both the legitimate page load and the malicious redirect, confirmed directly from tcpdump's explicit `HTTP: GET / HTTP/1.1` labeling in the log.
- Reconstructed the full attack chain from packet-level evidence: DNS resolution, TCP three-way handshake, HTTP request/response, followed by a second DNS lookup and TCP/HTTP session to a different IP address, showing the browser redirect from the legitimate site to the fake one.
- Correlated network-layer evidence with source code review findings (injected JavaScript, malicious download) and customer/helpdesk reports to build a complete, sourced incident timeline.
- Traced the root cause to a brute-forced default password on the administrative account, with no login attempt limiting in place.
- Recommended multi-factor authentication as the primary remediation, since it directly neutralizes the specific failure that enabled the attack: a correctly guessed password no longer being sufficient for access.

## Skills Demonstrated
- Packet capture (tcpdump) analysis and TCP/IP protocol interpretation
- Attack chain reconstruction from network and application layer evidence
- Incident documentation combining multiple evidence sources with clear sourcing
- Security control recommendations grounded in root cause analysis

## Context
Completed as part of the Google Cybersecurity Professional Certificate coursework. Scenario and log data are course-provided simulations, not a real client incident.
