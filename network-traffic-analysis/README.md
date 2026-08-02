# Network Traffic Analysis: SYN Flood Attack Investigation

## Overview
This case study analyzes a Wireshark packet capture from a simulated denial-of-service incident affecting a company's public-facing web server. The goal was to identify the attack type from raw traffic patterns, explain the underlying TCP mechanism being exploited, and assess the operational impact on the organization.

## Contents
- [syn_flood_report.pdf](SYN_Flood_Attack_Investigation.pdf) — Full incident analysis, including attack identification, three-way handshake breakdown, log evidence, business impact, and recommended mitigations.
- [wireshark_tcp_http_log.pdf](Wireshark TCP_HTTP log - TCP log.pdf) — Annotated packet capture log used for the analysis. Color-coded for readability: **red** for anomalous/attack traffic, **green** for normal client activity, **yellow** for error responses.

## Key Findings
- Identified a **SYN flood attack**: a single source IP repeatedly sent TCP SYN packets to port 443 without completing the handshake, exhausting server connection resources.
- Traced the impact on legitimate traffic, showing how genuine client requests began failing (504 Gateway Timeout, connection resets) once server resources were consumed by the flood.
- Proposed concrete mitigations, including SYN cookies, connection rate limiting, and DDoS protection services, going beyond simple IP blocking given the risk of source spoofing.

## Skills Demonstrated
- Packet capture (PCAP) analysis and TCP protocol interpretation
- Denial-of-service attack pattern recognition
- Incident documentation and stakeholder-ready reporting
- Security control recommendations grounded in observed evidence

## Context
Completed as part of the Google Cybersecurity Professional Certificate coursework. Scenario and log data are course-provided simulations, not a real client incident.
