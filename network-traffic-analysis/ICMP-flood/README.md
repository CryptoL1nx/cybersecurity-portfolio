# Incident Report Analysis: DoS Attack via ICMP Flood (NIST CSF)

## Overview
This case study applies the NIST Cybersecurity Framework (CSF) to a distributed denial-of-service incident in which an unconfigured firewall allowed a flood of ICMP packets to overwhelm an organization's internal network for two hours. The report works through all five CSF core functions, Identify, Protect, Detect, Respond, and Recover, mapping each to its official subcategories rather than treating the framework as a generic checklist.

## Contents
- [`NIST_CSF_Incident_Report_DoS_Attack.pdf`](./NIST_CSF_Incident_Report_DoS_Attack.pdf) — Full incident analysis: summary, five-function CSF breakdown, and prioritized recommendations.

## Key Findings
- Traced the root cause to a firewall with no ICMP filtering or rate-limiting rules configured, the entry point that allowed the flood to reach internal systems.
- Structured the analysis around the CSF's actual subcategories (Asset/Technology, Access Control, Continuous Monitoring, Mitigation, Recovery Planning, etc.) rather than a single paragraph per function, to reflect genuine framework fluency.
- Closed with prioritized, ownership-oriented recommendations rather than an open list of "shoulds," distinguishing an immediate low-cost fix (ICMP rate limiting, source IP verification) from a longer-term investment (IDS/IPS and SIEM deployment).

## Skills Demonstrated
- Applying the NIST Cybersecurity Framework to a real incident scenario
- Root cause analysis and prioritized remediation planning
- Structuring technical findings for a mixed technical/business audience
- Incident documentation aligned to a recognized industry framework

## Context
Completed as part of the Google Cybersecurity Professional Certificate coursework. Scenario is a course-provided simulation, not a real client incident.
