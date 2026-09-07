# Incident Handler's Journal

## Overview
This is a working journal maintained across the Google Cybersecurity Professional Certificate's "Sound the Alarm: Detection and Response" course. Unlike the standalone reports elsewhere in this portfolio, it's a running log, not a formal deliverable, and reflects how an analyst actually documents a case as it unfolds: partial facts, open questions, and next steps, rather than a finished narrative. New entries are added as later course activities are completed.

## Entry 1: Ransomware Incident (Healthcare)
A small U.S. primary-care clinic lost access to patient files and clinical systems after an employee opened a phishing attachment, allowing a threat actor to deploy ransomware across the network. A ransom note demanding payment for a decryption key was left on affected machines, and the organization was forced to shut down operations while investigating.

This entry captures the incident as first reported: what's confirmed, what's still unknown (attribution, exact timeline, whether data was exfiltrated), and the immediate next steps an analyst would take, including flagging likely HIPAA breach notification obligations given the healthcare context.

[**View Entry 1 (PDF)**](./Incident_Handlers_Journal_Entry_1.pdf)

## What This Demonstrates
- Real-time incident documentation using the 5 W's framework (who, what, when, where, why), distinguishing confirmed facts from open questions rather than presenting a case as more resolved than it is
- Correctly separating attacker motive/mechanism (why an attack succeeded) from organizational root cause (a separate, later stage of investigation)
- Awareness of sector-specific obligations, flagging HIPAA breach notification requirements without waiting to be prompted
- Practical incident handling instincts: evidence preservation, containment, and appropriate escalation (law enforcement, external IR support) for an organization with limited in-house capacity
