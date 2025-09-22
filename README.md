# SOC-analyst

# 12-Week Practical Curriculum (baseline — I’ll customize after you tell me level/hours)

Week 1 — Foundation (Networking + OS)

Goals: TCP/IP, common ports, basic Linux/Windows commands, file systems, process/listening ports.

Practice: Run Wireshark capture on your home machine, identify HTTP/DNS packets.


Week 2 — Logging & Telemetry

Goals: What logs are (Windows Event, syslog, firewall, web), log formats, parsing basics.

Practice: Enable and read Windows Event Viewer / Linux syslog; forward into a local ELK or Splunk Free instance.


Week 3 — SIEM basics (hands-on)

Goals: Ingest logs, create simple searches, dashboards, alerts.

Tools: Elastic Stack (ELK) or Splunk Free (both industry-relevant). 

Practice: Build an alert for repeated failed logins.


Week 4 — Endpoint/EDR + Forensics fundamentals

Goals: Understand EDR alerts, basic host triage (processes, persistence, autoruns).

Practice: Use open tools (Velociraptor/Fleet) or free trials of EDR to investigate a phishing simulation.


Week 5 — IDS/Network detection + packet analysis

Goals: Suricata/Zeek basics, signature vs behavioral detection.

Practice: Deploy Suricata locally and detect a simulated exploit.


Week 6 — Incident Response (NIST + playbooks)

Goals: Walk NIST incident life cycle; create an incident playbook for ransomware. 

Practice: Tabletop exercise — roleplay a breach and document steps.


Week 7 — Threat Intelligence & ATT&CK mapping

Goals: Map alerts to MITRE ATT&CK tactics/techniques; consume Intel feeds and IOCs.

Practice: Ingest a threat feed (MISP) and map a phishing campaign to ATT&CK entries.


Week 8 — Detection engineering & tuning

Goals: Write correlation rules and reduce false positives, unit-test detections.

Practice: Convert one noisy alert into a high-precision detection and document reasoning.


Week 9 — SOAR & Automation

Goals: Build a simple SOAR playbook (isolate host, enrich alert, notify).

Practice: Use TheHive+Cortex or open-source SOAR to automate a triage workflow.


Week 10 — Threat hunting & adversary simulation

Goals: Hypothesis-driven hunting, using Hunt IDE queries, TTP-based hunts.

Practice: Run hunts against historical logs; present findings.


Week 11 — AI in SOC (hands-on)

Goals: Build a small RAG pipeline to answer “why did this alert fire?” using logs + LLM; implement ML-based anomaly detection (unsupervised).

Practice: Create a notebook that ingests login logs, trains a simple anomaly detector, and generates human-readable summaries with an LLM (locally or via API), focusing on explainability and safety. 


Week 12 — Capstone project + career prep

Capstone: Create a mini-SOC: ingest logs into ELK, add Suricata, create 4 detections, automate triage via SOAR, and add an LLM summary step. Document with a report and a demo video.

Career: Resume bullet crafting, interview simulations, certifications to aim for (CompTIA Security+, CySA+, Splunk Core Certified, SANS/GIAC if aiming high).



---

Hands-on labs & projects (immediate ones you can start)

1. Set up ELK or Splunk Free and ingest your system logs — craft a “multiple failed logins” detection. 


2. Deploy Suricata on a VM and detect a simple exploit from a pcap.


3. Build a small SOAR playbook that auto-enriches an alert with IP reputation and then sends a Slack message.


4. Build a RAG pipeline: index a corpus of your incident reports and use an LLM to answer “what happened” for a given alert (this is the core of AI-assisted triage).




---

Tools & open resources to learn (quick list)

SIEM: Splunk (enterprise skills valuable), Elastic Stack (ELK) — choose one to master. 

IDS: Suricata, Zeek

EDR: CrowdStrike, Microsoft Defender for Endpoint (study concepts even if no license)

SOAR: TheHive + Cortex (open source) or commercial SOARs

Threat Intel: MISP, VirusTotal, AbuseIPDB

Forensics: Autopsy, Velociraptor, Volatility

Learning platforms: SANS courses (for advanced detection/response), LetsDefend, open labs. 



---

AI modules — concrete (how you’ll learn & apply AI safely)

1. LLM Triage Assistant (RAG + Guardrails)

Index incident reports + parsed logs (vector DB). Query LLM with context to get a short investigation summary, suggested next steps, and confidence score.

Safety guardrails: always show source snippets, require human approval before actions. (Human in the loop.)



2. Anomaly detection (ML pipeline)

Feature engineering from logs (counts per user/hour, uncommon process hashes). Train unsupervised models (Isolation Forest / DBSCAN) to surface anomalies. Evaluate with precision/recall on labeled datasets.



3. Automated IOC enrichment & prioritisation

Enrich IPs/domains via threat feeds, use ML to prioritise based on internal risk features (privileged user, asset criticality).



4. AI-assisted detection creation

Use LLMs to generate draft Sigma rules or correlation queries from natural language descriptions — then human-review and test them.



5. SOAR + AI

Use models to preread and summarize alerts; trigger automated remediation only when confidence and checks pass.




(Important: AI reduces analyst fatigue but introduces risk — adversarial manipulation, hallucination, and privacy issues — always design with verification & audit logs.) 


---

Certifications & career path

Entry: CompTIA Security+, CyberStart/Cybrary labs

Mid: CompTIA CySA+, Splunk Core Certified User/Power User, Elastic Certified Analyst

Advanced: GIAC GCIA/GCIH/GCFA (SANS), Splunk Certified Admin/Architect
