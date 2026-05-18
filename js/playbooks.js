// js/playbooks.js  — v3: 20 techniques, multiple option sets per technique

// Each technique has `optionSets`: an array of choice arrays.
// One set is picked randomly per triage, so the same technique never
// feels identical when it fires repeatedly over a long session.

const playbooks = {

    // ── T1046 — Network Service Discovery ─────────────────────────────────────
    "T1046": {
        title: "Network Reconnaissance / Port Scan Response",
        optionSets: [
            [
                { text: "Acknowledge recon event and cross-reference active block lists",          correct: true  },
                { text: "Shut down the perimeter firewall interface completely",                   correct: false },
                { text: "Launch a counter port-scan back at the source IP",                       correct: false }
            ],
            [
                { text: "Log source IP, escalate to threat hunt queue, add to watchlist",         correct: true  },
                { text: "Whitelist the source IP to avoid alert fatigue",                         correct: false },
                { text: "Reboot the border router to reset connection state",                     correct: false }
            ],
            [
                { text: "Apply geo-block rule at perimeter and document in ITSM ticket",          correct: true  },
                { text: "Email the source ISP to request a takedown",                             correct: false },
                { text: "Disable the IDS sensor to prevent false positives",                      correct: false }
            ]
        ]
    },

    // ── T1078 — Valid Accounts ─────────────────────────────────────────────────
    "T1078": {
        title: "Out-of-Hours / Anomalous Account Login",
        optionSets: [
            [
                { text: "Verify user identity via an out-of-band communication channel",          correct: true  },
                { text: "Approve the traffic automatically to avoid workflow disruption",          correct: false },
                { text: "Assume a system clock failure and clear the event entry",                correct: false }
            ],
            [
                { text: "Suspend session token and page the user via mobile — await response",   correct: true  },
                { text: "Reset the account password immediately without notifying the user",      correct: false },
                { text: "Add the account to the VIP exception list to reduce noise",              correct: false }
            ],
            [
                { text: "Force MFA re-challenge and lock session pending verification",           correct: true  },
                { text: "Delete the Active Directory account to prevent further access",          correct: false },
                { text: "Mark alert as false positive — legitimate travel is common",             correct: false }
            ]
        ]
    },

    // ── T1018 — Remote System Discovery ───────────────────────────────────────
    "T1018": {
        title: "Internal Reconnaissance / Host Discovery",
        optionSets: [
            [
                { text: "Isolate the source host and review LDAP query logs for scope",           correct: true  },
                { text: "Allow activity — internal AD queries are standard IT behaviour",          correct: false },
                { text: "Flush all DNS caches on the domain to disrupt enumeration",              correct: false }
            ],
            [
                { text: "Capture network traffic from the host and escalate for threat hunt",     correct: true  },
                { text: "Uninstall all AD management tools from the workstation immediately",     correct: false },
                { text: "Block all internal LDAP traffic at the firewall",                        correct: false }
            ]
        ]
    },

    // ── T1070.004 — Indicator Removal: File Deletion ──────────────────────────
    "T1070.004": {
        title: "Anti-Forensics / Log & File Tampering",
        optionSets: [
            [
                { text: "Acquire forensic image of host immediately before further changes occur", correct: true  },
                { text: "Restore deleted logs from the SIEM — no host action required",           correct: false },
                { text: "Reboot the host to restore default log settings",                        correct: false }
            ],
            [
                { text: "Isolate host, preserve volatile memory, trigger IR runbook",             correct: true  },
                { text: "Re-enable logging and allow the user to continue working",               correct: false },
                { text: "Notify the user that their log deletion was detected",                   correct: false }
            ]
        ]
    },

    // ── T1053.005 — Scheduled Task/Job ────────────────────────────────────────
    "T1053.005": {
        title: "Scheduled Task Persistence Anomaly",
        optionSets: [
            [
                { text: "Delete unauthorized Scheduled Task registry structures via EDR",         correct: true  },
                { text: "Format the server hard drive immediately",                               correct: false },
                { text: "Change the system time zone settings to stall task execution",           correct: false }
            ],
            [
                { text: "Disable and quarantine the task; review associated binary hash in VT",  correct: true  },
                { text: "Approve the task — SYSTEM-created tasks are standard Windows behaviour", correct: false },
                { text: "Restart the Task Scheduler service to dequeue pending tasks",            correct: false }
            ],
            [
                { text: "Remove task, hash associated payload, block hash via EDR policy",        correct: true  },
                { text: "Move the task trigger to a maintenance window to reduce business impact",correct: false },
                { text: "Grant the task elevated privileges to complete its run cleanly",         correct: false }
            ]
        ]
    },

    // ── T1059.001 — PowerShell ────────────────────────────────────────────────
    "T1059.001": {
        title: "Obfuscated PowerShell Execution Detected",
        optionSets: [
            [
                { text: "Terminate the PowerShell process and quarantine the host via EDR",       correct: true  },
                { text: "Whitelist the Base64 pattern in SIEM to suppress future alerts",         correct: false },
                { text: "Restart the Windows Update service to clear the execution context",      correct: false }
            ],
            [
                { text: "Enable PS script block logging, capture transcript, isolate host",       correct: true  },
                { text: "Disable PowerShell across the entire domain to block the vector",        correct: false },
                { text: "Email the user asking why they ran an encoded command",                  correct: false }
            ],
            [
                { text: "Kill process, extract decoded payload, submit to sandbox, isolate",      correct: true  },
                { text: "Allow execution to complete — killing mid-run may cause system damage",  correct: false },
                { text: "Add the host to the PowerShell exclusion list in the AV console",        correct: false }
            ]
        ]
    },

    // ── T1059.003 — Windows Command Shell ─────────────────────────────────────
    "T1059.003": {
        title: "Suspicious Command Shell Execution",
        optionSets: [
            [
                { text: "Terminate cmd.exe session, review parent process tree via EDR",          correct: true  },
                { text: "Ignore — cmd.exe is a standard OS component",                           correct: false },
                { text: "Block cmd.exe binary hash at the firewall level",                        correct: false }
            ],
            [
                { text: "Isolate host, capture full process tree, open IR ticket",                correct: true  },
                { text: "Restart the host to clear the shell session",                            correct: false },
                { text: "Email IT to check if any maintenance scripts are scheduled",             correct: false }
            ]
        ]
    },

    // ── T1059.005 — Visual Basic ──────────────────────────────────────────────
    "T1059.005": {
        title: "WMI / VBScript Fileless Execution",
        optionSets: [
            [
                { text: "Remove WMI event subscription via wmic and isolate host immediately",    correct: true  },
                { text: "Restart the WMI service to reset subscriptions",                         correct: false },
                { text: "Add the subscription task to the approved software register",            correct: false }
            ],
            [
                { text: "Kill WMI consumer process, audit all subscriptions domain-wide",         correct: true  },
                { text: "Disable WMI across all endpoints as a precaution",                       correct: false },
                { text: "Allow — WMI subscriptions are used by legitimate monitoring tools",       correct: false }
            ]
        ]
    },

    // ── T1547.001 — Registry Run Keys ─────────────────────────────────────────
    "T1547.001": {
        title: "Registry Persistence via Run Keys",
        optionSets: [
            [
                { text: "Remove unauthorized registry key and block associated binary via EDR",   correct: true  },
                { text: "Export and archive the registry key before taking any action",           correct: false },
                { text: "Notify the user that their startup program was flagged",                 correct: false }
            ],
            [
                { text: "Remediate key, submit binary to sandbox, scan similar hosts",           correct: true  },
                { text: "Leave the key in place and monitor for further activity",                correct: false },
                { text: "Reset the host to factory defaults immediately",                         correct: false }
            ]
        ]
    },

    // ── T1027 — Obfuscated Files / Payloads ───────────────────────────────────
    "T1027": {
        title: "Obfuscated Payload / Anti-Analysis Detected",
        optionSets: [
            [
                { text: "Quarantine the file, submit to sandbox, block hash across fleet",       correct: true  },
                { text: "Attempt to manually decode the file on the production host",             correct: false },
                { text: "Mark as low-risk — obfuscation is common in legitimate software",       correct: false }
            ],
            [
                { text: "Isolate host, capture memory, escalate to IR team with artefacts",      correct: true  },
                { text: "Delete the file and clear the AV quarantine log",                        correct: false },
                { text: "Run a full disk format to eliminate all potential payloads",             correct: false }
            ]
        ]
    },

    // ── T1566.001 — Spearphishing Attachment ──────────────────────────────────
    "T1566.001": {
        title: "Phishing / Spearphishing Attachment",
        optionSets: [
            [
                { text: "Quarantine the email, block sender domain, alert the user's manager",   correct: true  },
                { text: "Reply to the phishing sender warning them they have been reported",      correct: false },
                { text: "Forward the email to IT for filing — no immediate action needed",       correct: false }
            ],
            [
                { text: "Pull email from all inboxes, block attachment hash, brief IT security", correct: true  },
                { text: "Ask the user to simply delete the email and not click it again",         correct: false },
                { text: "Whitelist the sender domain to prevent mis-classification",              correct: false }
            ]
        ]
    },

    // ── T1110 — Brute Force ───────────────────────────────────────────────────
    "T1110": {
        title: "Brute Force / Credential Stuffing Response",
        optionSets: [
            [
                { text: "Block attacker IP at perimeter firewall and throttle auth endpoint",     correct: true  },
                { text: "Delete the target user's Active Directory profile entirely",             correct: false },
                { text: "Disable network interface on the primary Domain Controller",             correct: false }
            ],
            [
                { text: "Apply rate-limiting rule, geo-block source ASN, alert account owner",   correct: true  },
                { text: "Increase the account lockout threshold to reduce disruption",            correct: false },
                { text: "Disable MFA temporarily to determine if it is causing lockouts",         correct: false }
            ],
            [
                { text: "Force account lock, reset credentials, apply CAPTCHA at login portal",  correct: true  },
                { text: "Allow attempts to continue while monitoring for successful login",       correct: false },
                { text: "Block all SSH/RDP globally to prevent further brute force exposure",     correct: false }
            ]
        ]
    },

    // ── T1204.002 — Malicious File Execution ──────────────────────────────────
    "T1204.002": {
        title: "Malicious File / Payload Execution",
        optionSets: [
            [
                { text: "Revoke user session tokens and trigger password reset via IdP",          correct: true  },
                { text: "Reply to the email warning the external sender",                         correct: false },
                { text: "Ignore — the corporate firewall will block outbound C2 traffic",        correct: false }
            ],
            [
                { text: "Isolate host via EDR, preserve memory, remove payload, reset creds",    correct: true  },
                { text: "Ask the user to close the document and resume normal work",              correct: false },
                { text: "Reboot the host — malware cannot survive a power cycle",                correct: false }
            ],
            [
                { text: "Kill malicious process, quarantine file, scan all hosts for IOC hash",  correct: true  },
                { text: "Leave host online to gather more threat intelligence data",              correct: false },
                { text: "Wipe and reimage without preserving forensic evidence",                  correct: false }
            ]
        ]
    },

    // ── T1048 — Exfiltration Over Alternative Protocol ────────────────────────
    "T1048": {
        title: "Data Exfiltration / Egress Spike Triage",
        optionSets: [
            [
                { text: "Terminate process handles executing unauthorized outbound data transit", correct: true  },
                { text: "Reboot the database server to clear active network connections",         correct: false },
                { text: "Add the destination IP to the internal DNS safe list",                   correct: false }
            ],
            [
                { text: "Block destination IP/domain at proxy, preserve PCAP, open P1 ticket",  correct: true  },
                { text: "Throttle outbound bandwidth to slow the transfer without alerting actor",correct: false },
                { text: "Allow traffic to complete — interrupting may corrupt business data",     correct: false }
            ],
            [
                { text: "Isolate host, block egress domain, initiate data loss assessment",      correct: true  },
                { text: "Notify the user that their upload was too large",                        correct: false },
                { text: "Contact the destination ISP to confirm the IP is malicious first",       correct: false }
            ]
        ]
    },

    // ── T1021.001 — Remote Desktop Protocol ───────────────────────────────────
    "T1021.001": {
        title: "Lateral Movement via RDP",
        optionSets: [
            [
                { text: "Terminate RDP session, isolate both source and target hosts",            correct: true  },
                { text: "Allow the session — RDP between internal hosts is normal IT activity",  correct: false },
                { text: "Disable RDP globally across the estate immediately",                     correct: false }
            ],
            [
                { text: "Force session disconnect, reset credentials, review access logs",        correct: true  },
                { text: "Shadow the RDP session to observe the attacker's activity",              correct: false },
                { text: "Move the host to a monitoring VLAN without disconnecting the session",   correct: false }
            ]
        ]
    },

    // ── T1055 — Process Injection ─────────────────────────────────────────────
    "T1055": {
        title: "Process Injection / Memory Manipulation",
        optionSets: [
            [
                { text: "Isolate host via EDR containment and collect memory dump for analysis",  correct: true  },
                { text: "Kill only the injected process and allow the host to continue",          correct: false },
                { text: "Restart the affected process to remove the injection",                   correct: false }
            ],
            [
                { text: "Terminate parent and child processes, isolate, initiate forensic IR",    correct: true  },
                { text: "Scan only — do not contain, to avoid alerting the attacker",            correct: false },
                { text: "Reboot the host; process injection cannot persist across a restart",     correct: false }
            ]
        ]
    },

    // ── T1190 — Exploit Public-Facing Application ─────────────────────────────
    "T1190": {
        title: "Web Application Exploitation Attempt",
        optionSets: [
            [
                { text: "Block source IP at WAF, review web server logs for successful requests", correct: true  },
                { text: "Take the web application offline immediately to prevent exploitation",    correct: false },
                { text: "Disable WAF alerting rules that are generating noise",                   correct: false }
            ],
            [
                { text: "Apply virtual patch at WAF, collect HTTP logs, check for shells",       correct: true  },
                { text: "Update the application immediately on the live production server",       correct: false },
                { text: "Ignore — automated scanners generate this type of traffic constantly",   correct: false }
            ]
        ]
    },

    // ── T1562.001 — Impair Defenses ───────────────────────────────────────────
    "T1562.001": {
        title: "Security Tool Tampering / Defense Evasion",
        optionSets: [
            [
                { text: "Isolate host, re-enable defenses remotely via policy, open P1 ticket",  correct: true  },
                { text: "Re-enable AV locally and allow the user to continue working",            correct: false },
                { text: "Accept the change — users sometimes disable AV for performance reasons", correct: false }
            ],
            [
                { text: "Trigger EDR full-disk scan via cloud console, isolate pending results",  correct: true  },
                { text: "Email the user to ask if they disabled the security tool deliberately",   correct: false },
                { text: "Reinstall the AV agent without preserving the current host state",       correct: false }
            ]
        ]
    },

    // ── T1003.001 — LSASS Memory Credential Dumping ───────────────────────────
    "T1003.001": {
        title: "LSASS Credential Dumping Event",
        optionSets: [
            [
                { text: "Isolate host via EDR network containment immediately",                   correct: true  },
                { text: "Run a quick Windows Defender update scan on the asset",                  correct: false },
                { text: "Email the user asking if they installed Mimikatz",                       correct: false }
            ],
            [
                { text: "Contain host, reset all cached domain credentials, audit AD for changes",correct: true  },
                { text: "Remove lsass.exe from the process allow-list and restart it",            correct: false },
                { text: "Enable credential guard — it will retroactively protect dumped hashes",  correct: false }
            ],
            [
                { text: "Isolate, preserve memory dump, escalate with IOCs to Tier 2",           correct: true  },
                { text: "Kill the process that accessed LSASS and resume normal monitoring",      correct: false },
                { text: "Rotate only the affected user's password and close the ticket",          correct: false }
            ]
        ]
    },

    // ── T1486 — Data Encrypted for Impact (Ransomware) ────────────────────────
    "T1486": {
        title: "Ransomware / Mass Encryption Event",
        optionSets: [
            [
                { text: "Hard-isolate the host immediately — disconnect from network and power",  correct: true  },
                { text: "Run a backup immediately to preserve encrypted files",                   correct: false },
                { text: "Pay the ransom to recover files before encryption spreads further",      correct: false }
            ],
            [
                { text: "Trigger P0 incident, isolate host, kill encryption process, notify CISO",correct: true  },
                { text: "Reboot the host into safe mode to stop the encryption process",          correct: false },
                { text: "Allow encryption to complete — partial encryption corrupts more files",  correct: false }
            ]
        ]
    },

    // ── T1078.002 — Domain Accounts Abuse ────────────────────────────────────
    "T1078.002": {
        title: "Privileged / Domain Account Abuse",
        optionSets: [
            [
                { text: "Revoke all active sessions for the account and force credential reset",  correct: true  },
                { text: "Monitor the account passively for 24 hours before acting",              correct: false },
                { text: "Remove domain admin rights permanently without investigation",           correct: false }
            ],
            [
                { text: "Isolate affected systems, audit AD for privilege changes, alert CISO",   correct: true  },
                { text: "Reduce account privileges temporarily until the user can be contacted",  correct: false },
                { text: "Allow access — Domain Admins need broad access by definition",          correct: false }
            ]
        ]
    },

    // ── T1136.002 — Create Domain Account ────────────────────────────────────
    "T1136.002": {
        title: "Unauthorised Domain Account Creation",
        optionSets: [
            [
                { text: "Disable the new account immediately and audit all recent AD changes",    correct: true  },
                { text: "Leave the account active while investigating to avoid disrupting attacker",correct: false},
                { text: "Remove the account creator's access as a precaution only",               correct: false }
            ],
            [
                { text: "Delete rogue account, revoke creating user's privileges, open P1",      correct: true  },
                { text: "Ask the creating user for justification before taking any action",       correct: false },
                { text: "Move account to a restricted OU pending review",                         correct: false }
            ]
        ]
    },

    // ── Default fallback ──────────────────────────────────────────────────────
    "Default": {
        title: "General Security Incident Triage",
        optionSets: [
            [
                { text: "Acknowledge event and escalate to Tier 2 investigation queues",          correct: true  },
                { text: "Discard logs to save database storage capacity",                         correct: false },
                { text: "Label event as a permanent false positive",                              correct: false }
            ],
            [
                { text: "Document findings in ITSM ticket and trigger standard IR checklist",    correct: true  },
                { text: "Auto-close the alert — low-confidence detections rarely indicate risk", correct: false },
                { text: "Reboot the affected asset to clear any potential malicious state",       correct: false }
            ]
        ]
    }
};