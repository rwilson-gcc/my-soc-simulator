// js/playbooks.js

const playbooks = {
    "T1110": {
        title: "Brute Force / Credential Stuffing Response",
        options: [
            { text: "Block Attacker IP on Perimeter Firewall", correct: true },
            { text: "Delete the target user's Active Directory profile entirely", correct: false },
            { text: "Disable network interface on the primary Domain Controller", correct: false }
        ]
    },
    "T1003.001": {
        title: "LSASS Credential Dumping Event",
        options: [
            { text: "Run a quick Windows Defender update scan on the asset", correct: false },
            { text: "Isolate Host via EDR network containment protocols", correct: true },
            { text: "Email the user asking if they installed Mimikatz", correct: false }
        ]
    },
    "T1204.002": {
        title: "Malicious Phishing Execution Workflow",
        options: [
            { text: "Reply to the email warning the external sender", correct: false },
            { text: "Ignore the alert since the corporate firewall is online", correct: false },
            { text: "Revoke User Session Tokens & trigger password reset via IdP", correct: true }
        ]
    },
    "T1048": {
        title: "Data Exfiltration / Egress Spike Triage",
        options: [
            { text: "Terminate process handles executing unauthorized outbound data transit", correct: true },
            { text: "Reboot the database server to clear active network connections", correct: false },
            { text: "Add the destination malicious IP to the internal DNS safe list", correct: false }
        ]
    },
    "T1046": {
        title: "Network Service Discovery / Port Scan",
        options: [
            { text: "Acknowledge recon event and cross-reference block lists", correct: true },
            { text: "Shut down the perimeter firewall interface completely", correct: false },
            { text: "Launch a counter port-scan attack back at the source IP", correct: false }
        ]
    },
    "T1053.005": {
        title: "Scheduled Task Persistence Anomaly",
        options: [
            { text: "Format the server's hard drive immediately", correct: false },
            { text: "Delete unauthorized Scheduled Task registry structures via EDR tools", correct: true },
            { text: "Change the system time zone settings to stall execution", correct: false }
        ]
    },
    "T1078": {
        title: "Out-of-Hours Account Login Anomaly",
        options: [
            { text: "Verify user identity via an out-of-band communication channel", correct: true },
            { text: "Approve the traffic automatically to avoid user workflow disruption", correct: false },
            { text: "Assume a system clock failure and clear the event entry", correct: false }
        ]
    },
    "Default": {
        title: "General Security Incident Triage",
        options: [
            { text: "Acknowledge Event & Escalate to Tier 2 Queues", correct: true },
            { text: "Discard logs to save database storage capacity", correct: false },
            { text: "Label event as a permanent false positive", correct: false }
        ]
    }
};
