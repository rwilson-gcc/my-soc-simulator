// js/playbooks.js

const playbooks = {
    "T1110": {
        title: "Brute Force / Credential Stuffing Response",
        steps: [
            "Verify source IP geolocation against known company VPN profiles.",
            "Temporarily lock out target account from Active Directory/IdP.",
            "Check for successful logins directly following the brute force attempts."
        ],
        remediation: "Block Attacker IP on Perimeter Firewall"
    },
    "T1003.001": {
        title: "LSASS Credential Dumping Event",
        steps: [
            "Confirm if the executing file path is an approved administrative utility.",
            "Collect Endpoint Detection & Response (EDR) memory triage dump.",
            "Isolate the host immediately from the local network segment."
        ],
        remediation: "Isolate Host via EDR"
    },
    "T1204.002": {
        title: "Malicious Phishing Execution Workflow",
        steps: [
            "Locate parent email message ID in the secure email gateway logs.",
            "Identify and purge matching emails from all user mailboxes globally.",
            "Force-expire active user session tokens and initiate a password reset."
        ],
        remediation: "Revoke User Session Tokens"
    },
    "T1048": {
        title: "Data Exfiltration / Egress Spike Triage",
        steps: [
            "Identify protocol used for data transit (DNS, HTTPS, FTP).",
            "Trace internal process ID responsible for initiating the connection.",
            "Cross-reference transfer volume against corporate data loss prevention policies."
        ],
        remediation: "Kill Network Connection Handle"
    },
    "T1046": {
        title: "Network Service Discovery / Port Scan",
        steps: [
            "Identify scope of target ports scanned on the perimeter interface.",
            "Cross-reference source IP against global threat intelligence feeds.",
            "Verify perimeter firewall drop rules are actively rejecting traffic."
        ],
        remediation: "Acknowledge Recon Event"
    },
    "T1053.005": {
        title: "Scheduled Task Persistence Anomaly",
        steps: [
            "Review task XML definitions inside Windows Task Scheduler logs.",
            "Identify user token context responsible for registering the task binaries.",
            "Check endpoint execution history for unexpected script parameters."
        ],
        remediation: "Delete Scheduled Task via EDR"
    },
    "T1078": {
        title: "Out-of-Hours Account Login Anomaly",
        steps: [
            "Verify account owner's typical working pattern adjustments.",
            "Check host sign-in geography context for concurrent logons (impossible travel).",
            "Confirm multi-factor authentication (MFA) token challenge succeeded."
        ],
        remediation: "Verify User Identity via Out-of-Band Channel"
    },
    "Default": {
        title: "General Security Incident Triage",
        steps: [
            "Review associated raw system logs for context.",
            "Identify endpoint owner and critical asset tier assignment.",
            "Escalate to tier-2 incident response queue if behavior continues."
        ],
        remediation: "Acknowledge Event"
    }
};