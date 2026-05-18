// js/app.js  — v3: high-entropy SIEM simulation

// ── Asset pool ─────────────────────────────────────────────────────────────────
const assets = [
    // Domain / Identity
    "DC-01.corp", "DC-02.corp", "ADFS-SRV-01",
    // Databases
    "SQL-PROD-02", "SQL-REPLICA-03", "MONGO-ANALYTICS-01",
    // Endpoints / Workstations
    "WS-ENG-491", "WS-FIN-112", "WS-HR-204", "LAPTOP-EXEC-07",
    // Perimeter / Network
    "GW-BORDER-01", "FW-CORE-02", "VPN-CONCENTRATOR-01", "DMZ-WEB-01",
    // Cloud / Container
    "CLOUD-KUBE-04", "CLOUD-S3-PROXY", "CLOUD-LAMBDA-09",
    // Enterprise Apps
    "SAP-FIN-01", "EXCHANGE-MBX-01", "SHAREPOINT-FARM-02"
];

// ── Source geo / ISP pool ──────────────────────────────────────────────────────
const sourceContexts = [
    "London, UK (AS5089 Virgin Media)",
    "Frankfurt, DE (AS3320 Deutsche Telekom)",
    "Ashburn, VA, US (AS7018 AT&T)",
    "Unknown / TOR Exit Node",
    "Unknown / VPN Proxy (Mullvad)",
    "Tokyo, JP (AS2516 KDDI)",
    "Sydney, AU (AS4804 Microplex PTY)",
    "Amsterdam, NL (AS20940 Akamai)",
    "Moscow, RU (AS8359 MTS)",
    "Beijing, CN (AS4134 Chinanet)",
    "Sao Paulo, BR (AS18881 TELEFONICA)",
    "Bucharest, RO (AS9050 ROMTELECOM)",
    "Lagos, NG (AS37148 IPNX Nigeria)",
    "Singapore, SG (AS4657 StarHub)",
    "Seoul, KR (AS4766 Korea Telecom)",
    "Stockholm, SE (AS1257 Tele2)",
    "Chicago, IL, US (AS11427 TWC)",
    "Toronto, CA (AS577 Bell Canada)",
    "Kyiv, UA (AS15895 Kyivstar)",
    "Dubai, AE (AS5384 ETISALAT-UAE)",
    "Istanbul, TR (AS9121 Turk Telekomunikasyon)"
];

// ── Contextual injection pools ─────────────────────────────────────────────────
const usernames = [
    "j.harris", "m.chen", "a.patel", "l.okonkwo", "r.schmidt",
    "t.nguyen", "s.kowalski", "d.fernandez", "k.yamamoto", "p.osei",
    "svc_backup", "svc_monitor", "svc_deploy", "adm_legacy", "adm_sa01",
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"
];

const processes = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "msiexec.exe", "svchost.exe (non-std path)",
    "python3.exe", "node.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe"
];

const filePaths = [
    "C:\\Users\\Public\\Downloads\\update.exe",
    "C:\\Windows\\Temp\\svc32.dll",
    "C:\\ProgramData\\Intel\\telemetry.ps1",
    "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.exe",
    "C:\\Windows\\System32\\Tasks\\MicrosoftEdgeUpdateBroker",
    "/tmp/.hidden/beacon",
    "/var/www/html/.htaccess.php",
    "\\\\DC-01\\SYSVOL\\scripts\\logon.bat",
    "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Users\\svc_backup\\AppData\\Roaming\\update\\svch0st.exe"
];

const registryKeys = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "HKCU\\Environment\\UserInitMprLogonScript"
];

const ports      = [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 4444, 5985, 6379, 8080, 8443, 9200, 27017];
const taskNames  = ["MicrosoftEdgeUpdateBroker", "GoogleUpdateTaskUser", "WinDefendHelper",
                    "AdobeFlashUpdate", "JavaAutoUpdate", "NvidiaTelemetry",
                    "IntelThermalMgr", "OneDriveStandaloneUpdater", "SysMonTask"];
const extensions = ["enc", "locked", "crypted", "WNCRY", "pay2key", "deadbolt"];
const timeStrs   = ["02:14:07", "03:41:22", "23:58:01", "04:07:55", "01:19:33", "00:03:11"];

// ── Weighted signature pool ────────────────────────────────────────────────────
const signaturePool = [
    // LOW
    { sev: "Low", mitre: "T1046", weight: 8, templates: [
        "Inbound {{port_count}}-port TCP sweep detected from {{src_ip}} against perimeter",
        "Network recon: SYN scan across ports {{port_a}}-{{port_b}} logged at border",
        "NMAP-style OS fingerprinting probe from {{src_ip}} flagged by IDS",
        "Sequential port probe on {{asset}} — {{port_count}} attempts in 12 seconds",
        "Stealth FIN scan from {{src_ip}}, targeting service enumeration"
    ]},
    { sev: "Low", mitre: "T1078", weight: 6, templates: [
        "Stale account {{username}} authenticated outside business hours from {{src_ip}}",
        "Dormant service account {{username}} login at {{time_str}} — last seen 47 days ago",
        "VPN auth for {{username}} from unexpected geo: {{location}}",
        "Shared admin account {{username}} login — no MFA challenge recorded",
        "{{username}} authenticated from {{location}} — prior session was domestic"
    ]},
    { sev: "Low", mitre: "T1018", weight: 5, templates: [
        "Net view / domain enumeration commands run by {{username}} on {{asset}}",
        "LDAP query flood from {{asset}} — {{port_count}} object lookups in 30 seconds",
        "BloodHound-compatible SAMR pipe calls observed from {{username}}",
        "Ping sweep of /24 subnet initiated from workstation {{asset}}",
        "Internal DNS zone transfer requested from non-authoritative host {{asset}}"
    ]},
    { sev: "Low", mitre: "T1070.004", weight: 4, templates: [
        "Windows event log cleared on {{asset}} by {{username}}",
        "Security audit log deletion detected — {{port_count}} entries removed on {{asset}}",
        "Prefetch file mass deletion by {{process}} on {{asset}}",
        "USN journal purge executed via fsutil.exe on {{asset}}",
        "Anti-forensics: timestomping activity detected on {{file_path}}"
    ]},
    // MEDIUM
    { sev: "Medium", mitre: "T1053.005", weight: 7, templates: [
        "Unauthorized scheduled task '{{task_name}}' registered under SYSTEM on {{asset}}",
        "New persistence task created by {{process}} pointing to {{file_path}}",
        "Scheduled task modification detected — trigger changed to logon-based on {{asset}}",
        "schtasks.exe /create invoked with hidden flag by {{username}} on {{asset}}",
        "COM object hijack via task XML on {{asset}} — registry: {{reg_key}}"
    ]},
    { sev: "Medium", mitre: "T1059.001", weight: 7, templates: [
        "Base64-encoded PowerShell payload executed via {{process}} on {{asset}}",
        "PowerShell -EncodedCommand flag detected — IEX download cradle suspected on {{asset}}",
        "Constrained Language Mode bypass attempted by {{username}} on {{asset}}",
        "AMSI bypass string pattern detected in PowerShell transcript on {{asset}}",
        "Obfuscated PS1 script launched from {{file_path}} — entropy score: 7.4"
    ]},
    { sev: "Medium", mitre: "T1059.003", weight: 5, templates: [
        "cmd.exe spawned from non-interactive parent {{process}} on {{asset}}",
        "Suspicious cmd.exe /c invocation with chained operators on {{asset}}",
        "Batch file {{file_path}} executed with SYSTEM privileges on {{asset}}",
        "cmd.exe launched from {{file_path}} — anomalous execution chain",
        "Command shell spawned by Office macro process on {{asset}}"
    ]},
    { sev: "Medium", mitre: "T1547.001", weight: 5, templates: [
        "Registry run-key persistence added: {{reg_key}} pointing to {{file_path}}",
        "Startup folder entry created by {{process}} on {{asset}}",
        "HKCU Run key modified by non-admin {{username}} on {{asset}}",
        "Winlogon userinit hijack detected in registry on {{asset}}",
        "New autorun entry pointing to {{file_path}} registered on {{asset}}"
    ]},
    { sev: "Medium", mitre: "T1027", weight: 4, templates: [
        "High-entropy DLL dropped to {{file_path}} — possible packing detected",
        "certutil.exe -decode invocation on {{asset}} — binary decoding in progress",
        "XOR-obfuscated shellcode pattern found in {{process}} memory on {{asset}}",
        "Steganographic payload extracted from image file on {{asset}}",
        "Compiled HTML Help (.chm) execution on {{asset}} — rare process lineage"
    ]},
    { sev: "Medium", mitre: "T1566.001", weight: 6, templates: [
        "Phishing email with weaponised attachment delivered to {{username}}@corp",
        "Macro-enabled Office document opened by {{username}} on {{asset}}",
        "Email link clicked leading to credential harvest page — user: {{username}}",
        "Suspicious .lnk attachment executed from Outlook on {{asset}}",
        "PDF exploit attempted via email attachment on {{username}}s workstation"
    ]},
    // HIGH
    { sev: "High", mitre: "T1110", weight: 7, templates: [
        "SSH brute force: {{port_count}} failed attempts from {{src_ip}} against {{asset}}",
        "Password spray: {{port_count}} accounts targeted from single IP {{src_ip}}",
        "RDP brute force: {{port_count}} auth failures on {{asset}} in under 60 seconds",
        "Credential stuffing via web login from {{src_ip}} — {{port_count}} attempts",
        "Kerberos pre-auth failures spiking — AS-REP roasting suspected on {{asset}}"
    ]},
    { sev: "High", mitre: "T1204.002", weight: 6, templates: [
        "Malicious macro payload executed from email attachment on {{asset}}",
        "User {{username}} opened weaponised Excel document — {{process}} spawned",
        "Drive-by download triggered from phishing link on {{asset}} — payload: {{file_path}}",
        "ISO/LNK smuggling execution chain initiated on {{asset}} by {{username}}",
        "OneNote embedded payload executed by {{username}} on {{asset}}"
    ]},
    { sev: "High", mitre: "T1048", weight: 6, templates: [
        "Anomalous outbound transfer: {{data_mb}}MB to {{src_ip}} over port {{port_b}} from {{asset}}",
        "DNS tunnelling exfiltration pattern detected from {{asset}} to {{src_ip}}",
        "HTTPS POST flood to uncategorised domain — {{data_mb}}MB in 8 minutes from {{asset}}",
        "Rclone.exe detected syncing to external cloud endpoint from {{asset}}",
        "FTP data channel to {{src_ip}}:{{port_b}} initiated outside change window on {{asset}}"
    ]},
    { sev: "High", mitre: "T1021.001", weight: 5, templates: [
        "Lateral RDP from {{asset}} to internal DC — user: {{username}}",
        "Pass-the-hash RDP auth detected to {{asset}} — no plaintext creds used",
        "RDP session from jump host to {{asset}} at {{time_str}} — unscheduled",
        "Concurrent RDP sessions from geo-dispersed IPs on {{asset}}",
        "RDP tunnelled over non-standard port {{port_b}} to {{asset}}"
    ]},
    { sev: "High", mitre: "T1055", weight: 5, templates: [
        "Process injection into {{process}} on {{asset}} — shellcode pattern matched",
        "CreateRemoteThread call targeting lsass.exe from non-system process on {{asset}}",
        "Reflective DLL injection via {{process}} on {{asset}} — no disk artifact",
        "Process hollowing of {{process}} detected by EDR heuristics on {{asset}}",
        "AtomBombing technique signature observed in {{process}} on {{asset}}"
    ]},
    { sev: "High", mitre: "T1190", weight: 4, templates: [
        "Web application exploit attempt on {{asset}} — CVE-pattern URI string from {{src_ip}}",
        "SQL injection payload in POST body targeting {{asset}} login endpoint",
        "Log4Shell exploitation attempt on {{asset}} from {{src_ip}}",
        "XXE injection in SOAP body targeting {{asset}} internal service",
        "Path traversal exploit: ../../../etc/passwd pattern on {{asset}} web root"
    ]},
    { sev: "High", mitre: "T1562.001", weight: 4, templates: [
        "Windows Defender real-time protection disabled on {{asset}} by {{username}}",
        "EDR agent process terminated via kill signal on {{asset}}",
        "Security tool uninstall detected — AV removed from {{asset}}",
        "Firewall rules flushed via netsh.exe on {{asset}} — all inbound now permitted",
        "Audit policy modified to suppress security event generation on {{asset}}"
    ]},
    // CRITICAL
    { sev: "Critical", mitre: "T1003.001", weight: 4, templates: [
        "Mimikatz LSASS dump signature detected in memory on {{asset}}",
        "LSASS process accessed by non-system process {{process}} on {{asset}}",
        "Credential dump via procdump.exe targeting lsass.exe on {{asset}}",
        "WDigest credential caching re-enabled in registry on {{asset}} — harvest suspected",
        "LSASS handle opened with PROCESS_VM_READ rights by {{process}} on {{asset}}"
    ]},
    { sev: "Critical", mitre: "T1486", weight: 3, templates: [
        "Ransomware-pattern mass file encryption on {{asset}} — {{port_count}} files/min",
        "Shadow copy deletion via vssadmin.exe on {{asset}} — ransomware pre-stage",
        "High-volume .{{ext}} rename activity on {{asset}} — possible live encryption",
        "Ransom note dropped to multiple directories on {{asset}}: README_DECRYPT.txt",
        "Volume shadow wipe + rapid file modification on {{asset}} — contain immediately"
    ]},
    { sev: "Critical", mitre: "T1078.002", weight: 3, templates: [
        "Domain Admin {{username}} used from workstation outside PAW policy on {{asset}}",
        "Enterprise Admin credential replay across {{port_count}} hosts simultaneously",
        "Golden Ticket suspected — {{username}} auth with unusually long ticket lifetime",
        "DCSync operation performed by non-DC account {{username}} from {{asset}}",
        "Domain Admin {{username}} logged in via RDP from unmanaged device {{src_ip}}"
    ]},
    { sev: "Critical", mitre: "T1136.002", weight: 2, templates: [
        "New domain admin account '{{task_name}}' created outside change management window",
        "Backdoor local admin '{{task_name}}' added to Domain Admins by {{username}}",
        "AD account creation + immediate privilege escalation sequence on {{asset}}",
        "Hidden admin creation via net.exe detected on {{asset}} by {{username}}",
        "Rogue user '{{task_name}}' added to Backup Operators group on {{asset}}"
    ]},
    { sev: "Critical", mitre: "T1059.005", weight: 3, templates: [
        "WMI persistent subscription created for lateral execution on {{asset}} by {{username}}",
        "WMIC process call create spawning {{process}} from remote host {{src_ip}}",
        "WMI event consumer '{{task_name}}' registered — fileless execution mechanism",
        "ActiveScriptEventConsumer writing {{file_path}} via WMI subscription on {{asset}}",
        "WMI namespace backdoor on {{asset}} — command-and-control channel suspected"
    ]}
];

// Build weighted draw pool
const weightedPool = [];
signaturePool.forEach(sig => {
    for (let i = 0; i < (sig.weight || 1); i++) weightedPool.push(sig);
});

// ── Random helpers ─────────────────────────────────────────────────────────────
const rnd      = (n)    => Math.floor(Math.random() * n);
const pick     = (arr)  => arr[rnd(arr.length)];
const rndRange = (a, b) => a + rnd(b - a + 1);

function generateRandomIP() {
    return `${rndRange(2, 217)}.${rndRange(1, 254)}.${rndRange(1, 254)}.${rndRange(1, 254)}`;
}

function resolveTemplate(template) {
    const portA = pick(ports);
    const portB = pick(ports.filter(p => p !== portA));
    return template
        .replace(/{{src_ip}}/g,      generateRandomIP())
        .replace(/{{location}}/g,    pick(sourceContexts))
        .replace(/{{username}}/g,    pick(usernames))
        .replace(/{{process}}/g,     pick(processes))
        .replace(/{{file_path}}/g,   pick(filePaths))
        .replace(/{{reg_key}}/g,     pick(registryKeys))
        .replace(/{{port_a}}/g,      portA)
        .replace(/{{port_b}}/g,      portB)
        .replace(/{{port_count}}/g,  rndRange(12, 994))
        .replace(/{{data_mb}}/g,     rndRange(80, 4800))
        .replace(/{{task_name}}/g,   pick(taskNames))
        .replace(/{{ext}}/g,         pick(extensions))
        .replace(/{{time_str}}/g,    pick(timeStrs))
        .replace(/{{asset}}/g,       pick(assets));
}

// ── Analyst notes ──────────────────────────────────────────────────────────────
const analystNoteTemplates = [
    "First occurrence on this asset in 30 days. Correlated with 2 prior low-severity alerts.",
    "Source IP flagged in threat intel feed (AlienVault OTX) — associated with Lazarus Group TTPs.",
    "Confidence: HIGH. EDR telemetry and SIEM correlation both independently triggered.",
    "No prior baseline for this behaviour on the asset. Treat as suspicious until confirmed.",
    "Similar signature fired on DMZ-WEB-01 six minutes ago — possible coordinated activity.",
    "Source ASN previously seen in credential-stuffing campaigns targeting financial sector.",
    "Matches a Cobalt Strike beacon pattern from recent threat intelligence brief.",
    "Account {{username}} was reported on PTO — activity is anomalous.",
    "Geo-velocity anomaly: same account authenticated from London and Singapore within 18 minutes.",
    "Process ancestry: explorer.exe → winword.exe → {{process}} — classic spear-phish chain.",
    "Third alert of this type in 90 minutes. Escalation threshold approaching.",
    "Firewall logs confirm bidirectional traffic — possible C2 channel established.",
    "Asset is a Crown Jewel system. Confirmed threats should auto-escalate to Tier 2.",
    "Sandbox detonation of recovered binary: malicious — 42/72 AV detections.",
    "No matching change ticket in ITSM. Activity is out-of-policy.",
    "IOC matches known Cl0p ransomware affiliate infrastructure.",
    "Behaviour consistent with Living-off-the-Land (LotL) tradecraft — low tool footprint.",
    "Similar TTP observed in recent CISA advisory AA24-038A.",
    "Host has not received patch KB5031356 — exploitation window open.",
    "Alert auto-correlated with 4 other events on the same subnet in the last hour."
];

function getAnalystNote() {
    return resolveTemplate(pick(analystNoteTemplates));
}

// ── State ──────────────────────────────────────────────────────────────────────
const DEFAULT_STATE = {
    totalIncidents:    0,
    highRisks:         0,
    investigatedCount: 0,
    containedCount:    0,
    escalatedCount:    0,
    serverTallies:     {},
    secondsElapsed:    0,
    investigatedIDs:   [],
    theme:             "dark"
};

let state = { ...DEFAULT_STATE };
try {
    const saved = localStorage.getItem('soc_sim_state');
    if (saved) state = { ...DEFAULT_STATE, ...JSON.parse(saved) };
} catch (_) {}

const investigatedAlerts = new Set(state.investigatedIDs || []);
let currentActiveAlert   = null;
let metricsExpanded      = false;
let cadenceTimeout;

// ── Theme ──────────────────────────────────────────────────────────────────────
initializeActiveTheme();

function initializeActiveTheme() {
    const htmlEl = document.documentElement;
    const btn    = document.getElementById('theme-btn');
    if (state.theme === "dark") {
        htmlEl.classList.add('dark');
        if (btn) btn.innerText = "☀️ LIGHT MODE";
    } else {
        htmlEl.classList.remove('dark');
        if (btn) btn.innerText = "🌙 DARK MODE";
    }
}

function toggleSystemTheme() {
    state.theme = state.theme === "dark" ? "light" : "dark";
    persistState();
    initializeActiveTheme();
}

// ── Mobile sidebar ─────────────────────────────────────────────────────────────
function toggleMetricsSidebar() {
    metricsExpanded = !metricsExpanded;
    const sidebar = document.getElementById('metrics-sidebar');
    const btn     = document.getElementById('metrics-toggle-btn');
    if (!sidebar) return;
    if (metricsExpanded) {
        sidebar.classList.remove('collapsed');
        sidebar.classList.add('expanded');
        if (btn) btn.innerText = "📊 HIDE";
    } else {
        sidebar.classList.remove('expanded');
        sidebar.classList.add('collapsed');
        if (btn) btn.innerText = "📊 METRICS";
    }
}

// ── Persistence ────────────────────────────────────────────────────────────────
function persistState() {
    state.investigatedIDs = [...investigatedAlerts];
    try { localStorage.setItem('soc_sim_state', JSON.stringify(state)); } catch (_) {}
}

// ── Alert generation ───────────────────────────────────────────────────────────
function createProceduralAlert() {
    const asset    = pick(assets);
    const sigDef   = pick(weightedPool);
    const text     = resolveTemplate(pick(sigDef.templates));
    const loc      = pick(sourceContexts);
    const detail   = `[${sigDef.mitre}] ${text} (${loc})`;
    const ts       = new Date().toLocaleTimeString();

    state.totalIncidents++;
    if (sigDef.sev === "High" || sigDef.sev === "Critical") state.highRisks++;
    if (!state.serverTallies[asset]) state.serverTallies[asset] = { Low: 0, Medium: 0, High: 0, Critical: 0 };
    state.serverTallies[asset][sigDef.sev]++;

    persistState();
    renderAlertRow(ts, asset, detail, sigDef.sev, sigDef.mitre);
    updateMetricsUI();
}

// ── Variable cadence — with burst waves ────────────────────────────────────────
function scheduleNextAlert() {
    const isBurst   = Math.random() < 0.08;
    const baseDelay = isBurst ? rndRange(8000, 18000) : rndRange(3000, 9000);

    cadenceTimeout = setTimeout(() => {
        createProceduralAlert();
        if (isBurst) {
            const burstCount = rndRange(2, 4);
            for (let i = 1; i <= burstCount; i++) {
                setTimeout(createProceduralAlert, i * rndRange(400, 900));
            }
        }
        scheduleNextAlert();
    }, baseDelay);
}

// ── Render ─────────────────────────────────────────────────────────────────────
function renderAlertRow(time, asset, msg, severity, mitre) {
    const tbody = document.getElementById('alert-stream-body');

    const badgeMap = {
        Low:      "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400 border border-blue-200 dark:border-blue-900/30",
        Medium:   "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-900/30",
        High:     "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 border border-orange-200 dark:border-orange-900/30 font-bold",
        Critical: "bg-red-100 dark:bg-red-950/50 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-900 animate-pulse font-extrabold"
    };
    const badgeClass = badgeMap[severity] || "bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700";

    const safeAsset = asset.replace(/'/g, "\\'");
    const alertID   = `${Date.now()}-${mitre}-${Math.random().toString(36).slice(2, 7)}`;
    const safeID    = alertID.replace(/'/g, "\\'");

    const row = document.createElement('tr');
    row.className = "hover:bg-slate-200/50 dark:hover:bg-slate-900/60 transition-colors border-b border-slate-200 dark:border-slate-900/50 cursor-pointer text-slate-700 dark:text-slate-400";
    row.setAttribute("onclick", `loadPlaybook('${mitre}', '${safeAsset}', this, '${safeID}')`);

    row.innerHTML = `
        <td class="py-2.5 pr-3 font-mono text-xs text-slate-400 dark:text-slate-500 align-top pt-3">${time}</td>
        <td class="py-2.5 pr-3 font-semibold text-slate-800 dark:text-slate-300 align-top pt-3 whitespace-nowrap">${asset}</td>
        <td class="py-2.5 pr-4 msg-cell text-slate-800 dark:text-slate-400 align-top pt-3">${msg}</td>
        <td class="py-2.5 text-center align-top pt-3"><span class="px-2 py-0.5 rounded text-xs ${badgeClass}">${severity}</span></td>
        <td class="py-2.5 text-right align-top pt-3">
            <button class="text-xs text-emerald-800 dark:text-emerald-400 bg-emerald-100/50 dark:bg-emerald-950/30 border border-emerald-300 dark:border-emerald-900 px-2 py-1.5 sm:py-1 rounded font-bold min-w-[56px]">Triage</button>
        </td>
    `;

    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 30) tbody.removeChild(tbody.lastChild);
}

// ── Playbook ───────────────────────────────────────────────────────────────────
function loadPlaybook(mitreID, assetName, rowElement, alertID) {
    const desk     = document.getElementById('playbook-content');
    const playbook = playbooks[mitreID] || playbooks["Default"];

    currentActiveAlert = { row: rowElement, asset: assetName, mitre: mitreID, id: alertID };

    if (!investigatedAlerts.has(alertID)) {
        investigatedAlerts.add(alertID);
        state.investigatedCount++;
        persistState();
        updateMetricsUI();
    }

    // Each playbook has multiple option sets — pick one randomly
    const optionSets = playbook.optionSets || [playbook.options];
    const shuffled   = [...pick(optionSets)].sort(() => Math.random() - 0.5);
    const note       = getAnalystNote();

    const choicesHTML = shuffled.map(opt => `
        <button onclick="submitMitigationChoice(${opt.correct})"
                class="w-full text-left font-sans text-xs bg-white border border-slate-200 hover:border-slate-400 active:bg-slate-100 text-slate-800 dark:bg-slate-950/60 dark:border-slate-800 dark:hover:border-slate-600 dark:hover:bg-slate-900 dark:text-slate-300 p-3 rounded transition-all cursor-pointer shadow-sm">
            🔹 ${opt.text}
        </button>
    `).join('');

    desk.innerHTML = `
        <div class="w-full flex flex-col h-full justify-between text-left">
            <div>
                <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-2 border-b border-slate-200 dark:border-slate-900 pb-1.5 gap-1">
                    <h3 class="text-emerald-700 dark:text-emerald-400 font-bold text-xs uppercase">${playbook.title}</h3>
                    <span class="text-[11px] text-slate-500">Asset: <b class="text-slate-800 dark:text-slate-300">${assetName}</b> &nbsp;·&nbsp; MITRE: <b class="text-slate-700 dark:text-slate-300">${mitreID}</b></span>
                </div>
                <div class="text-[10px] bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/30 text-amber-800 dark:text-amber-400 rounded px-2 py-1.5 mb-3 font-sans italic">
                    📋 Analyst note: ${note}
                </div>
                <p class="text-[11px] text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3">Select the correct incident containment procedure:</p>
                <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 sm:gap-3">${choicesHTML}</div>
            </div>
        </div>
    `;
}

function submitMitigationChoice(isCorrect) {
    if (!currentActiveAlert) return;
    const desk = document.getElementById('playbook-content');

    if (isCorrect) {
        state.containedCount++;
        persistState();
        currentActiveAlert.row.style.opacity = '0.3';
        currentActiveAlert.row.removeAttribute('onclick');
        currentActiveAlert.row.style.cursor  = 'default';
        const btn = currentActiveAlert.row.querySelector('button');
        if (btn) { btn.innerText = "Mitigated"; btn.className = "text-xs text-slate-400 dark:text-slate-600 border border-slate-200 dark:border-slate-900 bg-transparent px-2 py-1 rounded cursor-not-allowed min-w-[56px]"; }
        desk.innerHTML = `<div class="flex flex-col items-center justify-center text-center py-4 gap-2">
            <span class="text-emerald-700 dark:text-emerald-500 font-bold text-sm tracking-wide">✔ THREAT CONTAINED SUCCESSFULLY</span>
            <span class="text-xs text-slate-500 dark:text-slate-400 max-w-sm">Correct remediation vector applied. Incident closed. Continue monitoring SIEM telemetry.</span>
        </div>`;
    } else {
        state.escalatedCount++;
        persistState();
        currentActiveAlert.row.style.opacity = '0.4';
        currentActiveAlert.row.removeAttribute('onclick');
        currentActiveAlert.row.style.cursor  = 'default';
        const btn = currentActiveAlert.row.querySelector('button');
        if (btn) { btn.innerText = "Escalated"; btn.className = "text-xs text-red-600 border border-red-200 bg-red-50 dark:text-red-400 dark:border-red-950 dark:bg-red-950/10 px-2 py-1 rounded cursor-not-allowed min-w-[56px]"; }
        desk.innerHTML = `<div class="flex flex-col items-center justify-center text-center py-4 gap-2">
            <span class="text-red-700 dark:text-red-500 font-bold text-sm tracking-wide">❌ NOT CONTAINED — ESCALATING THREAT</span>
            <span class="text-xs text-slate-600 dark:text-slate-400 max-w-md">Incorrect protocol chosen. Incident automatically escalated to Tier-3 engineering for emergency response.</span>
        </div>`;
    }

    currentActiveAlert = null;
    updateMetricsUI();
}

// ── Metrics UI ─────────────────────────────────────────────────────────────────
function updateMetricsUI() {
    document.getElementById('tally-high').innerText          = state.highRisks;
    document.getElementById('tally-total').innerText         = state.totalIncidents;
    document.getElementById('tally-investigated').innerText  = state.investigatedCount;
    document.getElementById('tally-contained').innerText     = state.containedCount;
    document.getElementById('tally-escalated').innerText     = state.escalatedCount;

    const container = document.getElementById('server-tally-list');
    container.innerHTML = '';
    const sorted = Object.keys(state.serverTallies).sort((a, b) => {
        const s = (t) => (state.serverTallies[t].Critical||0)*4 + (state.serverTallies[t].High||0)*2 + (state.serverTallies[t].Medium||0);
        return s(b) - s(a);
    });
    sorted.slice(0, 4).forEach(server => {
        const c = state.serverTallies[server];
        const item = document.createElement('div');
        item.className = "flex justify-between items-center bg-white border border-slate-200 dark:bg-slate-950/60 dark:border-slate-900 p-1.5 rounded";
        item.innerHTML = `
            <span class="font-bold text-slate-700 dark:text-slate-400 text-xs truncate mr-2">${server}</span>
            <div class="flex gap-1 text-[9px] font-sans shrink-0">
                <span class="bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-400 px-1 rounded">${c.Critical||0}C</span>
                <span class="bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-400 px-1 rounded">${c.High||0}H</span>
                <span class="bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-400 px-1 rounded">${c.Medium||0}M</span>
                <span class="bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-400 px-1 rounded">${c.Low||0}L</span>
            </div>`;
        container.appendChild(item);
    });
}

// ── Reset ──────────────────────────────────────────────────────────────────────
function resetSimulationSession() {
    if (confirm("Are you sure you want to terminate this operational monitoring shift? All current session metrics and tallies will be permanently wiped.")) {
        clearTimeout(cadenceTimeout);
        localStorage.removeItem('soc_sim_state');
        window.location.reload();
    }
}

// ── Shift clock ────────────────────────────────────────────────────────────────
setInterval(() => {
    state.secondsElapsed++;
    const elapsed = Math.min(state.secondsElapsed, 8 * 3600);
    const fmt = (n) => String(n).padStart(2, '0');
    document.getElementById('sim-clock').innerText =
        `Shift Time: ${fmt(Math.floor(elapsed/3600))}:${fmt(Math.floor((elapsed%3600)/60))}:${fmt(elapsed%60)} / 08:00:00`;
    if (state.secondsElapsed % 10 === 0) persistState();
}, 1000);

// ── Boot ───────────────────────────────────────────────────────────────────────
updateMetricsUI();
createProceduralAlert();
scheduleNextAlert();