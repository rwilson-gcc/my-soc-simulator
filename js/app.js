// js/app.js

const assets = ["DC-01.corp", "SQL-PROD-02", "WS-ENG-491", "DMZ-WEB-01", "SAP-FIN-01", "GW-BORDER-01", "CLOUD-KUBE-04"];
const locations = ["London, UK", "Frankfurt, DE", "Ashburn, US", "Unknown / VPN Proxy", "Tokyo, JP", "Sydney, AU"];

const signatures = [
    { text: "Inbound port sweep detected on perimeter", sev: "Low", mitre: "T1046" },
    { text: "Stale domain account logged in out-of-hours", sev: "Low", mitre: "T1078" },
    { text: "Unusual scheduled task registered by SYSTEM", sev: "Medium", mitre: "T1053.005" },
    { text: "Base64 encoded PowerShell command string passed", sev: "Medium", mitre: "T1059.001" },
    { text: "Brute force attempts detected via SSH interfaces", sev: "High", mitre: "T1110" },
    { text: "Phishing payload executed from local mail agent", sev: "High", mitre: "T1204.002" },
    { text: "Massive outbound data egress transfer initiated", sev: "High", mitre: "T1048" },
    { text: "Mimikatz LSASS dump signature found in host memory", sev: "Critical", mitre: "T1003.001" }
];

let state = { 
    totalIncidents: 0, 
    highRisks: 0, 
    investigatedCount: 0,
    containedCount: 0,
    serverTallies: {}, 
    secondsElapsed: 0,
    theme: "dark" // Main operational display configuration flag
};

let currentActiveAlert = null;
const investigatedAlerts = new Set(); 

if (localStorage.getItem('soc_sim_state')) {
    const savedState = JSON.parse(localStorage.getItem('soc_sim_state'));
    state = { ...state, ...savedState };
}

// Ensure theme alignment is executed early on system bootstrapping
initializeActiveTheme();

function initializeActiveTheme() {
    const htmlEl = document.documentElement;
    const btn = document.getElementById('theme-btn');
    
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
    localStorage.setItem('soc_sim_state', JSON.stringify(state));
    initializeActiveTheme();
}

function generateRandomIP() {
    return `${Math.floor(Math.random() * 218) + 2}.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`;
}

function createProceduralAlert() {
    const asset = assets[Math.floor(Math.random() * assets.length)];
    const sig = signatures[Math.floor(Math.random() * signatures.length)];
    const detailedMessage = `[${sig.mitre}] ${sig.text} (Src: ${generateRandomIP()} [${locations[Math.floor(Math.random() * locations.length)]}])`;
    const timestamp = new Date().toLocaleTimeString();

    state.totalIncidents++;
    if (sig.sev === "High" || sig.sev === "Critical") state.highRisks++;

    if (!state.serverTallies[asset]) state.serverTallies[asset] = { Low: 0, Medium: 0, High: 0, Critical: 0 };
    state.serverTallies[asset][sig.sev]++;

    localStorage.setItem('soc_sim_state', JSON.stringify(state));

    renderAlertRow(timestamp, asset, detailedMessage, sig.sev, sig.mitre);
    updateMetricsUI();
}

function renderAlertRow(time, asset, msg, severity, mitre) {
    const tbody = document.getElementById('alert-stream-body');
    
    let badgeClass = "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-300 dark:border-slate-700";
    if (severity === "Low") badgeClass = "bg-blue-50 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-900/30";
    if (severity === "Medium") badgeClass = "bg-amber-50 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900/30";
    if (severity === "High") badgeClass = "bg-orange-50 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400 border border-orange-200 dark:border-orange-900/30 font-bold";
    if (severity === "Critical") badgeClass = "bg-red-50 dark:bg-red-950/50 text-red-600 dark:text-red-400 border border-red-300 dark:border-red-900 animate-pulse font-extrabold";

    const row = document.createElement('tr');
    row.className = "hover:bg-slate-100/60 dark:hover:bg-slate-900/60 transition-colors border-b border-slate-100 dark:border-slate-900/50 cursor-pointer text-slate-600 dark:text-slate-400";
    const uniqueAlertID = `${time}-${mitre}`;
    row.setAttribute("onclick", `loadPlaybook('${mitre}', '${asset}', this, '${uniqueAlertID}')`);
    
    row.innerHTML = `
        <td class="py-2.5 font-mono text-xs text-slate-400 dark:text-slate-500">${time}</td>
        <td class="py-2.5 font-semibold text-slate-700 dark:text-slate-300">${asset}</td>
        <td class="py-2.5 pr-4 truncate max-w-md">${msg}</td>
        <td class="py-2.5 text-center"><span class="px-2 py-0.5 rounded text-xs ${badgeClass}">${severity}</span></td>
        <td class="py-2.5 text-right">
            <button class="text-xs text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900 px-2 py-1 rounded">Investigate</button>
        </td>
    `;

    tbody.insertBefore(row, tbody.firstChild);
    if (tbody.children.length > 25) tbody.removeChild(tbody.lastChild);
}

function loadPlaybook(mitreID, assetName, rowElement, alertID) {
    const desk = document.getElementById('playbook-content');
    const playbook = playbooks[mitreID] || playbooks["Default"];
    
    currentActiveAlert = { row: rowElement, asset: assetName, mitre: mitreID, id: alertID };

    if (!investigatedAlerts.has(alertID)) {
        investigatedAlerts.add(alertID);
        state.investigatedCount++;
        localStorage.setItem('soc_sim_state', JSON.stringify(state));
        updateMetricsUI();
    }

    let optionsShuffled = [...playbook.options].sort(() => Math.random() - 0.5);

    let choicesHTML = optionsShuffled.map((opt) => `
        <button onclick="submitMitigationChoice(${opt.correct})" 
                class="w-full text-left font-sans text-xs bg-slate-50 dark:bg-slate-950/60 p-3 border border-slate-200 dark:border-slate-800 rounded hover:border-slate-400 dark:hover:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-900 text-slate-700 dark:text-slate-300 transition-all cursor-pointer">
            🔹 ${opt.text}
        </button>
    `).join('');

    desk.innerHTML = `
        <div class="w-full flex flex-col h-full justify-between text-left">
            <div>
                <div class="flex justify-between items-center mb-2 border-b border-slate-200 dark:border-slate-900 pb-1.5">
                    <h3 class="text-emerald-600 dark:text-emerald-400 font-bold text-xs uppercase">${playbook.title}</h3>
                    <span class="text-[11px] text-slate-400 dark:text-slate-500">Asset: <b class="text-slate-700 dark:text-slate-300">${assetName}</b></span>
                </div>
                <p class="text-[11px] text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Select the correct incident containment procedure:</p>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-3">${choicesHTML}</div>
            </div>
        </div>
    `;
}

function submitMitigationChoice(isCorrect) {
    if (!currentActiveAlert) return;

    const desk = document.getElementById('playbook-content');

    if (isCorrect) {
        state.containedCount++;
        localStorage.setItem('soc_sim_state', JSON.stringify(state));

        currentActiveAlert.row.style.opacity = '0.3';
        currentActiveAlert.row.removeAttribute('onclick');
        const btn = currentActiveAlert.row.querySelector('button');
        if (btn) {
            btn.innerText = "Mitigated";
            btn.className = "text-xs text-slate-400 dark:text-slate-600 border border-slate-200 dark:border-slate-900 bg-transparent px-2 py-1 rounded cursor-not-allowed";
        }

        desk.innerHTML = `
            <div class="flex flex-col items-center justify-center text-center py-2">
                <span class="text-emerald-600 dark:text-emerald-500 font-bold text-sm tracking-wide mb-1">✔ THREAT CONTAINED SUCCESSFULLY</span>
                <span class="text-xs text-slate-400 dark:text-slate-500">Correct remediation vector processed. Keep monitoring SIEM telemetry feeds.</span>
            </div>
        `;
    } else {
        currentActiveAlert.row.style.opacity = '0.5';
        currentActiveAlert.row.removeAttribute('onclick');
        const btn = currentActiveAlert.row.querySelector('button');
        if (btn) {
            btn.innerText = "Failed";
            btn.className = "text-xs text-red-600/60 dark:text-red-400/60 border border-red-200 dark:border-red-950 bg-red-50 dark:bg-red-950/10 px-2 py-1 rounded cursor-not-allowed";
        }

        desk.innerHTML = `
            <div class="flex flex-col items-center justify-center text-center py-2">
                <span class="text-red-600 dark:text-red-500 font-bold text-sm tracking-wide mb-1">❌ NOT CONTAINED - ESCALATING THREAT</span>
                <span class="text-xs text-slate-500 dark:text-slate-400 max-w-md">Incorrect protocol chosen. Remediation step failed, incident log payload passed to Tier-3 engineering teams.</span>
            </div>
        `;
    }

    currentActiveAlert = null;
    updateMetricsUI();
}

function updateMetricsUI() {
    document.getElementById('tally-high').innerText = state.highRisks;
    document.getElementById('tally-total').innerText = state.totalIncidents;
    document.getElementById('tally-investigated').innerText = state.investigatedCount;
    document.getElementById('tally-contained').innerText = state.containedCount;

    const serverListContainer = document.getElementById('server-tally-list');
    serverListContainer.innerHTML = '';

    const sortedServers = Object.keys(state.serverTallies).sort((a, b) => {
        return (state.serverTallies[b].Critical * 4 + state.serverTallies[b].High * 2 + state.serverTallies[b].Medium) - 
               (state.serverTallies[a].Critical * 4 + state.serverTallies[a].High * 2 + state.serverTallies[a].Medium);
    });

    sortedServers.slice(0, 4).forEach(server => {
        const counts = state.serverTallies[server];
        const item = document.createElement('div');
        item.className = "flex justify-between items-center bg-slate-50 dark:bg-slate-950/60 p-1.5 border border-slate-200 dark:border-slate-900 rounded";
        item.innerHTML = `
            <span class="font-bold text-slate-500 dark:text-slate-400 text-xs">${server}</span>
            <div class="flex gap-1 text-[9px] font-sans">
                <span class="bg-red-100 dark:bg-red-950 text-red-600 dark:text-red-400 px-1 rounded">${counts.Critical || 0}C</span>
                <span class="bg-orange-100 dark:bg-orange-950 text-orange-600 dark:text-orange-400 px-1 rounded">${counts.High || 0}H</span>
                <span class="bg-amber-100 dark:bg-amber-950 text-amber-600 dark:text-amber-400 px-1 rounded">${counts.Medium || 0}M</span>
                <span class="bg-blue-100 dark:bg-blue-950 text-blue-600 dark:text-blue-400 px-1 rounded">${counts.Low || 0}L</span>
            </div>
        `;
        serverListContainer.appendChild(item);
    });
}

function resetSimulationSession() {
    if (confirm("Are you sure you want to terminate this operational monitoring shift? All current session metrics and tallies will be permanently wiped.")) {
        localStorage.removeItem('soc_sim_state');
        window.location.reload();
    }
}

setInterval(createProceduralAlert, 4000);
setInterval(() => {
    state.secondsElapsed++;
    let hrs = Math.floor(state.secondsElapsed / 3600);
    let mins = Math.floor((state.secondsElapsed % 3600) / 60);
    let secs = state.secondsElapsed % 60;
    document.getElementById('sim-clock').innerText = `Shift Time: ${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')} / 08:00:00`;
}, 1000);

// Initialize layouts on system entry
if(document.getElementById('theme-btn')) { initializeActiveTheme(); }
updateMetricsUI();
createProceduralAlert();
