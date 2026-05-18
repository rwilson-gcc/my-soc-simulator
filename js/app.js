// js/app.js

const assets = ["DC-01.corp", "SQL-PROD-02", "WS-ENG-491", "DMZ-WEB-01", "SAP-FIN-01", "GW-BORDER-01", "CLOUD-KUBE-04"];
const locations = ["London, UK", "Frankfurt, DE", "Ashburn, US", "Unknown / VPN Proxy", "Tokyo, JP", "Sydney, AU"];

// Diversified signature array across all triage classes
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
    secondsElapsed: 0 
};

let currentActiveAlert = null;
const investigatedAlerts = new Set(); // Protects metrics against duplicate clicks on the same alert

// Hydrate metrics from persistent browser memory if they exist
if (localStorage.getItem('soc_sim_state')) {
    const savedState = JSON.parse(localStorage.getItem('soc_sim_state'));
    state = { ...state, ...savedState };
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
    
    let badgeClass = "bg-slate-800 text-slate-400";
    if (severity === "Low") badgeClass = "bg-blue-950/40 text-blue-400 border border-blue-900/30";
    if (severity === "Medium") badgeClass = "bg-amber-950/40 text-amber-400 border border-amber-900/30";
    if (severity === "High") badgeClass = "bg-orange-950/40 text-orange-400 border border-orange-900/30 font-bold";
    if (severity === "Critical") badgeClass = "bg-red-950/50 text-red-400 border border-red-900 animate-pulse font-extrabold";

    const row = document.createElement('tr');
    row.className = "hover:bg-slate-900/60 transition-colors border-b border-slate-900/50 cursor-pointer";
    const uniqueAlertID = `${time}-${mitre}`;
    row.setAttribute("onclick", `loadPlaybook('${mitre}', '${asset}', this, '${uniqueAlertID}')`);
    
    row.innerHTML = `
        <td class="py-2.5 font-mono text-xs text-slate-500">${time}</td>
        <td class="py-2.5 font-semibold text-slate-300">${asset}</td>
        <td class="py-2.5 pr-4 text-slate-400 truncate max-w-md">${msg}</td>
        <td class="py-2.5 text-center"><span class="px-2 py-0.5 rounded text-xs ${badgeClass}">${severity}</span></td>
        <td class="py-2.5 text-right">
            <button class="text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-900 px-2 py-1 rounded">Investigate</button>
        </td>
    `;

    tbody.insertBefore(row, tbody.firstChild);
    
    // Prevent DOM memory crash over 8 hours by keeping max visible table rows capped at 25
    if (tbody.children.length > 25) tbody.removeChild(tbody.lastChild);
}

function loadPlaybook(mitreID, assetName, rowElement, alertID) {
    const desk = document.getElementById('playbook-content');
    const playbook = playbooks[mitreID] || playbooks["Default"];
    
    currentActiveAlert = { row: rowElement, asset: assetName, mitre: mitreID, id: alertID };

    // Tally up investigation actions safely
    if (!investigatedAlerts.has(alertID)) {
        investigatedAlerts.add(alertID);
        state.investigatedCount++;
        localStorage.setItem('soc_sim_state', JSON.stringify(state));
        updateMetricsUI();
    }

    let stepsHTML = playbook.steps.map((step, idx) => `
        <label class="flex items-start gap-3 text-slate-300 text-sm cursor-pointer select-none bg-slate-950/40 p-2 border border-slate-900 rounded hover:border-slate-800">
            <input type="checkbox" class="mt-1 accent-emerald-500" id="step-${idx}">
            <span>${step}</span>
        </label>
    `).join('');

    desk.innerHTML = `
        <div class="w-full flex flex-col h-full justify-between text-left">
            <div>
                <div class="flex justify-between items-center mb-2">
                    <h3 class="text-emerald-400 font-bold text-sm uppercase">${playbook.title}</h3>
                    <span class="text-xs text-slate-500">Target Asset: <b class="text-slate-300">${assetName}</b></span>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-2 my-2">${stepsHTML}</div>
            </div>
            <div class="flex justify-end gap-3 mt-2 pt-2 border-t border-slate-900">
                <button onclick="executeMitigation()" class="text-xs font-bold bg-emerald-500 hover:bg-emerald-600 text-slate-950 px-4 py-2 rounded transition-all">
                    ⚡ Execute Action: ${playbook.remediation}
                </button>
            </div>
        </div>
    `;
}

function executeMitigation() {
    if (!currentActiveAlert) return;

    state.containedCount++;
    localStorage.setItem('soc_sim_state', JSON.stringify(state));

    currentActiveAlert.row.style.opacity = '0.2';
    currentActiveAlert.row.removeAttribute('onclick');
    const btn = currentActiveAlert.row.querySelector('button');
    if (btn) {
        btn.innerText = "Mitigated";
        btn.className = "text-xs text-slate-600 border border-slate-900 bg-transparent px-2 py-1 rounded cursor-not-allowed";
    }

    document.getElementById('playbook-content').innerHTML = `
        <span class="text-emerald-500 font-semibold mb-1 text-xs">✔ THREAT CONTAINED SUCCESSFULLY</span>
        <span class="text-xs text-slate-600">Select another active signature matrix to begin next triage routine.</span>
    `;
    
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

    // Sort infrastructure weights dynamically based on calculated danger score
    const sortedServers = Object.keys(state.serverTallies).sort((a, b) => {
        return (state.serverTallies[b].Critical * 4 + state.serverTallies[b].High * 2 + state.serverTallies[b].Medium) - 
               (state.serverTallies[a].Critical * 4 + state.serverTallies[a].High * 2 + state.serverTallies[a].Medium);
    });

    sortedServers.slice(0, 4).forEach(server => {
        const counts = state.serverTallies[server];
        const item = document.createElement('div');
        item.className = "flex justify-between items-center bg-slate-950/60 p-1.5 border border-slate-900 rounded";
        item.innerHTML = `
            <span class="font-bold text-slate-400 text-xs">${server}</span>
            <div class="flex gap-1 text-[9px] font-sans">
                <span class="bg-red-950 text-red-400 px-1 rounded">${counts.Critical || 0}C</span>
                <span class="bg-orange-950 text-orange-400 px-1 rounded">${counts.High || 0}H</span>
                <span class="bg-amber-950 text-amber-400 px-1 rounded">${counts.Medium || 0}M</span>
                <span class="bg-blue-950 text-blue-400 px-1 rounded">${counts.Low || 0}L</span>
            </div>
        `;
        serverListContainer.appendChild(item);
    });
}

// Tick loops: new logs every 4 seconds, clock update every 1 second
setInterval(createProceduralAlert, 4000);
setInterval(() => {
    state.secondsElapsed++;
    let hrs = Math.floor(state.secondsElapsed / 3600);
    let mins = Math.floor((state.secondsElapsed % 3600) / 60);
    let secs = state.secondsElapsed % 60;
    document.getElementById('sim-clock').innerText = `Shift Time: ${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')} / 08:00:00`;
}, 1000);

// Run initial execution rendering updates
updateMetricsUI();
createProceduralAlert();