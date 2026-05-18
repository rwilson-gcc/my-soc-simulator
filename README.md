🛡️ Enterprise SOC Simulator Engine (v1.0)
A lightweight, fully interactive, frontend-driven Security Operations Center (SOC) dashboard simulation designed to mimic a real-world SIEM telemetry stream and incident response workflow. This application runs entirely client-side, making it optimized for zero-cost hosting on GitHub Pages.


📊 Core Features
Procedural Alert Generation Engine: Simulates a live, organic infrastructure telemetry feed utilizing randomized attacker IPs, assets, localization tags, and MITRE ATT&CK vectors spanning all severity tiers (Low, Medium, High, Critical).

Interactive Incident Playbooks: Context-aware triage workspaces mapped directly to specific threat signatures inspired by NIST SP 800-61 incident handling frameworks.

State Persistence & Resilience: Tracks performance metrics (Alerts Investigated, Threats Contained, Asset Vulnerability Index) using persistent browser localStorage. Progression survives accidental window refreshes.

Built for Continuous 8-Hour Operations: Implements strict DOM management. The application continuously trims active table nodes to stay completely memory-safe, ensuring zero browser performance degradation or tab crashes over an extended shift.

📁 Repository Structure
index.html -> Main User Interface & Layout Shell

README.md -> Project Documentation

js/app.js -> Core Operational Engine, Simulation Loop & Metrics

js/playbooks.js -> Security Incident Triage Steps & Remediation Mappings

🛠️ Built With
HTML5: Semantic documentation architecture.

Tailwind CSS: Responsive, high-tech dark mode utility styling delivered via CDN.

Vanilla JavaScript (ES6): Procedural data engine, state preservation, and dynamic DOM injection.

⚙️ How It Works under the Hood
Ingestion Loop: Every 4 seconds, app.js runs a generator combining randomized pools of variables to ensure distinct log telemetry that rarely repeats over a standard 8-hour testing lifecycle.

Memory Throttling: To prevent the DOM memory leakage common in long-running web tracking instances, active UI rows are capped at 25 items—dropping the oldest nodes out of cache automatically.

Metrics Validation: An internal cryptographic-style string tracking validation map stops analysts from artificially inflating portfolio interaction scores via duplicate alert manipulation clicks.

⚖️ License
This project is licensed under the MIT License - see the LICENSE file for details.
