// ===============================================
// API CONFIG & AUTH SYSTEM
// ===============================================
const API_BASE = "http://localhost:5000";

// ── Auth guard: redirect to login if no valid token ──
(function authGuard() {
    const token = sessionStorage.getItem("wl_token");
    if (!token) {
        window.location.href = "login.html";
        return;
    }
    // Verify token is still valid
    fetch(`${API_BASE}/api/auth/verify`, {
        headers: { "Authorization": `Bearer ${token}` }
    }).then(res => {
        if (!res.ok) {
            sessionStorage.removeItem("wl_token");
            sessionStorage.removeItem("wl_user");
            window.location.href = "login.html";
        }
    }).catch(() => {
        // If backend is down, allow offline access with existing token
        console.warn("Could not verify token — backend may be offline");
    });
})();

// ── Authenticated fetch wrapper ──
async function authFetch(url, options = {}) {
    const token = sessionStorage.getItem("wl_token");
    if (!token) {
        window.location.href = "login.html";
        throw new Error("Not authenticated");
    }

    const headers = {
        ...(options.headers || {}),
        "Authorization": `Bearer ${token}`
    };

    const res = await fetch(url, { ...options, headers });

    // If server says 401, token is invalid/expired — redirect to login
    if (res.status === 401) {
        sessionStorage.removeItem("wl_token");
        sessionStorage.removeItem("wl_user");
        window.location.href = "login.html";
        throw new Error("Session expired");
    }

    return res;
}

// ── Logout function ──
function logout() {
    const token = sessionStorage.getItem("wl_token");
    if (token) {
        // Best-effort server-side logout (blacklist token)
        fetch(`${API_BASE}/api/auth/logout`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${token}` }
        }).catch(() => {});
    }
    sessionStorage.removeItem("wl_token");
    sessionStorage.removeItem("wl_user");
    window.location.href = "login.html";
}

// ===============================================
// FETCH LIVE ALERTS FROM FLASK
// ===============================================
async function fetchAlerts() {
    try {
        const res = await authFetch(`${API_BASE}/api/alerts`);
        const alerts = await res.json();
        renderLiveAlerts(alerts);
    } catch (err) {
        console.error("Failed to fetch alerts:", err);
    }
}

function renderLiveAlerts(alerts) {
    // Guard: don't overwrite if user has switched away from main tab
    const activeTab = document.querySelector(".tab.active")?.dataset.tab;
    if (activeTab && activeTab !== "main") return;

    const tbody = document.querySelector(".alerts-table tbody");
    if (!tbody) return;

    tbody.innerHTML = "";

    // Set up severity header with filter for main channel
    const severityHeader = document.querySelector(".severity-header");
    if (severityHeader) {
        severityHeader.innerHTML = `
            <button class="filter-btn">⏷</button> SEVERITY
            <div class="filter-menu">
                <div data-filter="all">All</div>
                <div data-filter="critical">Critical</div>
                <div data-filter="high">High</div>
                <div data-filter="medium">Medium</div>
            </div>`;
    }

    alerts.forEach((alert, index) => {
        const severityClass = alert.severity === "critical" ? "critical"
            : alert.severity === "high" ? "high" : "medium";

        const severityLabel = alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1);
        const date = new Date(alert.timestamp).toLocaleString();

        const row = document.createElement("tr");
        row.className = "log-row";
        row.dataset.channel = "main";
        row.dataset.alertId = `alert-${index + 1}`;
        row.innerHTML = `
            <td class="${severityClass}">
                <span class="arrow">▶</span> ${severityLabel}
            </td>
            <td>${date}</td>
            <td>${alert.process?.toUpperCase() || "UNKNOWN"} - ${alert.message.substring(0, 50)}...</td>
            <td>${alert.hostname || "–"}</td>
            <td>${alert.pid || "N/A"}</td>
            <td>${alert.process || "System"}</td>
            <td class="action">
                <button class="btn-soc action-add" title="Add to Investigation">+</button>
            </td>
        `;

        const detailsRow = document.createElement("tr");
        detailsRow.className = "log-details";
        detailsRow.style.display = "none";
        detailsRow.innerHTML = `
            <td colspan="7">
                <div class="details-box">
                    <p><strong>Timestamp:</strong> ${date}</p>
                    <p><strong>Host:</strong> ${alert.hostname}</p>
                    <p><strong>IP:</strong> ${alert.host_ip}</p>
                    <p><strong>Process:</strong> ${alert.process}</p>
                    <p><strong>Command:</strong> ${alert.command || "N/A"}</p>
                    <p><strong>User ID:</strong> ${alert.user_id}</p>
                    <p><strong>Message:</strong> ${alert.message}</p>
                    <p><strong>Severity:</strong> ${severityLabel}</p>
                </div>
            </td>
        `;

        tbody.appendChild(row);
        tbody.appendChild(detailsRow);
    });

    assignAlertIds();
    updateTabCounters();
}

// ===============================================
// RULE ENGINE ALERTS
// ===============================================
async function fetchRuleAlerts() {
    try {
        const res = await authFetch(`${API_BASE}/api/alerts/rules`);
        const data = await res.json();
        if (data.status === "ok") {
            renderRuleAlerts(data.alerts);
        }
    } catch (err) {
        console.error("Failed to fetch rule alerts:", err);
    }
}

// ===============================================
// CORRELATED ALERTS
// ===============================================
async function fetchCorrelatedAlerts() {
    try {
        const res = await authFetch(`${API_BASE}/api/alerts/correlated`);
        const data = await res.json();
        if (data.status === "ok") {
            renderCorrelatedAlerts(data.alerts);
        }
    } catch (err) {
        console.error("Failed to fetch correlated alerts:", err);
    }
}

function renderCorrelatedAlerts(alerts) {
    // Guard: don't overwrite if user has switched away from correlated tab
    const activeTab = document.querySelector(".tab.active")?.dataset.tab;
    if (activeTab && activeTab !== "correlated") return;

    const tbody = document.querySelector(".alerts-table tbody");
    if (!tbody) return;

    tbody.innerHTML = "";

    // Set severity header (no filter for correlated)
    const severityHeader = document.querySelector(".severity-header");
    if (severityHeader) severityHeader.innerHTML = `SEVERITY`;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align:center;color:#fff;padding:48px 20px;font-size:15px;letter-spacing:0.5px;">
                    [ NO CORRELATED ALERTS — ENGINE EVALUATES EVERY 60s ]
                </td>
            </tr>`;
        return;
    }

    alerts.forEach((alert, index) => {
        const severityClass = alert.severity === "critical" ? "critical"
            : alert.severity === "high" ? "high"
            : alert.severity === "medium" ? "medium" : "";
        const severityLabel = (alert.severity || "info").charAt(0).toUpperCase()
            + (alert.severity || "info").slice(1);
        const date = new Date(alert.timestamp).toLocaleString();

        const mitreBadge = alert.mitre_technique
            ? `<span class="mitre-badge">${alert.mitre_technique}</span>`
            : "";
        const chainBadge = `<span class="chain-badge">CHAIN</span>`;

        const seqSummary = (alert.sequence || []).map((step, i) => {
            const count = alert.event_counts ? alert.event_counts[i] : "?";
            return `${count}?? <em>${step.pattern.replace(/\|/g, " or ")}</em>`;
        }).join(" <span style='color:#fff'>→</span> ");

        const row = document.createElement("tr");
        row.className = "log-row";
        row.dataset.channel = "correlated";
        row.dataset.alertId = `corr-${index + 1}`;
        row.innerHTML = `
            <td class="${severityClass}">
                <span class="arrow">▶</span> ${severityLabel}
            </td>
            <td>${date}</td>
            <td>${chainBadge} ${alert.rule_name} ${mitreBadge}</td>
            <td>${alert.matched_group || "–"}</td>
            <td title="Sequence steps matched">${(alert.sequence || []).length} steps</td>
            <td>${alert.mitre_tactic || "–"}</td>
            <td class="action">
                <button class="btn-soc action-add" title="Add to Investigation">+</button>
            </td>
        `;

        const detailsRow = document.createElement("tr");
        detailsRow.className = "log-details";
        detailsRow.style.display = "none";
        detailsRow.innerHTML = `
            <td colspan="7">
                <div class="details-box">
                    <p><strong>Rule ID:</strong> ${alert.rule_id}</p>
                    <p><strong>Description:</strong> ${alert.description}</p>
                    <p><strong>Fired At:</strong> ${date}</p>
                    <p><strong>Matched Host:</strong> ${alert.matched_group}</p>
                    <p><strong>Attack Chain:</strong> ${seqSummary}</p>
                    <p><strong>Time Window:</strong> ${alert.time_window_seconds}s</p>
                    <p><strong>Severity:</strong> ${severityLabel}</p>
                    <p><strong>MITRE Tactic:</strong> ${alert.mitre_tactic}</p>
                    <p><strong>MITRE Technique:</strong> ${alert.mitre_technique} - ${alert.mitre_technique_name}</p>
                </div>
            </td>
        `;

        tbody.appendChild(row);
        tbody.appendChild(detailsRow);
    });

    assignAlertIds();
}

function renderRuleAlerts(alerts) {
    // Guard: don't overwrite if user has switched away from rules tab
    const activeTab = document.querySelector(".tab.active")?.dataset.tab;
    if (activeTab && activeTab !== "rules") return;

    const tbody = document.querySelector(".alerts-table tbody");
    if (!tbody) return;

    tbody.innerHTML = "";

    // Set severity header (no filter for rules)
    const severityHeader = document.querySelector(".severity-header");
    if (severityHeader) severityHeader.innerHTML = `SEVERITY`;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align:center;color:#fff;padding:48px 20px;font-size:15px;letter-spacing:0.5px;">
                    [ NO RULE ALERTS FIRED YET — ENGINE EVALUATES EVERY 60s ]
                </td>
            </tr>`;
        return;
    }

    alerts.forEach((alert, index) => {
        const severityClass = alert.severity === "critical" ? "critical"
            : alert.severity === "high" ? "high"
            : alert.severity === "medium" ? "medium" : "";
        const severityLabel = (alert.severity || "info").charAt(0).toUpperCase()
            + (alert.severity || "info").slice(1);
        const date = new Date(alert.timestamp).toLocaleString();

        const mitreBadge = alert.mitre_technique
            ? `<span class="mitre-badge">${alert.mitre_technique}</span>`
            : "";

        const ruleBadge = `<span class="rule-badge">RULE</span>`;

        const row = document.createElement("tr");
        row.className = "log-row";
        row.dataset.channel = "rules";
        row.dataset.alertId = `rule-${index + 1}`;
        row.innerHTML = `
            <td class="${severityClass}">
                <span class="arrow">▶</span> ${severityLabel}
            </td>
            <td>${date}</td>
            <td>${ruleBadge} ${alert.rule_name} ${mitreBadge}</td>
            <td>${alert.matched_group || "–"}</td>
            <td title="Event count in window">${alert.matched_count}x</td>
            <td>${alert.mitre_tactic || "–"}</td>
            <td class="action">
                <button class="btn-soc action-add" title="Add to Investigation">+</button>
            </td>
        `;

        const detailsRow = document.createElement("tr");
        detailsRow.className = "log-details";
        detailsRow.style.display = "none";
        detailsRow.innerHTML = `
            <td colspan="7">
                <div class="details-box">
                    <p><strong>Rule ID:</strong> ${alert.rule_id}</p>
                    <p><strong>Description:</strong> ${alert.description}</p>
                    <p><strong>Fired At:</strong> ${date}</p>
                    <p><strong>Matched Host:</strong> ${alert.matched_group}</p>
                    <p><strong>Hit Count:</strong> ${alert.matched_count} events in last ${alert.time_window_seconds}s</p>
                    <p><strong>Pattern:</strong> <code style="background:#111;padding:2px 6px;border-radius:3px;font-family:monospace;">${alert.pattern}</code></p>
                    <p><strong>Severity:</strong> ${severityLabel}</p>
                    <p><strong>MITRE Tactic:</strong> ${alert.mitre_tactic}</p>
                    <p><strong>MITRE Technique:</strong> ${alert.mitre_technique} - ${alert.mitre_technique_name}</p>
                </div>
            </td>
        `;

        tbody.appendChild(row);
        tbody.appendChild(detailsRow);
    });

    assignAlertIds();
}

// ===============================================
// FETCH STATS
// ===============================================
async function fetchStats() {
    try {
        const res = await authFetch(`${API_BASE}/api/stats`);
        const stats = await res.json();
        renderStats(stats);
    } catch (err) {
        console.error("Failed to fetch stats:", err);
    }
}

function renderStats(stats) {
    const mainTab = document.querySelector('.tab[data-tab="main"]');
    if (mainTab) {
        let badge = mainTab.querySelector(".counter-badge");
        if (!badge) {
            badge = document.createElement("span");
            badge.className = "counter-badge";
            badge.style.cssText = "margin-left:8px;font-size:0.85em;opacity:0.7;";
            mainTab.appendChild(badge);
        }
        badge.textContent = `(${stats.total_logs.toLocaleString()})`;
    }
}

// ===============================================
// LIVE SEARCH FOR LOG MANAGEMENT
// ===============================================
async function searchLogs(query) {
    try {
        const res = await authFetch(`${API_BASE}/api/logs/search?q=${encodeURIComponent(query)}&size=50`);
        const logs = await res.json();
        renderLogResults(logs);
    } catch (err) {
        console.error("Search failed:", err);
    }
}

function renderLogResults(logs) {
    const logList = document.querySelector(".log-list");
    if (!logList) return;

    logList.innerHTML = "";

    if (logs.length === 0) {
        logList.innerHTML = `<div class="log-item">No results found.</div>`;
        return;
    }

    logs.forEach(log => {
        const date = new Date(log.timestamp).toLocaleString();
        const div = document.createElement("div");
        div.className = "log-item";
        div.textContent = `[${date}] [${log.hostname}] [${log.process}] ${log.message}`;
        logList.appendChild(div);
    });
}

// ===============================================
// AUTO REFRESH EVERY 30 SECONDS
// ===============================================
let autoRefreshInterval = null;

function startAutoRefresh() {
    // Clear any existing interval to prevent stacking
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }

    autoRefreshInterval = setInterval(() => {
        const activePage = document.querySelector(".menu li.active")?.dataset.page;
        if (activePage === "monitoring") {
            const activeTab = document.querySelector(".tab.active")?.dataset.tab;
            if (activeTab === "rules") {
                fetchRuleAlerts();
            } else if (activeTab === "correlated") {
                fetchCorrelatedAlerts();
            } else if (activeTab === "main") {
                fetchAlerts();
            }
            // Do NOT auto-refresh if on investigation or closed tab -
            // those are local persistent data, not fetched from ES
        }
    }, 30000);
}

// ===============================================
// RAW LOG DATA
// ===============================================

const RAW_LOGS = [
    "[2025-11-15 17:50:01] [FW-01] DENY TCP 103.22.14.5:443 -> 172.16.20.69:3389 [RDP Brute Force]",
    "[2025-11-15 17:49:55] [AD-DC01] (Security) Successful Logon: stewart@company.io (Source: 172.16.17.183)",
    "[2025-11-15 17:49:50] [Tomcat-Server02] ERROR 500 GET /api/v2/users - 'SQLGrammarException: table not found'",
    "[2025-11-15 17:49:42] [SharePoint01] (Audit) File Accessed: stewart@company.io accessed Q1-Financials.xlsx",
    "[2025-11-15 17:49:30] [FW-01] ALLOW TCP 172.16.20.56:8443 -> 8.8.8.8:53 [DNS Query]",
    "[2025-11-15 17:48:12] [AD-DC01] (Security) Failed Logon: admin@company.io (Source: 10.0.0.45) [Reason: Bad Password]",
    "[2025-11-15 17:47:59] [FW-01] DENY UDP 198.51.100.7:1900 -> 172.16.20.255:1900 [SSDP Scan]",
    "[2025-11-15 17:47:33] [IDS-01] ALERT Signature ET TROJAN Win32/Emotet CnC Beacon (172.16.20.44 -> 45.33.32.156)",
    "[2025-11-15 17:46:58] [WS-Prod-01] (Sysmon) Process Create: powershell.exe -enc SQBFAFgA... PID:7284",
    "[2025-11-15 17:46:20] [Exchange-01] (MessageTracking) SEND FROM: ceo@company.io TO: external@protonmail.com SUBJECT: Re: Wire Transfer",
    "[2025-11-15 17:45:44] [FW-01] DENY TCP 172.16.20.69:445 -> 203.0.113.99:4444 [Outbound SMB Blocked]",
    "[2025-11-15 17:45:10] [AD-DC01] (Security) Privilege Escalation: jdoe added to Domain Admins (By: stewart@company.io)",
    "[2025-11-15 17:44:38] [Tomcat-Server02] WARN 403 POST /admin/config - Unauthorized access attempt from 172.16.20.56",
    "[2025-11-15 17:44:01] [FW-01] ALLOW TCP 172.16.20.17:443 -> 13.107.42.14:443 [SharePoint Online Sync]",
    "[2025-11-15 17:43:22] [ubuntu-dev] (auth.log) sshd: Failed password for root from 91.240.118.172 port 22 ssh2",
    "[2025-11-15 17:42:50] [WS-Prod-01] (Defender) Quarantined: Trojan:Win32/AgentTesla!ml in C:\\Users\\jdoe\\Downloads\\invoice.exe",
    "[2025-11-15 17:42:15] [AD-DC01] (Security) Account Lockout: jdoe@company.io after 5 failed attempts (Source: 172.16.20.69)",
    "[2025-11-15 17:41:30] [FW-01] DENY TCP 172.16.20.44:8080 -> 185.220.101.1:9001 [Tor Exit Node Blocked]",
    "[2025-11-15 17:40:55] [Exchange-01] (TransportRule) BLOCKED attachment invoice.exe in mail FROM: supplier@extvendor.com",
    "[2025-11-15 17:40:02] [IDS-01] ALERT Signature GPL ATTACK_RESPONSE id check returned root (172.16.20.51 -> 172.16.20.56)"
];

let logCurrentPage = 1;
let logCurrentQuery = "";
const LOGS_PER_PAGE = 10;

const THREAT_INTEL_DATA = [
    { date: "Nov, 09, 2025, 03:43 AM", type: "URL", data: "http://42.57.207.188:53729/i", tag: "malware_download", source: "urlhaus.abuse.ch" },
    { date: "Nov, 09, 2025, 03:39 AM", type: "URL", data: "http://182.119.3.51:51555/i", tag: "malware_download", source: "urlhaus.abuse.ch" },
    { date: "Nov, 09, 2025, 03:36 AM", type: "URL", data: "http://125.43.36.15:33285/bin.sh", tag: "malware_download", source: "urlhaus.abuse.ch" },
    { date: "Nov, 09, 2025, 03:28 AM", type: "URL", data: "http://115.50.33.28:60359/i", tag: "malware_download", source: "urlhaus.abuse.ch" },
    { date: "Nov, 08, 2025, 11:12 PM", type: "IP", data: "45.33.22.11", tag: "c2_server", source: "threatfox.abuse.ch" },
    { date: "Nov, 08, 2025, 10:55 PM", type: "IP", data: "91.240.118.172", tag: "brute_force", source: "blocklist.de" },
    { date: "Nov, 08, 2025, 09:30 PM", type: "Hash", data: "e99a18c428cb38d5f260853678922e03", tag: "trojan_agent", source: "malwarebazaar.abuse.ch" },
    { date: "Nov, 08, 2025, 08:17 PM", type: "Hash", data: "d41d8cd98f00b204e9800998ecf8427e", tag: "ransomware", source: "malwarebazaar.abuse.ch" },
    { date: "Nov, 08, 2025, 07:45 PM", type: "Domain", data: "evil-payload.xyz", tag: "phishing", source: "openphish.com" },
    { date: "Nov, 08, 2025, 06:02 PM", type: "Domain", data: "c2-callback.darknet.ru", tag: "c2_server", source: "threatfox.abuse.ch" },
    { date: "Nov, 08, 2025, 04:18 PM", type: "URL", data: "http://203.0.113.5/wp-content/uploads/shell.php", tag: "webshell", source: "urlhaus.abuse.ch" },
    { date: "Nov, 08, 2025, 02:55 PM", type: "IP", data: "185.220.101.1", tag: "tor_exit_node", source: "dan.me.uk" }
];

// ===============================================
// PAGE CONTENT TEMPLATES
// ===============================================

const pageTemplates = {
    logs: `
        <div class="logmgmt-container">
            <h2 class="log-title">Log Search</h2>
            <div class="log-search-box">
                <input type="text" placeholder="enter search query..." class="log-input" id="logSearchInput" />
                <button class="log-btn" id="logSearchBtn">SEARCH</button>
            </div>
            <div class="log-filters" style="display:flex;gap:10px;padding:12px 20px;background:#121212;border-bottom:1px solid #2a2a2a;flex-wrap:wrap;align-items:center;">
                <label style="font-size:14px;color:#fff;text-transform:uppercase;letter-spacing:0.5px;">Filters:</label>
                <input type="date" id="logFilterDate" style="background:#080808;border:1px solid #2a2a2a;color:#fff;padding:6px 12px;font-family:'Space Mono',monospace;font-size:15px;text-transform:uppercase;cursor:pointer;border-radius:3px; color-scheme: dark;">
                <select id="logFilterSeverity" style="background:#080808;border:1px solid #2a2a2a;color:#fff;padding:8px 12px;font-family:'Space Mono',monospace;font-size:15px;text-transform:uppercase;cursor:pointer;border-radius:3px;">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <select id="logFilterHostname" style="background:#080808;border:1px solid #2a2a2a;color:#fff;padding:8px 12px;font-family:'Space Mono',monospace;font-size:15px;text-transform:uppercase;cursor:pointer;border-radius:3px;">
                    <option value="">All Hosts</option>
                </select>
                <select id="logFilterProcess" style="background:#080808;border:1px solid #2a2a2a;color:#fff;padding:8px 12px;font-family:'Space Mono',monospace;font-size:15px;text-transform:uppercase;cursor:pointer;border-radius:3px;">
                    <option value="">All Processes</option>
                </select>
                <button class="log-btn" id="logClearFilters" style="font-size:14px;padding:8px 16px;">CLEAR</button>
            </div>
            <div class="log-table-header">
                <div>Event</div>
            </div>
            <div class="log-list" id="logList"></div>
            <div class="log-pagination" id="logPagination"></div>
        </div>
    `,
    cases: `
        <div class="case-container">
            <h2 class="case-title">Case List</h2>
            <div class="case-tabs">
                <button class="case-tab active" data-case-filter="all">All</button>
                <button class="case-tab" data-case-filter="open">Open</button>
                <button class="case-tab" data-case-filter="closed">Closed</button>
            </div>
            <div class="case-list" id="caseList"></div>
        </div>
    `,
    endpoints: `
        <div class="endpoint-container">
            <div class="ep-page-header">
                <div class="ep-page-title-row">
                    <h2 class="ep-page-title">Endpoint Security</h2>
                    <span class="ep-live-badge"> LIVE</span>
                </div>
                <div class="ep-summary-stats" id="epSummaryStats"></div>
            </div>
            <div class="ep-filter-bar" id="epFilterBar">
                <div class="ep-filter-pills" id="epFilterPills">
                    <button class="ep-filter-pill active" data-status="all">ALL</button>
                    <button class="ep-filter-pill" data-status="Healthy">HEALTHY</button>
                    <button class="ep-filter-pill" data-status="At Risk">AT RISK</button>
                    <button class="ep-filter-pill" data-status="Compromised">COMPROMISED</button>
                    <button class="ep-filter-pill" data-status="Isolated">ISOLATED</button>
                </div>
            </div>
            <div class="ep-systems-list" id="epSystemsList">
                <div style="text-align:center;color:#fff;padding:48px;font-size:14px;letter-spacing:1px;">[ LOADING ENDPOINTS FROM ELASTICSEARCH... ]</div>
            </div>
        </div>
    `,
    threatintel: `
        <div style="padding:20px;">
            <div style="margin-bottom:16px;">
                <div style="font-size:17px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:4px;">THREAT INTELLIGENCE</div>
                <div style="font-size:13px;color:#fff;margin-bottom:14px;">Live IP Reputation via AbuseIPDB</div>
                <div style="display:flex;gap:10px;flex-wrap:wrap;">
                    <input id="threatIpInput" placeholder="Lookup any IP..." style="background:#000;border:1px solid #333;color:#fff;padding:8px 12px;font-family:var(--font-primary);font-size:14px;width:220px;outline:none;"/>
                    <button id="threatLookupBtn" class="btn-soc">LOOKUP</button>
                    <button id="threatEnrichBtn" class="btn-soc">↻ ENRICH ATTACKERS</button>
                </div>
            </div>

            <div id="threatSingleResult"></div>

            <div class="ti-summary-bar">
                <div class="ti-stat-card">
                    <div class="ti-stat-num" id="tiStatTotal" style="color:#fff;">-</div>
                    <div class="ti-stat-label">IPs Checked</div>
                </div>
                <div class="ti-stat-card" style="border-left:3px solid #ff5252;">
                    <div class="ti-stat-num" id="tiStatMalicious" style="color:#ff5252;">-</div>
                    <div class="ti-stat-label">Malicious</div>
                </div>
                <div class="ti-stat-card" style="border-left:3px solid #ff9800;">
                    <div class="ti-stat-num" id="tiStatSuspicious" style="color:#ff9800;">-</div>
                    <div class="ti-stat-label">Suspicious</div>
                </div>
                <div class="ti-stat-card" style="border-left:3px solid #4caf50;">
                    <div class="ti-stat-num" id="tiStatClean" style="color:#4caf50;">-</div>
                    <div class="ti-stat-label">Clean</div>
                </div>
                <div class="ti-stat-card" style="border-left:3px solid #9c27b0;">
                    <div class="ti-stat-num" id="tiStatTor" style="color:#ce93d8;">-</div>
                    <div class="ti-stat-label">Tor Nodes</div>
                </div>
            </div>

            <table class="alerts-table">
                <thead><tr>
                    <th>IP ADDRESS</th>
                    <th>RISK LEVEL</th>
                    <th>GEO</th>
                    <th>ISP / TYPE</th>
                    <th>REPORTS (30/60/90d)</th>
                    <th>LAST SEEN</th>
                    <th>ACTIONS</th>
                </tr></thead>
                <tbody id="threatTableBody">
                    <tr><td colspan="7" style="text-align:center;color:#fff;padding:32px;font-size:14px;">
                        [ CLICK "ENRICH ATTACKERS" TO LOAD LIVE THREAT DATA ]
                    </td></tr>
                </tbody>
            </table>
        </div>
    `,
    hosts: `
        <div class="hosts-page-container">
            <div class="hosts-page-header">
                <h2 class="hosts-page-title">Host Log Viewer</h2>
                <span class="hosts-live-badge"> LIVE</span>
            </div>
            <div class="hosts-layout">
                <div class="hosts-sidebar">
                    <div class="hosts-sidebar-label">CONNECTED HOSTS</div>
                    <div id="hostsList"></div>
                </div>
                <div class="hosts-main" id="hostsMain">
                    <div class="hosts-placeholder">
                        [ SELECT A HOST TO VIEW LOGS ]
                    </div>
                </div>
            </div>
        </div>
    `,
    alerts: `
        <div class="logmgmt-container">
            <div class="monitoring-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--color-border-primary);">
                <div class="segmented-control" role="tablist" style="width: auto; flex: 1; border: none;">
                    <button class="tab active" role="tab" data-alerts-tab="rules" style="border-right:1px solid var(--color-border-primary);">Rule Engine <span class="counter-badge" id="apStatRule">0</span></button>
                    <button class="tab" role="tab" data-alerts-tab="correlated" style="border-right:1px solid var(--color-border-primary);">Correlated <span class="counter-badge" id="apStatCorr">0</span></button>
                    <button class="tab" role="tab" data-alerts-tab="closed">Closed <span class="counter-badge" id="apStatClosed">0</span></button>
                </div>
            </div>
            <div class="table-container">
                <table class="alerts-table" id="ruleAlertsTable">
                    <thead><tr>
                        <th>SEVERITY</th><th>DATE</th><th>RULE</th>
                        <th>HOST</th><th>COUNT</th><th>TACTIC</th><th>ACTION</th>
                    </tr></thead>
                    <tbody id="ruleAlertsBody"></tbody>
                </table>
                <table class="alerts-table" id="corrAlertsTable" style="display:none;">
                    <thead><tr>
                        <th>SEVERITY</th><th>DATE</th><th>CORRELATION RULE</th>
                        <th>HOST</th><th>STEPS</th><th>TACTIC</th><th>ACTION</th>
                    </tr></thead>
                    <tbody id="corrAlertsBody"></tbody>
                </table>
                <table class="alerts-table" id="closedAlertsTable" style="display:none;">
                    <thead><tr>
                        <th>SEVERITY</th><th>DATE</th><th>RULE</th>
                        <th>HOSTNAME</th><th>EVENT ID</th><th>TYPE</th><th>ACTION</th>
                    </tr></thead>
                    <tbody id="closedAlertsBody"></tbody>
                </table>
            </div>
        </div>
    `
};

// ===============================================
// APP INITIALIZATION
// ===============================================

document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

let monitoringCache = "";
let pollingInterval = null;
let cases = JSON.parse(localStorage.getItem('watchlogs_cases') || '[]');
let caseIdCounter = parseInt(localStorage.getItem('watchlogs_caseIdCounter') || '1');
let investigationAlerts = JSON.parse(localStorage.getItem('watchlogs_investigation') || '[]');
let closedAlertsList = JSON.parse(localStorage.getItem('watchlogs_closed') || '[]');

function saveAlertState() {
    localStorage.setItem('watchlogs_investigation', JSON.stringify(investigationAlerts));
    localStorage.setItem('watchlogs_closed', JSON.stringify(closedAlertsList));
    localStorage.setItem('watchlogs_cases', JSON.stringify(cases));
    localStorage.setItem('watchlogs_caseIdCounter', String(caseIdCounter));
}

function initApp() {
    const main = document.querySelector(".main");
    const menu = document.querySelector(".menu");
    const menuItems = document.querySelectorAll(".menu li");

    monitoringCache = main.innerHTML;

    menu.addEventListener("click", (e) => {
        const clickedItem = e.target.closest("li");
        if (!clickedItem) return;

        const page = clickedItem.dataset.page;
        menuItems.forEach(i => i.classList.remove("active"));
        clickedItem.classList.add("active");

        if (page === "monitoring") {
            main.innerHTML = monitoringCache;
            initMonitoringView();
        } else if (pageTemplates[page]) {
            main.innerHTML = pageTemplates[page];
            if (page === "logs") initLogManagement();
            if (page === "cases") initCasesView();
            if (page === "endpoints") initEndpointSecurity();
            if (page === "threatintel") initThreatIntel();
            if (page === "alerts") initAlertsPage();
            if (page === "hosts") initHostsPage();
        } else {
            main.innerHTML = "";
        }
    });

    main.addEventListener("click", (e) => {
        handleMainInteraction(e);
    });

    initMonitoringView();

    // Display logged-in username in sidebar
    const usernameEl = document.getElementById("sidebarUsername");
    if (usernameEl) {
        usernameEl.textContent = sessionStorage.getItem("wl_user") || "operator";
    }

    // Logout button hover effect
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("mouseenter", () => {
            logoutBtn.style.borderColor = "#ff5252";
            logoutBtn.style.color = "#ff5252";
        });
        logoutBtn.addEventListener("mouseleave", () => {
            logoutBtn.style.borderColor = "#2a2a2a";
            logoutBtn.style.color = "#888";
        });
    }
}

function initMonitoringView() {
    updateTabCounters();
    fetchAlerts();
    fetchStats();
    assignAlertIds();
    startAutoRefresh();

    if (!document.getElementById("monitoring-styles")) {
        const style = document.createElement("style");
        style.id = "monitoring-styles";
        style.textContent = `
            .alerts-table tbody { transition: opacity 0.3s ease; }
            .fade-out { opacity: 0; }

            .btn-soc {
                background: #000;
                border: 1px solid var(--color-border-primary);
                color: var(--color-text-primary);
                padding: 4px 8px;
                font-size: 13px;
                cursor: pointer;
                text-transform: uppercase;
                margin-right: 5px;
                transition: 0.2s;
                font-family: var(--font-primary);
            }
            .btn-soc:hover {
                background: var(--color-text-primary);
                color: #000;
            }
            .btn-soc.action-add {
                font-size: 20px;
                border: none;
                padding: 0 5px;
                background: transparent;
            }
            .btn-soc.action-add:hover { opacity: 0.7; }

                    /* Rule Engine badges */
            .rule-badge {
                display: inline-block;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1px;
                background: #0d1b2a;
                border: 1px solid #1e3a5f;
                color: #4fc3f7;
                padding: 2px 5px;
                border-radius: 3px;
                vertical-align: middle;
                margin-right: 5px;
            }
            .mitre-badge {
                display: inline-block;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.5px;
                background: #1a1a2e;
                border: 1px solid #3a3a6e;
                color: #9fa8da;
                padding: 2px 6px;
                border-radius: 3px;
                vertical-align: middle;
                margin-left: 6px;
            }
            /* Correlation chain badge */
            .chain-badge {
                display: inline-block;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 1px;
                background: #1a0d2e;
                border: 1px solid #6e3a8a;
                color: #ce93d8;
                padding: 2px 5px;
                border-radius: 3px;
                vertical-align: middle;
                margin-right: 5px;
            }
        `;
        document.head.appendChild(style);
    }
}

function assignAlertIds() {
    const rows = document.querySelectorAll(".log-row");
    rows.forEach((row, index) => {
        if (!row.dataset.alertId) {
            row.dataset.alertId = `alert-${index + 1}`;
        }
    });
}

// ===============================================
// MONITORING INTERACTION & WORKFLOW
// ===============================================

function handleMainInteraction(e) {
    const target = e.target;

    const logBtn = target.closest(".log-btn");
    if (logBtn) {
        const input = document.querySelector(".log-input");
        if (input && input.value.trim()) {
            searchLogs(input.value.trim());
        }
        return;
    }

    const tabBtn = target.closest(".tab");
    if (tabBtn) {
        switchTab(tabBtn.dataset.tab, tabBtn);
        return;
    }

    const arrow = target.closest(".arrow");
    if (arrow) {
        toggleLogDetails(arrow);
        return;
    }

    const filterBtn = target.closest(".filter-btn");
    if (filterBtn) {
        toggleFilterMenu(filterBtn);
        return;
    }
    const filterOption = target.closest(".filter-menu div");
    if (filterOption) {
        applySeverityFilter(filterOption);
        return;
    }

    const caseTab = target.closest(".case-tab");
    if (caseTab && caseTab.dataset.caseFilter) {
        filterCases(caseTab.dataset.caseFilter, caseTab);
        return;
    }

    const btn = target.closest("button") || target;
    if (btn.classList.contains("action-add")) {
        const row = btn.closest("tr");
        if (row && row.dataset.alertId) moveToInvestigation(row.dataset.alertId);
        return;
    }

    // Case Management actions via data-action attributes
    if (btn.dataset.action === "create-case") {
        const row = btn.closest("tr.log-row");
        if (row && row.dataset.alertId) createCase(row.dataset.alertId);
        return;
    }

    if (btn.dataset.action === "close-alert") {
        const row = btn.closest("tr.log-row");
        if (row && row.dataset.alertId) closeAlert(row.dataset.alertId);
        return;
    }

    if (btn.dataset.action === "reinvestigate") {
        const row = btn.closest("tr.log-row");
        if (row && row.dataset.alertId) reinvestigateAlert(row.dataset.alertId);
        return;
    }

    // Case Management page actions
    if (target.classList.contains("case-close-btn")) {
        const caseId = target.dataset.caseId;
        if (caseId) closeCaseById(caseId);
        return;
    }
    if (target.classList.contains("case-reopen-btn")) {
        const caseId = target.dataset.caseId;
        if (caseId) reopenCaseById(caseId);
        return;
    }
}

// ===============================================
// CORE FUNCTIONS
// ===============================================

function switchTab(channel, clickedTab) {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    clickedTab.classList.add("active");

    const tbody = document.querySelector(".alerts-table tbody");
    if (!tbody) return;

    tbody.classList.add("fade-out");
    setTimeout(() => {
        if (channel === "rules") {
            fetchRuleAlerts();
        } else if (channel === "correlated") {
            fetchCorrelatedAlerts();
        } else if (channel === "main") {
            fetchAlerts();
        } else if (channel === "investigation") {
            renderInvestigationTab();
        }
        tbody.classList.remove("fade-out");
    }, 200);
}

function renderInvestigationTab() {
    const tbody = document.querySelector(".alerts-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const severityHeader = document.querySelector(".severity-header");
    if (severityHeader) severityHeader.innerHTML = `SEVERITY`;

    if (investigationAlerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px 20px;font-size:15px;letter-spacing:0.5px;">[ NO ALERTS UNDER INVESTIGATION ]</td></tr>`;
        return;
    }

    investigationAlerts.forEach(a => {
        const sevClass = a.severityClass || "";
        const row = document.createElement("tr");
        row.className = "log-row";
        row.dataset.channel = "investigation";
        row.dataset.alertId = a.alertId;
        row.innerHTML = `
            <td class="${sevClass}"><span class="arrow">▶</span> ${a.severity}</td>
            <td>${a.date}</td>
            <td>${a.rule}</td>
            <td>${a.hostname || "–"}</td>
            <td>${a.eventId || "–"}</td>
            <td>${a.type || "–"}</td>
            <td class="action">
                ${a.caseId ? `<span style="color:#4caf50;font-weight:bold;">✔ ${a.caseId}</span>` : `<button class="btn-soc" data-action="create-case">CREATE CASE</button>`}
                <button class="btn-soc" data-action="close-alert">CLOSE ALERT</button>
            </td>
        `;

        const detailsRow = document.createElement("tr");
        detailsRow.className = "log-details";
        detailsRow.style.display = "none";
        detailsRow.innerHTML = `
            <td colspan="7">
                <div class="details-box">
                    <p><strong>Alert ID:</strong> ${a.alertId}</p>
                    <p><strong>Severity:</strong> ${a.severity}</p>
                    <p><strong>Date:</strong> ${a.date}</p>
                    <p><strong>Rule:</strong> ${a.rule}</p>
                    <p><strong>Hostname:</strong> ${a.hostname || "–"}</p>
                    <p><strong>Type:</strong> ${a.type || "–"}</p>
                    ${a.source ? `<p><strong>Source:</strong> ${a.source}</p>` : ""}
                </div>
            </td>
        `;

        tbody.appendChild(row);
        tbody.appendChild(detailsRow);
    });
}

function renderClosedTab() {
    const tbody = document.querySelector(".alerts-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const severityHeader = document.querySelector(".severity-header");
    if (severityHeader) severityHeader.innerHTML = `SEVERITY`;

    if (closedAlertsList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px 20px;font-size:15px;letter-spacing:0.5px;">[ NO CLOSED ALERTS ]</td></tr>`;
        return;
    }

    closedAlertsList.forEach(a => {
        const sevClass = a.severityClass || "";
        const row = document.createElement("tr");
        row.className = "log-row";
        row.dataset.channel = "closed";
        row.dataset.alertId = a.alertId;
        row.innerHTML = `
            <td class="${sevClass}"><span class="arrow">▶</span> ${a.severity}</td>
            <td>${a.date}</td>
            <td>${a.rule}</td>
            <td>${a.hostname || "–"}</td>
            <td>${a.eventId || "–"}</td>
            <td>${a.type || "–"}</td>
            <td class="action">
                <button class="btn-soc" data-action="reinvestigate">REINVESTIGATE</button>
            </td>
        `;

        const detailsRow = document.createElement("tr");
        detailsRow.className = "log-details";
        detailsRow.style.display = "none";
        detailsRow.innerHTML = `
            <td colspan="7">
                <div class="details-box">
                    <p><strong>Alert ID:</strong> ${a.alertId}</p>
                    <p><strong>Severity:</strong> ${a.severity}</p>
                    <p><strong>Date:</strong> ${a.date}</p>
                    <p><strong>Rule:</strong> ${a.rule}</p>
                    <p><strong>Hostname:</strong> ${a.hostname || "–"}</p>
                    <p><strong>Type:</strong> ${a.type || "–"}</p>
                </div>
            </td>
        `;

        tbody.appendChild(row);
        tbody.appendChild(detailsRow);
    });
}

// ===============================================
// WORKFLOW ACTIONS
// ===============================================

function moveToInvestigation(alertId) {
    const row = document.querySelector(`.log-row[data-alert-id="${alertId}"]`);
    if (!row) return;

    // Extract data from the row before it may be wiped by tab switch
    const cells = row.querySelectorAll("td");
    const severity = cells[0]?.textContent.replace("▶", "").trim() || "–";
    const severityClass = cells[0]?.className || "";
    const date = cells[1]?.textContent.trim() || "-";
    const rule = cells[2]?.textContent.trim() || "-";
    const hostname = cells[3]?.textContent.trim() || "-";
    const eventId = cells[4]?.textContent.trim() || "-";
    const type = cells[5]?.textContent.trim() || "-";

    // Don't add duplicates
    if (!investigationAlerts.find(a => a.alertId === alertId)) {
        investigationAlerts.push({
            alertId, severity, severityClass, date, rule, hostname, eventId, type,
            caseId: null, source: ""
        });
    }

    // Remove the row from current view
    const detailsRow = row.nextElementSibling;
    if (detailsRow && detailsRow.classList.contains("log-details")) detailsRow.remove();
    row.remove();

    saveAlertState();

    const investigationTab = document.querySelector('.tab[data-tab="investigation"]');
    if (investigationTab) {
        switchTab("investigation", investigationTab);
    }

    showToast("Alert moved to Investigation");
}

function createCase(alertId) {
    const alert = investigationAlerts.find(a => a.alertId === alertId);
    if (!alert) return;

    const caseId = "CASE-" + String(caseIdCounter++).padStart(4, "0");
    alert.caseId = caseId;

    const caseObj = {
        id: caseId,
        alertId,
        rule: alert.rule,
        severity: alert.severity,
        date: alert.date,
        type: alert.type,
        status: "open",
        createdAt: new Date().toISOString().replace("T", " ").split(".")[0]
    };
    cases.push(caseObj);

    saveAlertState();

    // Re-render investigation tab to show the case badge
    renderInvestigationTab();
    showToast(`Case ${caseId} created`);
}

function closeAlert(alertId) {
    const idx = investigationAlerts.findIndex(a => a.alertId === alertId);
    if (idx === -1) return;

    const alert = investigationAlerts.splice(idx, 1)[0];
    closedAlertsList.push(alert);

    saveAlertState();

    // Re-render investigation tab
    renderInvestigationTab();
    showToast("Alert closed");
}

function reinvestigateAlert(alertId) {
    const idx = closedAlertsList.findIndex(a => a.alertId === alertId);
    if (idx === -1) return;

    const alert = closedAlertsList.splice(idx, 1)[0];
    alert.caseId = null; // reset case if re-investigating
    investigationAlerts.push(alert);

    saveAlertState();

    const investigationTab = document.querySelector('.tab[data-tab="investigation"]');
    if (investigationTab) {
        switchTab("investigation", investigationTab);
    }

    showToast("Alert moved back to Investigation");
}

// ===============================================
// UTILITIES
// ===============================================

function toggleLogDetails(arrow) {
    const row = arrow.closest("tr");
    const detailsRow = row.nextElementSibling;
    arrow.classList.toggle("open");
    if (detailsRow && detailsRow.classList.contains("log-details")) {
        const isHidden = getComputedStyle(detailsRow).display === "none";
        detailsRow.style.display = isHidden ? "table-row" : "none";
    }
}

function toggleFilterMenu(btn) {
    const menu = btn.parentElement.querySelector(".filter-menu");
    if (menu) {
        const isFlex = menu.style.display === "flex";
        document.querySelectorAll(".filter-menu").forEach(m => m.style.display = "none");
        menu.style.display = isFlex ? "none" : "flex";
    }
}

function applySeverityFilter(option) {
    const filterType = option.dataset.filter;
    option.parentElement.style.display = "none";

    const rows = document.querySelectorAll(".log-row");
    rows.forEach(row => {
        if (!row.dataset.channel.includes("main")) return;

        const severityText = row.querySelector("td").textContent.toLowerCase();
        const match = (filterType === "all") || severityText.includes(filterType);

        if (match) {
            row.style.display = "table-row";
        } else {
            row.style.display = "none";
            const details = row.nextElementSibling;
            if (details) details.style.display = "none";
        }
    });
}

function updateTabCounters() {
    // Reserved for future badge counts
}

function initLogManagement() {
    let logPage = 1;
    let logQuery = "";
    let logDate = "";
    let logSeverity = "";
    let logHostname = "";
    let logProcess = "";
    const LOG_PAGE_SIZE = 10;

    // Populate filter dropdowns with real data
    populateFilterDropdowns();
    fetchLogs("", 1);

    const refreshInterval = setInterval(() => {
        const activePage = document.querySelector(".menu li.active")?.dataset.page;
        if (activePage === "logs") {
            fetchLogs(logQuery, logPage);
        } else {
            clearInterval(refreshInterval);
        }
    }, 30000);

    async function populateFilterDropdowns() {
        try {
            const res = await authFetch(`${API_BASE}/api/logs/filters`);
            const data = await res.json();

            const hostSelect = document.getElementById("logFilterHostname");
            if (hostSelect && data.hostnames) {
                data.hostnames.forEach(h => {
                    const opt = document.createElement("option");
                    opt.value = h;
                    opt.textContent = h;
                    hostSelect.appendChild(opt);
                });
            }

            const procSelect = document.getElementById("logFilterProcess");
            if (procSelect && data.processes) {
                data.processes.forEach(p => {
                    const opt = document.createElement("option");
                    opt.value = p;
                    opt.textContent = p;
                    procSelect.appendChild(opt);
                });
            }
        } catch (err) {
            console.error("Failed to load filter options:", err);
        }
    }

    async function fetchLogs(query = "", page = 1) {
        const offset = (page - 1) * LOG_PAGE_SIZE;
        let params = `size=${LOG_PAGE_SIZE}&from=${offset}`;

        if (logDate) params += `&date=${encodeURIComponent(logDate)}`;
        if (logSeverity) params += `&severity=${encodeURIComponent(logSeverity)}`;
        if (logHostname) params += `&hostname=${encodeURIComponent(logHostname)}`;
        if (logProcess) params += `&process=${encodeURIComponent(logProcess)}`;

        let url;
        if (query.trim()) {
            params += `&q=${encodeURIComponent(query)}`;
            url = `${API_BASE}/api/logs/search?${params}`;
        } else {
            url = `${API_BASE}/api/logs?${params}`;
        }

        try {
            const res = await authFetch(url);
            const data = await res.json();
            const logs = Array.isArray(data) ? data : data.logs;
            const total = Array.isArray(data) ? data.length : data.total;
            renderLogList(logs);
            renderLogPagination(total || 0, page, query);
        } catch (err) {
            console.error("Failed to fetch logs:", err);
        }
    }

    function renderLogList(logs) {
        const logList = document.getElementById("logList");
        if (!logList) return;

        if (!logs || logs.length === 0) {
            logList.innerHTML = `<div class="log-item" style="color:#fff;">No logs found matching your filters.</div>`;
            return;
        }

        logList.innerHTML = logs.map(log => {
            const date = new Date(log.timestamp).toLocaleString();
            const sev = log.severity || "low";
            const sevColor = sev === "critical" ? "#ff5252"
                           : sev === "high"     ? "#ffa726"
                           : sev === "medium"   ? "#ffca28"
                           :                     "#aaa";
            return `
                <div class="log-item">
                    <span style="color:#fff;font-size:13px;">[${date}]</span>
                    <span style="color:${sevColor};font-size:13px;margin:0 8px;">[${sev.toUpperCase()}]</span>
                    <span style="color:#fff;font-size:13px;">[${log.hostname}]</span>
                    <span style="color:#fff;font-size:13px;margin-left:6px;">[${log.process || "system"}]</span>
                    <span style="margin-left:6px;">${log.message}</span>
                </div>
            `;
        }).join("");
    }

    function renderLogPagination(total, currentPage, query) {
        const pagination = document.getElementById("logPagination");
        if (!pagination) return;

        const totalPages = Math.max(1, Math.ceil(total / LOG_PAGE_SIZE));
        let btns = "";

        btns += `<button data-log-page="${currentPage - 1}" ${currentPage === 1 ? "disabled" : ""}>◀</button>`;

        for (let i = 1; i <= totalPages; i++) {
            if (i === 1 || i === totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {
                const active = i === currentPage ? "background:#fff;color:#000;border-color:#fff;" : "";
                btns += `<button data-log-page="${i}" style="${active}">${i}</button>`;
            } else if (i === currentPage - 3 || i === currentPage + 3) {
                btns += `<button disabled style="background:transparent;border:none;">…</button>`;
            }
        }

        btns += `<button data-log-page="${currentPage + 1}" ${currentPage === totalPages ? "disabled" : ""}>▶</button>`;
        pagination.innerHTML = btns;

        pagination.querySelectorAll("button[data-log-page]").forEach(btn => {
            btn.addEventListener("click", () => {
                const p = parseInt(btn.dataset.logPage, 10);
                if (p >= 1 && p <= totalPages) {
                    logPage = p;
                    fetchLogs(logQuery, logPage);
                }
            });
        });
    }

    function doSearch() {
        logQuery = (document.getElementById("logSearchInput")?.value || "").trim();
        logDate = document.getElementById("logFilterDate")?.value || "";
        logSeverity = document.getElementById("logFilterSeverity")?.value || "";
        logHostname = document.getElementById("logFilterHostname")?.value || "";
        logProcess = document.getElementById("logFilterProcess")?.value || "";
        logPage = 1;
        fetchLogs(logQuery, logPage);
    }

    const searchBtn = document.getElementById("logSearchBtn");
    const searchInput = document.getElementById("logSearchInput");

    if (searchBtn) searchBtn.addEventListener("click", doSearch);
    if (searchInput) {
        searchInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") doSearch();
        });
    }

    // Filter change triggers instant search
    ["logFilterDate", "logFilterSeverity", "logFilterHostname", "logFilterProcess"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("change", doSearch);
    });

    // Clear filters button
    const clearBtn = document.getElementById("logClearFilters");
    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            if (searchInput) searchInput.value = "";
            const dateEl = document.getElementById("logFilterDate");
            if (dateEl) dateEl.value = "";
            document.getElementById("logFilterSeverity").value = "";
            document.getElementById("logFilterHostname").value = "";
            document.getElementById("logFilterProcess").value = "";
            logQuery = "";
            logDate = "";
            logSeverity = "";
            logHostname = "";
            logProcess = "";
            logPage = 1;
            fetchLogs("", 1);
        });
    }
}

function initCasesView() {
    // Inject case management styles once
    if (!document.getElementById("case-mgmt-styles")) {
        const style = document.createElement("style");
        style.id = "case-mgmt-styles";
        style.textContent = `
            .case-card-actions {
                display: flex;
                gap: 8px;
                margin-top: 10px;
                padding-top: 10px;
                border-top: 1px solid #222;
            }
            .case-action-btn {
                background: #000;
                border: 1px solid #333;
                color: #fff;
                padding: 5px 14px;
                font-size: 12px;
                font-family: var(--font-primary);
                cursor: pointer;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                transition: 0.15s;
                border-radius: 3px;
                font-weight: 600;
            }
            .case-action-btn:hover {
                border-color: #fff;
                color: #fff;
                background: #111;
            }
            .case-close-btn:hover {
                border-color: #ff5252;
                color: #ff5252;
            }
            .case-reopen-btn:hover {
                border-color: #4caf50;
                color: #4caf50;
            }
            .case-card-detail-row {
                display: flex;
                gap: 16px;
                margin-top: 8px;
                flex-wrap: wrap;
            }
            .case-detail-chip {
                font-size: 12px;
                color: #fff;
                background: #0a0a0a;
                border: 1px solid #1e1e1e;
                padding: 3px 10px;
                border-radius: 3px;
            }
        `;
        document.head.appendChild(style);
    }
    renderCaseList("all");
}

let activeCaseFilter = "all";

function renderCaseList(filter) {
    activeCaseFilter = filter;
    const container = document.getElementById("caseList");
    if (!container) return;

    let filtered;
    if (filter === "all") {
        filtered = cases;
    } else {
        filtered = cases.filter(c => c.status === filter);
    }

    if (filtered.length === 0) {
        if (cases.length === 0) {
            container.innerHTML = `<div class="case-message">No cases yet. Create a case from the Monitoring page by moving an alert to Investigation and clicking CREATE CASE.</div>`;
        } else {
            container.innerHTML = `<div class="case-message">No ${filter} cases.</div>`;
        }
        return;
    }

    container.innerHTML = filtered.map(c => {
        const statusClass = c.status === "open" ? "case-status-open" : "case-status-closed";
        const statusLabel = c.status.toUpperCase();
        const sevClass = c.severity ? c.severity.toLowerCase() : "";

        // Build action buttons based on status
        let actionBtns = "";
        if (c.status === "open") {
            actionBtns = `<button class="case-action-btn case-close-btn" data-case-id="${c.id}">✕ CLOSE CASE</button>`;
        } else {
            actionBtns = `<button class="case-action-btn case-reopen-btn" data-case-id="${c.id}"> ↻ REOPEN CASE</button>`;
        }

        return `
            <div class="case-card">
                <div class="case-card-header">
                    <span class="case-card-id">${c.id}</span>
                    <span class="${statusClass}">${statusLabel}</span>
                </div>
                <div class="case-card-rule">${c.rule || "–"}</div>
                <div class="case-card-meta">
                    <span class="${sevClass}">${c.severity || "-"}</span> . ${c.type || "–"} . ${c.createdAt || "–"}
                </div>
                <div class="case-card-detail-row">
                    <span class="case-detail-chip">Alert: ${c.alertId || "–"}</span>
                    ${c.closedAt ? `<span class="case-detail-chip">Closed: ${c.closedAt}</span>` : ""}
                </div>
                <div class="case-card-actions">
                    ${actionBtns}
                </div>
            </div>
        `;
    }).join("");
}

function closeCaseById(caseId) {
    const c = cases.find(cs => cs.id === caseId);
    if (!c || c.status === "closed") return;

    c.status = "closed";
    c.closedAt = new Date().toISOString().replace("T", " ").split(".")[0];

    saveAlertState();
    renderCaseList(activeCaseFilter);
    showToast(`${caseId} closed`);
}

function reopenCaseById(caseId) {
    const c = cases.find(cs => cs.id === caseId);
    if (!c || c.status === "open") return;

    c.status = "open";
    delete c.closedAt;

    // Also move the associated alert back to investigation if it was closed
    const alertIdx = closedAlertsList.findIndex(a => a.alertId === c.alertId);
    if (alertIdx !== -1) {
        const alert = closedAlertsList.splice(alertIdx, 1)[0];
        alert.caseId = caseId;
        investigationAlerts.push(alert);
    }

    saveAlertState();
    renderCaseList(activeCaseFilter);
    showToast(`${caseId} reopened`);
}

function filterCases(filter, clickedTab) {
    document.querySelectorAll(".case-tab").forEach(t => t.classList.remove("active"));
    clickedTab.classList.add("active");
    renderCaseList(filter);
}

// ===============================================
// ALERTS PAGE (Sidebar)
// ===============================================

let alertsActiveTab = "rules";
let alertsSeverityFilter = "all";

function initAlertsPage() {
    // Tab switching
    document.querySelectorAll('[data-alerts-tab]').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('[data-alerts-tab]').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            alertsActiveTab = tab.dataset.alertsTab;
            
            // Hide all tables
            document.getElementById('ruleAlertsTable').style.display = 'none';
            document.getElementById('corrAlertsTable').style.display = 'none';
            document.getElementById('closedAlertsTable').style.display = 'none';
            
            // Show selected table
            if (alertsActiveTab === 'rules') document.getElementById('ruleAlertsTable').style.display = 'table';
            if (alertsActiveTab === 'correlated') document.getElementById('corrAlertsTable').style.display = 'table';
            if (alertsActiveTab === 'closed') document.getElementById('closedAlertsTable').style.display = 'table';
        });
    });

    loadAllAlerts();

    const alertsRefreshTimer = setInterval(() => {
        const activePage = document.querySelector('.menu li.active')?.dataset.page;
        if (activePage !== 'alerts') { clearInterval(alertsRefreshTimer); return; }
        loadAllAlerts();
    }, 30000);
}

async function loadAllAlerts() {
    const ruleTbody = document.getElementById('ruleAlertsBody');
    const corrTbody = document.getElementById('corrAlertsBody');
    const closedTbody = document.getElementById('closedAlertsBody');

    if (ruleTbody) {
        ruleTbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:32px;">[ LOADING... ]</td></tr>`;
        await loadAlertsRules(ruleTbody);
        bindAlertRowEvents(ruleTbody);
    }
    if (corrTbody) {
        corrTbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:32px;">[ LOADING... ]</td></tr>`;
        await loadAlertsCorrelated(corrTbody);
        bindAlertRowEvents(corrTbody);
    }
    if (closedTbody) {
        closedTbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:32px;">[ LOADING... ]</td></tr>`;
        renderAlertsClosed(closedTbody);
        bindAlertRowEvents(closedTbody);
    }
    
    updateAlertsPageStats();
}

function updateAlertsPageStats() {
    const ruleTbody = document.getElementById('ruleAlertsBody');
    const corrTbody = document.getElementById('corrAlertsBody');
    const closedTbody = document.getElementById('closedAlertsBody');

    const sRule = document.getElementById('apStatRule');
    const sCorr = document.getElementById('apStatCorr');
    const sClosed = document.getElementById('apStatClosed');

    if (sRule && ruleTbody) {
        const count = ruleTbody.querySelectorAll('.log-row').length;
        sRule.textContent = count;
    }
    if (sCorr && corrTbody) {
        const count = corrTbody.querySelectorAll('.log-row').length;
        sCorr.textContent = count;
    }
    if (sClosed && closedTbody) {
        const count = closedTbody.querySelectorAll('.log-row').length;
        sClosed.textContent = count;
    }
}

function bindAlertRowEvents(tbody) {
    if (!tbody) return;
    tbody.querySelectorAll('.arrow').forEach(arrow => {
        arrow.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleLogDetails(arrow);
        });
    });
    tbody.querySelectorAll('.action-add').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const row = btn.closest('tr');
            if (row && row.dataset.alertId) {
                moveToInvestigationFromAlerts(row.dataset.alertId, row);
            }
        });
    });
    tbody.querySelectorAll('[data-action="create-case"]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const row = btn.closest('tr');
            if (row && row.dataset.alertId) { createCase(row.dataset.alertId); loadAllAlerts(); }
        });
    });
    tbody.querySelectorAll('[data-action="close-alert"]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const row = btn.closest('tr');
            if (row && row.dataset.alertId) { closeAlert(row.dataset.alertId); loadAllAlerts(); }
        });
    });
    tbody.querySelectorAll('[data-action="reinvestigate"]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const row = btn.closest('tr');
            if (row && row.dataset.alertId) { reinvestigateFromAlertsPage(row.dataset.alertId); }
        });
    });
}

function moveToInvestigationFromAlerts(alertId, row) {
    const cells = row.querySelectorAll('td');
    const severity = cells[0]?.textContent.replace('▶', '').trim() || '–';
    const severityClass = cells[0]?.className || '';
    const date = cells[1]?.textContent.trim() || '-';
    // Handle different columns... The table heads could be different based on channel.
    // In live it's Process+Msg, Host, etc. Let's make it simpler, since the old logic was:
    const rule = cells[2]?.textContent.trim() || '-';
    const hostname = cells[3]?.textContent.trim() || '-';
    const eventId = cells[4]?.textContent.trim() || '-';
    const type = cells[5]?.textContent.trim() || '-';

    if (!investigationAlerts.find(a => a.alertId === alertId)) {
        investigationAlerts.push({ alertId, severity, severityClass, date, rule, hostname, eventId, type, caseId: null, source: '' });
        saveAlertState();
        showToast('Alert moved to Investigation');
    }
}


function renderAlertsInvestigation(tbody) {
    if (investigationAlerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px 20px;font-size:15px;letter-spacing:0.5px;">[ NO ALERTS UNDER INVESTIGATION ]</td></tr>`;
        return;
    }
    let html = '';
    investigationAlerts.forEach(a => {
        if (alertsSeverityFilter !== 'all' && a.severity?.toLowerCase() !== alertsSeverityFilter) return;
        const sevClass = a.severityClass || '';
        html += `
            <tr class="log-row" data-channel="investigation" data-alert-id="${a.alertId}">
                <td class="${sevClass}"><span class="arrow">▶</span> ${a.severity}</td>
                <td>${a.date}</td>
                <td>${a.rule}</td>
                <td>${a.hostname || '–'}</td>
                <td>${a.eventId || '–'}</td>
                <td>${a.type || '–'}</td>
                <td class="action">
                    ${a.caseId ? `<span style="color:#4caf50;font-weight:bold;">&#10004; ${a.caseId}</span>` : `<button class="btn-soc" data-action="create-case">CREATE CASE</button>`}
                    <button class="btn-soc" data-action="close-alert">CLOSE ALERT</button>
                </td>
            </tr>
            <tr class="log-details" style="display:none;">
                <td colspan="7"><div class="details-box">
                    <p><strong>Alert ID:</strong> ${a.alertId}</p>
                    <p><strong>Severity:</strong> ${a.severity}</p>
                    <p><strong>Date:</strong> ${a.date}</p>
                    <p><strong>Rule:</strong> ${a.rule}</p>
                    <p><strong>Hostname:</strong> ${a.hostname || '–'}</p>
                    <p><strong>Type:</strong> ${a.type || '–'}</p>
                </div></td>
            </tr>`;
    });
    tbody.innerHTML = html || `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px;font-size:15px;">[ NO ALERTS MATCHING FILTER ]</td></tr>`;
}

async function loadAlertsRules(tbody) {
    try {
        const res = await authFetch(`${API_BASE}/api/alerts/rules`);
        const data = await res.json();
        const alerts = data.alerts || [];
        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px 20px;font-size:15px;letter-spacing:0.5px;">[ NO RULE ALERTS FIRED YET — ENGINE EVALUATES EVERY 60s ]</td></tr>`;
            return;
        }
        let html = '';
        alerts.forEach((a, i) => {
            const sevClass = a.severity === 'critical' ? 'critical' : a.severity === 'high' ? 'high' : a.severity === 'medium' ? 'medium' : '';
            const sevLabel = (a.severity || 'info').charAt(0).toUpperCase() + (a.severity || 'info').slice(1);
            const date = new Date(a.timestamp).toLocaleString();
            if (alertsSeverityFilter !== 'all' && a.severity !== alertsSeverityFilter) return;
            const mitreBadge = a.mitre_technique ? `<span class="mitre-badge">${a.mitre_technique}</span>` : '';
            const ruleBadge = `<span class="rule-badge">RULE</span>`;
            html += `
                <tr class="log-row" data-channel="rules" data-alert-id="rule-${i}">
                    <td class="${sevClass}"><span class="arrow">▶</span> ${sevLabel}</td>
                    <td>${date}</td>
                    <td>${ruleBadge} ${a.rule_name} ${mitreBadge}</td>
                    <td>${a.matched_group || '–'}</td>
                    <td title="Event count in window">${a.matched_count}x</td>
                    <td>${a.mitre_tactic || '–'}</td>
                    <td class="action"><button class="btn-soc action-add" title="Add to Investigation">+</button></td>
                </tr>
                <tr class="log-details" style="display:none;">
                    <td colspan="7"><div class="details-box">
                        <p><strong>Rule ID:</strong> ${a.rule_id}</p>
                        <p><strong>Description:</strong> ${a.description}</p>
                        <p><strong>Fired At:</strong> ${date}</p>
                        <p><strong>Matched Host:</strong> ${a.matched_group}</p>
                        <p><strong>Hit Count:</strong> ${a.matched_count} events in last ${a.time_window_seconds}s</p>
                        <p><strong>Pattern:</strong> <code style="background:#111;padding:2px 6px;border-radius:3px;">${a.pattern}</code></p>
                        <p><strong>Severity:</strong> ${sevLabel}</p>
                        <p><strong>MITRE Tactic:</strong> ${a.mitre_tactic}</p>
                        <p><strong>MITRE Technique:</strong> ${a.mitre_technique} - ${a.mitre_technique_name}</p>
                    </div></td>
                </tr>`;
        });
        tbody.innerHTML = html || `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px;font-size:15px;">[ NO ALERTS MATCHING FILTER ]</td></tr>`;
    } catch (err) {
        console.error('Rule alerts failed:', err);
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#ff5252;padding:32px;">[ FAILED TO LOAD ]</td></tr>`;
    }
}

async function loadAlertsCorrelated(tbody) {
    try {
        const res = await authFetch(`${API_BASE}/api/alerts/correlated`);
        const data = await res.json();
        const alerts = data.alerts || [];
        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px 20px;font-size:15px;letter-spacing:0.5px;">[ NO CORRELATED ALERTS — ENGINE EVALUATES EVERY 60s ]</td></tr>`;
            return;
        }
        let html = '';
        alerts.forEach((a, i) => {
            const sevClass = a.severity === 'critical' ? 'critical' : a.severity === 'high' ? 'high' : a.severity === 'medium' ? 'medium' : '';
            const sevLabel = (a.severity || 'info').charAt(0).toUpperCase() + (a.severity || 'info').slice(1);
            const date = new Date(a.timestamp).toLocaleString();
            if (alertsSeverityFilter !== 'all' && a.severity !== alertsSeverityFilter) return;
            const mitreBadge = a.mitre_technique ? `<span class="mitre-badge">${a.mitre_technique}</span>` : '';
            const chainBadge = `<span class="chain-badge">CHAIN</span>`;
            const seqSummary = (a.sequence || []).map((step, si) => {
                const count = a.event_counts ? a.event_counts[si] : '?';
                return `${count}x <em>${step.pattern.replace(/\|/g, ' or ')}</em>`;
            }).join(" <span style='color:#fff'>&#8594;</span> ");
            html += `
                <tr class="log-row" data-channel="correlated" data-alert-id="corr-${i}">
                    <td class="${sevClass}"><span class="arrow">▶</span> ${sevLabel}</td>
                    <td>${date}</td>
                    <td>${chainBadge} ${a.rule_name} ${mitreBadge}</td>
                    <td>${a.matched_group || '–'}</td>
                    <td title="Sequence steps matched">${(a.sequence || []).length} steps</td>
                    <td>${a.mitre_tactic || '–'}</td>
                    <td class="action"><button class="btn-soc action-add" title="Add to Investigation">+</button></td>
                </tr>
                <tr class="log-details" style="display:none;">
                    <td colspan="7"><div class="details-box">
                        <p><strong>Rule ID:</strong> ${a.rule_id}</p>
                        <p><strong>Description:</strong> ${a.description}</p>
                        <p><strong>Fired At:</strong> ${date}</p>
                        <p><strong>Matched Host:</strong> ${a.matched_group}</p>
                        <p><strong>Attack Chain:</strong> ${seqSummary}</p>
                        <p><strong>Time Window:</strong> ${a.time_window_seconds}s</p>
                        <p><strong>Severity:</strong> ${sevLabel}</p>
                        <p><strong>MITRE Tactic:</strong> ${a.mitre_tactic}</p>
                        <p><strong>MITRE Technique:</strong> ${a.mitre_technique} - ${a.mitre_technique_name}</p>
                    </div></td>
                </tr>`;
        });
        tbody.innerHTML = html || `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px;font-size:15px;">[ NO ALERTS MATCHING FILTER ]</td></tr>`;
    } catch (err) {
        console.error('Correlated alerts failed:', err);
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#ff5252;padding:32px;">[ FAILED TO LOAD ]</td></tr>`;
    }
}

function renderAlertsClosed(tbody) {
    if (closedAlertsList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px 20px;font-size:15px;letter-spacing:0.5px;">[ NO CLOSED ALERTS ]</td></tr>`;
        return;
    }
    let html = '';
    closedAlertsList.forEach(a => {
        if (alertsSeverityFilter !== 'all' && a.severity?.toLowerCase() !== alertsSeverityFilter) return;
        const sevClass = a.severityClass || '';
        html += `
            <tr class="log-row" data-channel="closed" data-alert-id="${a.alertId}">
                <td class="${sevClass}"><span class="arrow">▶</span> ${a.severity}</td>
                <td>${a.date}</td>
                <td>${a.rule}</td>
                <td>${a.hostname || '–'}</td>
                <td>${a.eventId || '–'}</td>
                <td>${a.type || '–'}</td>
                <td class="action"><button class="btn-soc" data-action="reinvestigate">REINVESTIGATE</button></td>
            </tr>
            <tr class="log-details" style="display:none;">
                <td colspan="7"><div class="details-box">
                    <p><strong>Alert ID:</strong> ${a.alertId}</p>
                    <p><strong>Severity:</strong> ${a.severity}</p>
                    <p><strong>Date:</strong> ${a.date}</p>
                    <p><strong>Rule:</strong> ${a.rule}</p>
                    <p><strong>Hostname:</strong> ${a.hostname || '–'}</p>
                    <p><strong>Type:</strong> ${a.type || '–'}</p>
                </div></td>
            </tr>`;
    });
    tbody.innerHTML = html || `<tr><td colspan="7" style="text-align:center;color:#fff;padding:48px;font-size:15px;">[ NO ALERTS MATCHING FILTER ]</td></tr>`;
}

function reinvestigateFromAlertsPage(alertId) {
    reinvestigateAlert(alertId);
    setTimeout(() => loadAllAlerts(), 300);
}

// ===============================================
// ENDPOINT SECURITY
// ===============================================

let allEndpoints = [];
let epStatusFilter = "all";
let epHealthCheckTimer = null;
let epLastChecked = null;

async function initEndpointSecurity() {
    // Inject endpoint page styles once
    if (!document.getElementById("ep-page-styles")) {
        const style = document.createElement("style");
        style.id = "ep-page-styles";
        style.textContent = `
            .endpoint-container {
                background: var(--color-bg-primary);
                border: 1px solid var(--color-border-primary);
                border-radius: 6px;
                height: calc(100vh - 60px);
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }
            .ep-page-header {
                padding: 20px 24px 14px;
                border-bottom: 1px solid var(--color-border-primary);
                background: var(--color-bg-secondary);
            }
            .ep-page-title-row {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 14px;
            }
            .ep-page-title {
                font-size: 18px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 1.5px;
                margin: 0;
                color: var(--color-text-primary);
            }
            .ep-live-badge {
                font-size: 12px;
                color: #4caf50;
                font-weight: 700;
                letter-spacing: 1px;
                animation: epPulse 2s infinite;
            }
            @keyframes epPulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
            .ep-summary-stats {
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
            }
            .ep-stat-card {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 10px 16px;
                border-radius: 4px;
                border: 1px solid var(--color-border-primary);
                background: #0a0a0a;
                min-width: 120px;
            }
            .ep-stat-num {
                font-size: 24px;
                font-weight: 700;
                line-height: 1;
            }
            .ep-stat-label {
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 1px;
                color: #fff;
                line-height: 1.3;
            }

            /* Filter bar */
            .ep-filter-bar {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 12px 24px;
                border-bottom: 1px solid var(--color-border-primary);
                background: var(--color-bg-tertiary);
            }
            .ep-filter-pills {
                display: flex;
                gap: 6px;
            }
            .ep-filter-pill {
                background: #000;
                border: 1px solid #333;
                color: #fff;
                padding: 5px 12px;
                font-size: 12px;
                font-family: var(--font-primary);
                cursor: pointer;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                transition: 0.15s;
                border-radius: 3px;
                font-weight: 600;
            }
            .ep-filter-pill:hover { border-color: #fff; color: #fff; }
            .ep-filter-pill.active { border-color: #fff; color: #fff; background: #1a1a1a; }
            .ep-filter-pill[data-status="Healthy"].active { border-color: #4caf50; color: #4caf50; background: #0a1a0a; }
            .ep-filter-pill[data-status="At Risk"].active { border-color: #ffca28; color: #ffca28; background: #1a1400; }
            .ep-filter-pill[data-status="Compromised"].active { border-color: #ff5252; color: #ff5252; background: #1a0000; }
            .ep-filter-pill[data-status="Isolated"].active { border-color: #64b5f6; color: #64b5f6; background: #0a0a1a; }

            /* Systems list */
            .ep-systems-list {
                flex: 1;
                overflow-y: auto;
                padding: 16px 24px;
                scrollbar-width: thin;
                scrollbar-color: var(--color-border-primary) #0a0a0a;
            }

            /* System card */
            .ep-system-card {
                background: #111;
                border: 1px solid #1e1e1e;
                border-radius: 6px;
                margin-bottom: 10px;
                transition: all 0.2s ease;
                overflow: hidden;
            }
            .ep-system-card:hover {
                border-color: #fff;
                background: #151515;
            }
            .ep-system-card.expanded {
                border-color: #fff;
                background: #0e0e0e;
            }

            /* Card header (always visible) */
            .ep-card-header {
                display: flex;
                align-items: center;
                padding: 16px 20px;
                cursor: pointer;
                gap: 16px;
                user-select: none;
            }
            .ep-card-header:hover {
                background: rgba(255,255,255,0.02);
            }

            .ep-card-status {
                display: flex;
                align-items: center;
                gap: 8px;
                min-width: 130px;
            }
            .ep-status-dot {
                display: inline-block;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                box-shadow: 0 0 6px currentColor;
                flex-shrink: 0;
            }
            .ep-status-dot.healthy { color: #4caf50; background: #4caf50; }
            .ep-status-dot.at-risk { color: #ffca28; background: #ffca28; }
            .ep-status-dot.compromised { color: #ff5252; background: #ff5252; animation: epStatusBlink 1.5s infinite; }
            .ep-status-dot.isolated { color: #64b5f6; background: #64b5f6; }
            @keyframes epStatusBlink { 0%,100%{opacity:1} 50%{opacity:0.5} }

            .ep-card-status-label {
                font-size: 12px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .ep-card-info {
                flex: 1;
                display: flex;
                align-items: center;
                gap: 24px;
                flex-wrap: wrap;
            }
            .ep-card-hostname {
                font-size: 17px;
                font-weight: 700;
                color: var(--color-text-primary);
                min-width: 150px;
            }
            .ep-card-ip {
                font-family: var(--font-primary);
                font-size: 14px;
                color: #4fc3f7;
                min-width: 120px;
            }
            .ep-card-os {
                font-size: 14px;
                color: #fff;
                min-width: 150px;
            }
            .ep-card-events {
                font-size: 14px;
                color: #fff;
                font-weight: 600;
            }

            .ep-card-chevron {
                color: #fff;
                font-size: 16px;
                transition: transform 0.3s ease;
                flex-shrink: 0;
            }
            .ep-system-card.expanded .ep-card-chevron {
                transform: rotate(180deg);
                color: #fff;
            }

            /* Card detail (expandable) */
            .ep-card-detail {
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.35s ease, padding 0.35s ease;
                padding: 0 20px;
                background: #0a0a0a;
                border-top: 0 solid transparent;
            }
            .ep-system-card.expanded .ep-card-detail {
                max-height: 500px;
                padding: 20px;
                border-top: 1px solid #1a1a1a;
            }

            .ep-detail-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 12px;
                margin-bottom: 16px;
            }
            .ep-detail-item {
                background: #111;
                border: 1px solid #1e1e1e;
                padding: 12px 14px;
                border-radius: 4px;
            }
            .ep-detail-label {
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 1px;
                color: #fff;
                font-weight: 700;
                margin-bottom: 4px;
            }
            .ep-detail-value {
                font-size: 16px;
                color: #ddd;
                font-weight: 600;
            }
            .ep-sev-bar {
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
            }
            .ep-sev-chip {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 4px 10px;
                border-radius: 3px;
                font-size: 13px;
                font-weight: 700;
            }
            .ep-sev-chip.critical { background: #1a0000; border: 1px solid #ff5252; color: #ff5252; }
            .ep-sev-chip.high { background: #1a0d00; border: 1px solid #ff9800; color: #ff9800; }
            .ep-sev-chip.medium { background: #1a1400; border: 1px solid #ffca28; color: #ffca28; }

            .ep-policy-badge {
                display: inline-block;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.5px;
                padding: 3px 8px;
                border-radius: 3px;
                text-transform: uppercase;
                white-space: nowrap;
            }
            .ep-policy-badge.standard {
                background: #0a1a0a;
                border: 1px solid #4caf50;
                color: #4caf50;
            }
            .ep-policy-badge.monitoring {
                background: #1a1400;
                border: 1px solid #ffca28;
                color: #ffca28;
            }
            .ep-policy-badge.isolate {
                background: #1a0000;
                border: 1px solid #ff5252;
                color: #ff5252;
            }

            /* Empty state */
            .ep-empty-state {
                text-align: center;
                color: #fff;
                padding: 48px;
                font-size: 14px;
                letter-spacing: 1px;
                text-transform: uppercase;
            }
        `;
        document.head.appendChild(style);
    }

    try {
        const res = await authFetch(`${API_BASE}/api/endpoints`);
        const data = await res.json();

        if (data.status === "ok" && data.endpoints && data.endpoints.length > 0) {
            allEndpoints = data.endpoints;
        } else {
            allEndpoints = [];
        }
    } catch (err) {
        console.error("Failed to fetch endpoints:", err);
        allEndpoints = [];
    }

    epStatusFilter = "all";
    document.querySelectorAll(".ep-filter-pill").forEach(p => p.classList.remove("active"));
    const allPill = document.querySelector(".ep-filter-pill[data-status='all']");
    if (allPill) allPill.classList.add("active");

    epLastChecked = new Date();
    renderEpSummaryStats();
    applyEpFilters();
    initEpFilters();
}

function renderEpSummaryStats() {
    const container = document.getElementById("epSummaryStats");
    if (!container) return;

    const total = allEndpoints.length;
    const healthy = allEndpoints.filter(e => e.status === "Healthy").length;
    const atRisk = allEndpoints.filter(e => e.status === "At Risk").length;
    const compromised = allEndpoints.filter(e => e.status === "Compromised").length;
    const isolatedCount = allEndpoints.filter(e => e.status === "Isolated").length;

    container.innerHTML = `
        <div class="ep-stat-card">
            <span class="ep-stat-num" style="color:#fff;">${total}</span>
            <span class="ep-stat-label">Total<br>Endpoints</span>
        </div>
        <div class="ep-stat-card" style="border-left:3px solid #4caf50;">
            <span class="ep-stat-num" style="color:#4caf50;">${healthy}</span>
            <span class="ep-stat-label">Healthy<br>Systems</span>
        </div>
        <div class="ep-stat-card" style="border-left:3px solid #ffca28;">
            <span class="ep-stat-num" style="color:#ffca28;">${atRisk}</span>
            <span class="ep-stat-label">At Risk<br>Systems</span>
        </div>
        <div class="ep-stat-card" style="border-left:3px solid #ff5252;">
            <span class="ep-stat-num" style="color:#ff5252;">${compromised}</span>
            <span class="ep-stat-label">Compromised<br>Systems</span>
        </div>
        <div class="ep-stat-card" style="border-left:3px solid #64b5f6;">
            <span class="ep-stat-num" style="color:#64b5f6;">${isolatedCount}</span>
            <span class="ep-stat-label">Isolated<br>Systems</span>
        </div>
    `;
}

function renderEpSystemsList(endpoints) {
    const container = document.getElementById("epSystemsList");
    if (!container) return;

    if (endpoints.length === 0) {
        container.innerHTML = `<div class="ep-empty-state">[ NO ENDPOINTS FOUND ]</div>`;
        return;
    }

    container.innerHTML = endpoints.map((ep, idx) => {
        const statusClass = ep.status === "Compromised" ? "compromised"
            : ep.status === "At Risk" ? "at-risk"
            : ep.status === "Isolated" ? "isolated" : "healthy";
        const statusColor = ep.status === "Compromised" ? "#ff5252"
            : ep.status === "At Risk" ? "#ffca28"
            : ep.status === "Isolated" ? "#64b5f6" : "#4caf50";
        const policyClass = ep.policy.includes("Isolated") ? "isolate"
            : ep.policy.includes("Monitoring") ? "monitoring" : "standard";

        // Format last active
        let lastActiveDisplay = "-";
        let lastActiveFull = "–";
        if (ep.last_active) {
            const lastDate = new Date(ep.last_active);
            lastActiveFull = lastDate.toLocaleString();
            const now = new Date();
            const diffMs = now - lastDate;
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMs / 3600000);
            const diffDays = Math.floor(diffMs / 86400000);

            if (diffMins < 1) lastActiveDisplay = "Just now";
            else if (diffMins < 60) lastActiveDisplay = `${diffMins}m ago`;
            else if (diffHours < 24) lastActiveDisplay = `${diffHours}h ago`;
            else if (diffDays < 7) lastActiveDisplay = `${diffDays}d ago`;
            else lastActiveDisplay = lastDate.toLocaleDateString();
        }

        return `
            <div class="ep-system-card" data-ep-idx="${idx}" id="ep-card-${idx}">
                <div class="ep-card-header" data-ep-idx="${idx}">
                    <div class="ep-card-status">
                        <span class="ep-status-dot ${statusClass}"></span>
                        <span class="ep-card-status-label" style="color:${statusColor};">${ep.status}</span>
                    </div>
                    <div class="ep-card-info">
                        <span class="ep-card-hostname">${ep.hostname}</span>
                        <span class="ep-card-ip">${ep.ip || "-"}</span>
                        <span class="ep-card-os">${ep.os || "Unknown"}</span>
                        <span class="ep-card-events">Risk: ${ep.risk_score !== undefined ? ep.risk_score : 0}</span>
                    </div>
                    <span class="ep-card-chevron">v</span>
                </div>
                <div class="ep-card-detail">
                    <div class="ep-detail-grid">
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Hostname</div>
                            <div class="ep-detail-value">${ep.hostname}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">IP Address</div>
                            <div class="ep-detail-value" style="color:#4fc3f7;">${ep.ip || "-"}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Operating System</div>
                            <div class="ep-detail-value">${ep.os || "Unknown"}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Platform</div>
                            <div class="ep-detail-value">${ep.os_platform || "-"}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Architecture</div>
                            <div class="ep-detail-value">${ep.architecture || "-"}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Last Active</div>
                            <div class="ep-detail-value">${lastActiveFull}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Health Status</div>
                            <div class="ep-detail-value" style="color:${statusColor};font-weight:700;">${ep.status}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Total Events</div>
                            <div class="ep-detail-value">${(ep.event_count || 0).toLocaleString()}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Risk Score</div>
                            <div class="ep-detail-value" style="color:${statusColor}">${ep.risk_score !== undefined ? ep.risk_score : 0}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Applied Policy</div>
                            <div class="ep-detail-value"><span class="ep-policy-badge ${policyClass}">${ep.policy}</span></div>
                        </div>
                        ${ep.isolated_at ? `<div class="ep-detail-item">
                            <div class="ep-detail-label">Isolated Since</div>
                            <div class="ep-detail-value" style="color:#64b5f6;font-weight:700;">${new Date(ep.isolated_at).toLocaleString()}</div>
                        </div>` : ''}
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Auth Failures</div>
                            <div class="ep-detail-value" style="color:${ep.auth_failures > 5 ? '#ff5252' : '#ddd'};font-weight:700;">${ep.auth_failures || 0}</div>
                        </div>
                        <div class="ep-detail-item">
                            <div class="ep-detail-label">Priv Escalations</div>
                            <div class="ep-detail-value" style="color:${ep.priv_escalations > 0 ? '#ff9800' : '#ddd'};font-weight:700;">${ep.priv_escalations || 0}</div>
                        </div>
                    </div>
                    <div class="ep-sev-bar" style="display:flex; justify-content: space-between; width: 100%; align-items: center;">
                        <div style="display:flex; gap:8px;">
                            <span class="ep-sev-chip critical">CRITICAL: ${ep.critical || 0}</span>
                            <span class="ep-sev-chip high">HIGH: ${ep.high || 0}</span>
                        </div>
                        ${ep.policy === "Isolated (Network Blocked)" ? `<button class="ep-deisolate-btn" data-host="${ep.hostname}" style="background:#4caf50;color:#fff;border:1px solid #4caf50;padding:4px 12px;border-radius:3px;font-size:11px;font-weight:bold;text-transform:uppercase;cursor:pointer;">De-Isolate</button>` : (ep.status === "Compromised" ? `<button class="ep-isolate-btn" data-host="${ep.hostname}" style="background:#b71c1c;color:#fff;border:1px solid #ff5252;padding:4px 12px;border-radius:3px;font-size:11px;font-weight:bold;text-transform:uppercase;cursor:pointer;">Isolate System</button>` : '')}
                    </div>
                </div>
            </div>
        `;
    }).join("");

    // Attach click listeners for expanding/collapsing cards
    container.querySelectorAll(".ep-card-header").forEach(header => {
        header.addEventListener("click", () => {
            const idx = header.dataset.epIdx;
            const card = document.getElementById(`ep-card-${idx}`);
            if (!card) return;

            // Toggle this card
            const wasExpanded = card.classList.contains("expanded");

            // Collapse all cards first
            container.querySelectorAll(".ep-system-card.expanded").forEach(c => {
                c.classList.remove("expanded");
            });

            // If it wasn't expanded, expand it
            if (!wasExpanded) {
                card.classList.add("expanded");
                // Smooth scroll into view
                setTimeout(() => {
                    card.scrollIntoView({ behavior: "smooth", block: "nearest" });
                }, 100);
            }
        });
    });

    container.querySelectorAll(".ep-isolate-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            e.stopPropagation();
            const host = btn.dataset.host;
            if (confirm(`Are you sure you want to isolate network traffic for ${host}?`)) {
                showToast(`Isolating host ${host}...`);
                try {
                    const res = await authFetch(`${API_BASE}/api/endpoints/${host}/isolate`, { method: "POST" });
                    const data = await res.json();
                    const ep = allEndpoints.find(e => e.hostname === host);
                    if (ep) {
                        ep.status = "Isolated";
                        ep.policy = "Isolated (Network Blocked)";
                        ep.isolated_at = data.isolated_at || new Date().toISOString();
                        renderEpSummaryStats();
                        applyEpFilters();
                    }
                    showToast(`Host ${host} isolated successfully.`, "success");
                } catch (err) {
                    showToast(`Failed to isolate ${host}.`, "error");
                }
            }
        });
    });

    container.querySelectorAll(".ep-deisolate-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            e.stopPropagation();
            const host = btn.dataset.host;
            if (confirm(`Are you sure you want to restore network connectivity for ${host}?`)) {
                showToast(`Removing isolation for host ${host}...`);
                try {
                    await authFetch(`${API_BASE}/api/endpoints/${host}/deisolate`, { method: "POST" });
                    // Re-fetch endpoints to get fresh status from the backend threshold engine
                    const epRes = await authFetch(`${API_BASE}/api/endpoints`);
                    const epData = await epRes.json();
                    if (epData.status === "ok" && epData.endpoints) {
                        allEndpoints = epData.endpoints;
                    }
                    renderEpSummaryStats();
                    applyEpFilters();
                    showToast(`Host ${host} connectivity restored.`, "success");
                } catch (err) {
                    showToast(`Failed to deisolate ${host}.`, "error");
                }
            }
        });
    });
}

function initEpFilters() {
    const filterPills = document.querySelectorAll(".ep-filter-pill");
    if (!filterPills.length) return;

    filterPills.forEach(pill => {
        // Remove old listeners by cloning
        const fresh = pill.cloneNode(true);
        pill.parentNode.replaceChild(fresh, pill);

        fresh.addEventListener("click", () => {
            // Always query fresh DOM for current pills
            document.querySelectorAll(".ep-filter-pill").forEach(p => p.classList.remove("active"));
            fresh.classList.add("active");
            epStatusFilter = fresh.dataset.status;
            applyEpFilters();
        });
    });
}

function applyEpFilters() {
    let filtered = allEndpoints;

    if (epStatusFilter !== "all") {
        filtered = filtered.filter(ep => ep.status === epStatusFilter);
    }

    renderEpSystemsList(filtered);
}



// ===============================================
// HOSTS PAGE
// ===============================================

let hostsAutoRefreshTimer = null;
let currentHostname = null;
let currentHostEventType = null;

async function initHostsPage() {
    // Inject styles once
    if (!document.getElementById("hosts-styles")) {
        const style = document.createElement("style");
        style.id = "hosts-styles";
        style.textContent = `
            .hosts-page-container { padding: 0; height: 100%; display: flex; flex-direction: column; }
            .hosts-page-header { display: flex; align-items: center; gap: 12px; padding: 18px 24px 12px; border-bottom: 1px solid var(--color-border-primary); }
            .hosts-page-title { font-size: 17px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin: 0; }
            .hosts-live-badge { font-size: 12px; color: #4caf50; font-weight: 700; letter-spacing: 1px; animation: pulse 2s infinite; }
            @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
            .hosts-layout { display: flex; flex: 1; overflow: hidden; }
            .hosts-sidebar { width: 200px; min-width: 200px; border-right: 1px solid var(--color-border-primary); overflow-y: auto; padding: 12px 0; }
            .hosts-sidebar-label { font-size: 11px; font-weight: 700; letter-spacing: 1.5px; color: #fff; padding: 0 14px 8px; text-transform: uppercase; }
            .host-item { padding: 10px 14px; cursor: pointer; font-size: 14px; border-left: 3px solid transparent; transition: 0.15s; }
            .host-item:hover { background: #111; border-left-color: #fff; }
            .host-item.selected { background: #111; border-left-color: var(--color-text-primary); color: var(--color-text-primary); }
            .host-item-name { font-weight: 700; font-size: 14px; }
            .host-item-count { font-size: 12px; color: #fff; margin-top: 2px; }
            .host-item-os { font-size: 12px; color: #4caf50; margin-top: 1px; }
            .hosts-main { flex: 1; overflow-y: auto; padding: 16px 20px; }
            .hosts-placeholder { color: #fff; text-align: center; margin-top: 80px; font-size: 15px; letter-spacing: 1px; }
            .host-detail-header { display: flex; align-items: center; gap: 16px; margin-bottom: 14px; flex-wrap: wrap; }
            .host-detail-title { font-size: 17px; font-weight: 700; text-transform: uppercase; }
            .host-detail-ip { font-size: 13px; color: #4fc3f7; background: #0d1b2a; border: 1px solid #1e3a5f; padding: 2px 8px; border-radius: 3px; }
            .host-detail-os { font-size: 13px; color: #4caf50; }
            .host-event-filters { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; }
            .host-filter-btn { background: #000; border: 1px solid #333; color: #fff; padding: 4px 10px; font-size: 12px; font-family: var(--font-primary); cursor: pointer; text-transform: uppercase; letter-spacing: 0.5px; transition: 0.15s; border-radius: 2px; }
            .host-filter-btn:hover { border-color: #fff; color: #fff; }
            .host-filter-btn.active { border-color: var(--color-text-primary); color: var(--color-text-primary); background: #111; }
            .host-stats-row { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
            .host-stat-pill { font-size: 12px; padding: 3px 10px; border-radius: 2px; font-weight: 700; letter-spacing: 0.5px; }
            .host-stat-pill.critical { background: #1a0000; border: 1px solid #ff5252; color: #ff5252; }
            .host-stat-pill.high { background: #1a0d00; border: 1px solid #ff9800; color: #ff9800; }
            .host-stat-pill.medium { background: #1a1400; border: 1px solid #ffca28; color: #ffca28; }
            .host-stat-pill.low { background: #111; border: 1px solid #444; color: #fff; }
            .host-logs-table { width: 100%; border-collapse: collapse; font-size: 14px; }
            .host-logs-table th { text-align: left; padding: 7px 10px; border-bottom: 1px solid #222; color: #fff; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }
            .host-logs-table td { padding: 7px 10px; border-bottom: 1px solid #111; vertical-align: top; }
            .host-logs-table tr:hover td { background: #0a0a0a; }
            .host-log-msg { max-width: 420px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #fff; }
            .host-log-msg:hover { white-space: normal; word-break: break-all; }
            .host-sev { font-size: 12px; font-weight: 700; text-transform: uppercase; }
            .host-sev.critical { color: #ff5252; }
            .host-sev.high { color: #ff9800; }
            .host-sev.medium { color: #ffca28; }
            .host-sev.low { color: #fff; }
            .host-event-badge { font-size: 11px; background: #111; border: 1px solid #333; color: #fff; padding: 1px 5px; border-radius: 2px; text-transform: uppercase; white-space: nowrap; }
            .host-load-more { display: block; width: 100%; margin-top: 12px; background: #000; border: 1px solid #333; color: #fff; padding: 8px; font-size: 13px; font-family: var(--font-primary); cursor: pointer; text-transform: uppercase; letter-spacing: 0.5px; transition: 0.15s; }
            .host-load-more:hover { border-color: #fff; color: #fff; }
            .hosts-loading { color: #fff; text-align: center; padding: 40px; font-size: 14px; letter-spacing: 1px; }
        `;
        document.head.appendChild(style);
    }

    await loadHostsList();

    // Auto refresh every 30s if a host is selected
    if (hostsAutoRefreshTimer) clearInterval(hostsAutoRefreshTimer);
    hostsAutoRefreshTimer = setInterval(() => {
        if (currentHostname) loadHostLogs(currentHostname, currentHostEventType, false);
    }, 30000);
}

async function loadHostsList() {
    const list = document.getElementById("hostsList");
    if (!list) return;
    list.innerHTML = `<div class="hosts-loading">Loading...</div>`;

    try {
        const res = await authFetch(`${API_BASE}/api/hosts`);
        const data = await res.json();

        if (!data.hosts || data.hosts.length === 0) {
            list.innerHTML = `<div style="padding:14px;font-size:13px;color:#fff;">No hosts found.</div>`;
            return;
        }

        list.innerHTML = data.hosts.map(h => `
            <div class="host-item" data-hostname="${h.hostname}">
                <div class="host-item-name">${h.hostname}</div>
                <div class="host-item-count">${h.log_count.toLocaleString()} events</div>
            </div>
        `).join("");

        list.querySelectorAll(".host-item").forEach(item => {
            item.addEventListener("click", () => {
                list.querySelectorAll(".host-item").forEach(i => i.classList.remove("selected"));
                item.classList.add("selected");
                currentHostname = item.dataset.hostname;
                currentHostEventType = null;
                loadHostLogs(currentHostname, null, true);
            });
        });

        // Auto-select first host
        const first = list.querySelector(".host-item");
        if (first) first.click();

    } catch (err) {
        list.innerHTML = `<div style="padding:14px;font-size:13px;color:#ff5252;">Failed to load hosts.</div>`;
        console.error("Failed to load hosts:", err);
    }
}

async function loadHostLogs(hostname, eventType = null, showLoader = true) {
    const main = document.getElementById("hostsMain");
    if (!main) return;

    if (showLoader) {
        main.innerHTML = `<div class="hosts-loading">[ LOADING ${hostname.toUpperCase()} LOGS... ]</div>`;
    }

    try {
        const params = new URLSearchParams({ size: 100 });
        if (eventType) params.append("event_type", eventType);

        const res = await authFetch(`${API_BASE}/api/logs/host/${encodeURIComponent(hostname)}?${params}`);
        const data = await res.json();

        renderHostDetail(data, hostname, eventType);
    } catch (err) {
        main.innerHTML = `<div class="hosts-loading" style="color:#ff5252;">[ FAILED TO LOAD LOGS ]</div>`;
        console.error("Failed to load host logs:", err);
    }
}

function renderHostDetail(data, hostname, activeEventType) {
    const main = document.getElementById("hostsMain");
    if (!main) return;

    // Build severity pills
    const sevPills = (data.severities || []).map(s =>
        `<span class="host-stat-pill ${s.severity}">${s.severity.toUpperCase()} ${s.count}</span>`
    ).join("");

    // Build event type filter buttons
    const allBtn = `<button class="host-filter-btn ${!activeEventType ? 'active' : ''}" data-et="">ALL</button>`;
    const etBtns = (data.event_types || []).map(et =>
        `<button class="host-filter-btn ${activeEventType === et.type ? 'active' : ''}" data-et="${et.type}">
            ${et.type.replace(/_/g, " ")} <span style="color:#fff">(${et.count})</span>
        </button>`
    ).join("");

    // Build log rows
    const rows = (data.logs || []).map(log => {
        const sev = log.severity || "low";
        const date = new Date(log.timestamp).toLocaleString();
        const process = log.process || "–";
        const command = log.command ? `<span style="color:#fff;font-size:12px;">${log.command.substring(0, 60)}${log.command.length > 60 ? '...' : ''}</span>` : "";
        const eventBadge = log.event_type
            ? `<span class="host-event-badge">${log.event_type.replace(/_/g, " ")}</span>`
            : "";
        return `
            <tr>
                <td><span class="host-sev ${sev}">${sev.toUpperCase()}</span></td>
                <td style="white-space:nowrap;color:#fff;font-size:13px;">${date}</td>
                <td>${eventBadge}</td>
                <td style="color:#fff;font-size:13px;">${process}</td>
                <td class="host-log-msg" title="${log.message?.replace(/"/g, '&quot;') || ''}">${log.message || "–"}<br>${command}</td>
            </tr>
        `;
    }).join("");

    const emptyRow = data.logs.length === 0
        ? `<tr><td colspan="5" style="text-align:center;color:#fff;padding:32px;font-size:14px;letter-spacing:0.5px;">[ NO LOGS FOUND ]</td></tr>`
        : "";

    main.innerHTML = `
        <div class="host-detail-header">
            <span class="host-detail-title">${hostname}</span>
            <span class="host-detail-ip">${data.logs[0]?.host_ip || ""}</span>
            <span class="host-detail-os">${data.logs[0]?.os || ""}</span>
            <span style="font-size:13px;color:#fff;margin-left:auto;">${data.total.toLocaleString()} total events</span>
        </div>
        <div class="host-stats-row">${sevPills}</div>
        <div class="host-event-filters">${allBtn}${etBtns}</div>
        <table class="host-logs-table">
            <thead>
                <tr>
                    <th>SEV</th>
                    <th>TIME</th>
                    <th>EVENT TYPE</th>
                    <th>PROCESS</th>
                    <th>MESSAGE</th>
                </tr>
            </thead>
            <tbody>${rows}${emptyRow}</tbody>
        </table>
        ${data.total > 100 ? `<div style="font-size:13px;color:#fff;text-align:center;padding:10px;">Showing 100 of ${data.total.toLocaleString()} - refine with event type filters above</div>` : ""}
    `;

    // Attach filter button listeners
    main.querySelectorAll(".host-filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            currentHostEventType = btn.dataset.et || null;
            loadHostLogs(hostname, currentHostEventType, true);
        });
    });
}

// ===============================================
// THREAT INTEL
// ===============================================

async function initThreatIntel() {

    // -- Inject styles -----------------------------------------
    if (!document.getElementById("threat-intel-styles")) {
        const style = document.createElement("style");
        style.id = "threat-intel-styles";
        style.textContent = `
            .ti-summary-bar {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }
            .ti-stat-card {
                flex: 1;
                min-width: 120px;
                background: #0a0a0a;
                border: 1px solid #1e1e1e;
                border-radius: 4px;
                padding: 12px 16px;
                text-align: center;
            }
            .ti-stat-num {
                font-size: 26px;
                font-weight: 700;
                line-height: 1;
                margin-bottom: 4px;
            }
            .ti-stat-label {
                font-size: 11px;
                color: #fff;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .risk-badge {
                display: inline-block;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.5px;
                padding: 3px 8px;
                border-radius: 3px;
                text-transform: uppercase;
                white-space: nowrap;
            }
            .risk-critical { background: #1a0000; border: 1px solid #ff5252; color: #ff5252; }
            .risk-suspicious { background: #1a0d00; border: 1px solid #ff9800; color: #ff9800; }
            .risk-clean { background: #0a1a0a; border: 1px solid #4caf50; color: #4caf50; }
            .ti-score-bar {
                display: inline-block;
                width: 60px;
                height: 6px;
                background: #1a1a1a;
                border-radius: 3px;
                vertical-align: middle;
                margin-left: 6px;
                overflow: hidden;
            }
            .ti-score-fill {
                height: 100%;
                border-radius: 3px;
                transition: width 0.4s ease;
            }
            .ti-action-btn {
                background: #000;
                border: 1px solid #333;
                color: #fff;
                padding: 3px 8px;
                font-size: 11px;
                font-family: var(--font-primary);
                cursor: pointer;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                border-radius: 2px;
                transition: 0.15s;
                white-space: nowrap;
            }
            .ti-action-btn:hover { border-color: #fff; color: #fff; }
            .ti-action-btn.block:hover { border-color: #ff5252; color: #ff5252; }
            .ti-action-btn.watch:hover { border-color: #ffca28; color: #ffca28; }
            .ti-action-btn.copy:hover { border-color: #4fc3f7; color: #4fc3f7; }
            .ti-report-pills {
                display: flex;
                gap: 4px;
                flex-wrap: wrap;
            }
            .ti-report-pill {
                font-size: 11px;
                padding: 2px 6px;
                background: #111;
                border: 1px solid #222;
                border-radius: 2px;
                color: #fff;
                white-space: nowrap;
            }
            .ti-report-pill span {
                color: #fff;
                font-weight: 700;
            }
            .watchlist-badge {
                display: inline-block;
                font-size: 11px;
                color: #ffca28;
                border: 1px solid #ffca28;
                padding: 1px 5px;
                border-radius: 2px;
                margin-left: 4px;
            }
            .blocked-badge {
                display: inline-block;
                font-size: 11px;
                color: #ff5252;
                border: 1px solid #ff5252;
                padding: 1px 5px;
                border-radius: 2px;
                margin-left: 4px;
            }
        `;
        document.head.appendChild(style);
    }

    // -- State -------------------------------------------------
    let watchlist = JSON.parse(localStorage.getItem("ti_watchlist") || "[]");
    let blocklist = JSON.parse(localStorage.getItem("ti_blocklist") || "[]");
    let enrichedResults = [];

    // -- Helper: Risk level ------------------------------------
    function getRisk(score) {
        if (score >= 75) return { label: "CRITICAL THREAT", cls: "risk-critical", color: "#ff5252" };
        if (score >= 25) return { label: "SUSPICIOUS", cls: "risk-suspicious", color: "#ff9800" };
        return { label: "CLEAN", cls: "risk-clean", color: "#4caf50" };
    }

    // -- Helper: Country code display (no emoji) ---------------
    function countryFlag(code) {
        if (!code || code.length !== 2) return "";
        return `<span style="font-size:12px;font-weight:700;color:#4fc3f7;background:#0d1b2a;border:1px solid #1e3a5f;padding:1px 5px;border-radius:2px;letter-spacing:1px;">${code.toUpperCase()}</span>`;
    }

    // -- Summary stats bar -------------------------------------
    function updateSummaryBar(results) {
        const total = results.length;
        const malicious = results.filter(r => r.abuse_score >= 75).length;
        const suspicious = results.filter(r => r.abuse_score >= 25 && r.abuse_score < 75).length;
        const clean = results.filter(r => r.abuse_score < 25).length;
        const tor = results.filter(r => r.is_tor).length;

        document.getElementById("tiStatTotal").textContent = total;
        document.getElementById("tiStatMalicious").textContent = malicious;
        document.getElementById("tiStatSuspicious").textContent = suspicious;
        document.getElementById("tiStatClean").textContent = clean;
        document.getElementById("tiStatTor").textContent = tor;
    }

    // -- Render table row --------------------------------------
    function renderRow(r) {
        const risk = getRisk(r.abuse_score);
        const flag = countryFlag(r.country);
        const geo = [r.city, r.country].filter(Boolean).join(", ");
        const lastReported = r.last_reported
            ? new Date(r.last_reported).toLocaleDateString() : "Never";
        const isWatched = watchlist.includes(r.ip);
        const isBlocked = blocklist.includes(r.ip);

        const scoreBarColor = r.abuse_score >= 75 ? "#ff5252"
            : r.abuse_score >= 25 ? "#ff9800" : "#4caf50";

        const flags = [
            r.is_tor ? `<span style="color:#ff5252;font-size:11px;font-weight:700;border:1px solid #ff5252;padding:1px 4px;border-radius:2px;">TOR</span>` : "",
            r.is_whitelisted ? `<span style="color:#4caf50;font-size:11px;border:1px solid #4caf50;padding:1px 4px;border-radius:2px;">WL</span>` : "",
            isWatched ? `<span class="watchlist-badge">WATCH</span>` : "",
            isBlocked ? `<span class="blocked-badge">BLOCKED</span>` : "",
        ].filter(Boolean).join(" ");
        return `
            <tr class="log-row" data-ip="${r.ip}">
                <td style="font-family:monospace;color:#4fc3f7;">
                    ${r.ip}
                    ${flags ? `<br><span style="margin-top:3px;display:inline-flex;gap:3px;flex-wrap:wrap;">${flags}</span>` : ""}
                </td>
                <td>
                    <span class="risk-badge ${risk.cls}">${risk.label}</span>
                    <br>
                    <span style="font-size:13px;color:${scoreBarColor};font-weight:700;">${r.abuse_score}%</span>
                    <span class="ti-score-bar">
                        <span class="ti-score-fill" style="width:${r.abuse_score}%;background:${scoreBarColor};"></span>
                    </span>
                </td>
                <td>
                    ${flag}
                    <span style="color:#fff;font-size:14px;margin-left:4px;">${geo || "-"}</span>
                </td>
                <td>
                    <span style="color:#fff;font-size:13px;font-weight:700;">${r.isp_short || "-"}</span>
                    <br>
                    <span style="color:#fff;font-size:12px;" title="${r.isp}">${r.usage_type || ""}</span>
                </td>
                <td>
                    <div class="ti-report-pills">
                        <span class="ti-report-pill">30d <span>${r.reports_30d ?? r.total_reports}</span></span>
                        <span class="ti-report-pill">60d <span>${r.reports_60d ?? r.total_reports}</span></span>
                        <span class="ti-report-pill">90d <span>${r.reports_90d ?? r.total_reports}</span></span>
                    </div>
                </td>
                <td style="color:#fff;font-size:13px;">${lastReported}</td>
                <td>
                    <div style="display:flex;gap:4px;flex-wrap:wrap;">
                        <button class="ti-action-btn block" data-action="block" data-ip="${r.ip}" title="Block IP">BLOCK</button>
                        <button class="ti-action-btn watch" data-action="watch" data-ip="${r.ip}" title="Add to Watchlist">WATCH</button>
                        <button class="ti-action-btn copy" data-action="copy" data-ip="${r.ip}" title="Copy IP">COPY</button>
                    </div>
                </td>
            </tr>
        `;
    }

    // -- Render table ------------------------------------------
    function renderTable(results) {
        const tbody = document.getElementById("threatTableBody");
        if (!tbody) return;

        if (!results || results.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:32px;font-size:14px;">
                [ NO PUBLIC ATTACKER IPs FOUND ]
            </td></tr>`;
            return;
        }

        tbody.innerHTML = results.map(r => renderRow(r)).join("");

        // Attach action button listeners
        tbody.querySelectorAll(".ti-action-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const ip = btn.dataset.ip;
                const action = btn.dataset.action;

                if (action === "copy") {
                    navigator.clipboard.writeText(ip).then(() => showToast(`Copied ${ip}`));

                } else if (action === "block") {
                    if (!blocklist.includes(ip)) {
                        blocklist.push(ip);
                        localStorage.setItem("ti_blocklist", JSON.stringify(blocklist));
                        showToast(`${ip} added to blocklist`);
                    } else {
                        blocklist = blocklist.filter(b => b !== ip);
                        localStorage.setItem("ti_blocklist", JSON.stringify(blocklist));
                        showToast(`${ip} removed from blocklist`);
                    }
                    renderTable(enrichedResults);

                } else if (action === "watch") {
                    if (!watchlist.includes(ip)) {
                        watchlist.push(ip);
                        localStorage.setItem("ti_watchlist", JSON.stringify(watchlist));
                        showToast(`${ip} added to watchlist`);
                    } else {
                        watchlist = watchlist.filter(w => w !== ip);
                        localStorage.setItem("ti_watchlist", JSON.stringify(watchlist));
                        showToast(`${ip} removed from watchlist`);
                    }
                    renderTable(enrichedResults);
                }
            });
        });
    }

    // -- Single IP lookup --------------------------------------
    document.getElementById("threatLookupBtn").addEventListener("click", async () => {
        const ip = document.getElementById("threatIpInput").value.trim();
        if (!ip) return;

        const resultDiv = document.getElementById("threatSingleResult");
        resultDiv.innerHTML = `<div style="color:#fff;font-size:14px;padding:10px 0;">[ LOOKING UP ${ip}... ]</div>`;

        try {
            const res = await authFetch(`${API_BASE}/api/threat/lookup/${ip}`);
            const data = await res.json();

            if (data.status !== "ok") {
                resultDiv.innerHTML = `<div style="color:#ff5252;font-size:14px;">[ ERROR: ${data.message} ]</div>`;
                return;
            }

            const risk = getRisk(data.abuse_score);
            const flag = countryFlag(data.country);
            const scoreBarColor = data.abuse_score >= 75 ? "#ff5252"
                : data.abuse_score >= 25 ? "#ff9800" : "#4caf50";

            resultDiv.innerHTML = `
                <div style="background:#0a0a0a;border:1px solid #222;padding:16px;margin-bottom:16px;border-left:3px solid ${scoreBarColor};">
                    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
                        <span style="font-family:monospace;color:#4fc3f7;font-size:16px;font-weight:700;">${data.ip}</span>
                        <span class="risk-badge ${risk.cls}">${risk.label}</span>
                        ${flag}
                        ${data.is_tor ? `<span style="color:#ff5252;font-size:12px;border:1px solid #ff5252;padding:2px 6px;border-radius:2px;">TOR EXIT NODE</span>` : ""}
                    </div>
                    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;font-size:14px;">
                        <div style="background:#111;padding:10px;border-radius:3px;">
                            <div style="color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Abuse Score</div>
                            <div style="color:${scoreBarColor};font-size:22px;font-weight:700;">${data.abuse_score}%</div>
                            <div class="ti-score-bar" style="width:100%;margin-top:6px;margin-left:0;">
                                <div class="ti-score-fill" style="width:${data.abuse_score}%;background:${scoreBarColor};"></div>
                            </div>
                        </div>
                        <div style="background:#111;padding:10px;border-radius:3px;">
                            <div style="color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Location</div>
                            <div style="color:#fff;display:flex;align-items:center;gap:6px;">${flag} ${[data.city, data.country].filter(Boolean).join(", ") || "-"}</div>
                        </div>
                        <div style="background:#111;padding:10px;border-radius:3px;">
                            <div style="color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">ISP</div>
                            <div style="color:#fff;font-weight:700;">${data.isp_short || "-"}</div>
                            <div style="color:#fff;font-size:12px;margin-top:2px;">${data.isp || ""}</div>
                        </div>
                        <div style="background:#111;padding:10px;border-radius:3px;">
                            <div style="color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Reports</div>
                            <div class="ti-report-pills" style="margin-top:4px;">
                                <span class="ti-report-pill">30d <span>${data.reports_30d}</span></span>
                                <span class="ti-report-pill">60d <span>${data.reports_60d}</span></span>
                                <span class="ti-report-pill">90d <span>${data.reports_90d}</span></span>
                            </div>
                        </div>
                        <div style="background:#111;padding:10px;border-radius:3px;">
                            <div style="color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Usage Type</div>
                            <div style="color:#fff;">${data.usage_type || "-"}</div>
                        </div>
                        <div style="background:#111;padding:10px;border-radius:3px;">
                            <div style="color:#fff;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Last Reported</div>
                            <div style="color:#fff;">${data.last_reported ? new Date(data.last_reported).toLocaleString() : "Never"}</div>
                        </div>
                    </div>
                </div>
            `;
        } catch (err) {
            resultDiv.innerHTML = `<div style="color:#ff5252;font-size:14px;">[ FAILED TO LOOKUP IP ]</div>`;
        }
    });

    // -- Enrich attackers --------------------------------------
    document.getElementById("threatEnrichBtn").addEventListener("click", async () => {
        const tbody = document.getElementById("threatTableBody");
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#fff;padding:32px;font-size:14px;">[ ENRICHING ATTACKER IPs... ]</td></tr>`;

        try {
            const res = await authFetch(`${API_BASE}/api/threat/enrich`);
            const data = await res.json();

            enrichedResults = data.results || [];
            updateSummaryBar(enrichedResults);
            renderTable(enrichedResults);

        } catch (err) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#ff5252;padding:32px;font-size:14px;">[ FAILED TO LOAD THREAT DATA ]</td></tr>`;
        }
    });

    // Auto-load
    document.getElementById("threatEnrichBtn").click();
}
function showToast(message, type) {
    const borderColor = type === "success" ? "#4caf50" : type === "error" ? "#ff5252" : "#fff";
    const toast = document.createElement("div");
    toast.textContent = message;
    Object.assign(toast.style, {
        position: "fixed",
        bottom: "24px",
        right: "24px",
        background: "#1a1a1a",
        color: "#fff",
        border: "1px solid #333",
        borderLeft: `4px solid ${borderColor}`,
        padding: "12px 20px",
        fontFamily: "'Space Mono', monospace",
        fontSize: "13px",
        zIndex: "9999",
        borderRadius: "4px",
        opacity: "1",
        transition: "opacity 0.4s ease",
        boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
        letterSpacing: "0.5px"
    });
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 400);
    }, 2500);
}
