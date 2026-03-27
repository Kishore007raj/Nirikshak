const API_BASE = 'http://127.0.0.1:8000';
let socket;

// DOM Elements
const elements = {
    btnScan: document.getElementById('btn-scan'),
    btnText: document.querySelector('#btn-scan .btn-text'),
    spinner: document.querySelector('#btn-scan .spinner'),
    providerSelect: document.getElementById('cloud-provider'),
    riskScore: document.getElementById('risk-score'),
    riskStatus: document.getElementById('risk-status'),
    complianceScore: document.getElementById('compliance-score'),
    complianceStatus: document.getElementById('compliance-status'),
    complianceCircle: document.getElementById('compliance-circle'),
    kpiScanTime: document.getElementById('kpi-scan-time'),
    kpiRps: document.getElementById('kpi-rps'),
    kpiDensity: document.getElementById('kpi-density'),
    severityChart: document.getElementById('severity-chart'),
    historyList: document.getElementById('history-list'),
    findingsBody: document.getElementById('findings-body'),
    scanTimestamp: document.getElementById('scan-timestamp'),
    progressCircle: document.querySelector('.progress-ring__circle'),
    toastContainer: document.getElementById('toast-container'),
    initialState: document.getElementById('initial-state'),
    dashboardLeft: document.getElementById('dashboard-left'),
    dashboardRight: document.getElementById('dashboard-right'),
    downloadReportBtn: document.getElementById('downloadReport'),
    summaryText: document.getElementById('summaryText'),
    providerBadge: document.getElementById('providerBadge')
};

// Circle properties
const radius = elements.progressCircle.r.baseVal.value;
const circumference = radius * 2 * Math.PI;

[elements.progressCircle, elements.complianceCircle].forEach(c => {
    if (c) {
        c.style.strokeDasharray = `${circumference} ${circumference}`;
        c.style.strokeDashoffset = circumference;
    }
});

// State
let isScanning = false;

// Initialization
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    elements.btnScan.addEventListener('click', runScan);
});

// Setup progress ring
function setProgress(percent, color, circleElem) {
    if (!circleElem) return;
    const offset = circumference - (percent / 100) * circumference;
    circleElem.style.strokeDashoffset = offset;
    circleElem.style.stroke = color;
}

// Show Toast Notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<div>${message}</div>`;
    
    elements.toastContainer.appendChild(toast);
    
    // Animate in
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Remove after 3s
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// WebSocket connection
function initWebSocket() {
    socket = new WebSocket("ws://127.0.0.1:8000/ws/scan");
    
    socket.onopen = () => {
        console.log("WebSocket connected");
    };
    
    socket.onclose = () => {
        console.log("WebSocket disconnected. Reconnecting in 3s...");
        setTimeout(initWebSocket, 3000);
    };

    socket.onerror = (err) => {
        console.error("WebSocket error", err);
    };

    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.status === "started") {
            showLoading();
            showToast(`Starting scan...`, 'info');
        }

        if (data.status === "progress") {
            showToast(`Progress: ${data.stage} (${data.progress}%)`, 'info');
        }

        if (data.status === "completed") {
            const payload = data.data || data;
            renderDashboard(payload);
            loadHistory();
            enablePDF(payload.scan_id);
            stopLoading();
            showToast("Scan completed successfully!", "success");
        }

        if (data.status === "error") {
            stopLoading();
            showError(data.message || "Unknown scan error");
        }
    };
}

// Enable PDF Download — triggers actual file download
function enablePDF(scanId) {
    if (!scanId) return;
    elements.downloadReportBtn.classList.remove('hidden');
    elements.downloadReportBtn.disabled = false;
    elements.downloadReportBtn.onclick = () => {
        // Create a hidden anchor to trigger proper file download
        const link = document.createElement('a');
        link.href = `${API_BASE}/download/${scanId}`;
        link.download = `nirikshak_report_${scanId}.pdf`;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast("Downloading PDF report...", "info");
    };
}

// Run a scan
function runScan() {
    if (isScanning) return;
    
    const provider = elements.providerSelect.value;
    // Hide UI initial state
    elements.initialState.classList.add('hidden');
    
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ provider }));
    } else {
        showError("WebSocket not connected");
    }
}

function showLoading() {
    isScanning = true;
    elements.btnScan.disabled = true;
    elements.btnText.textContent = "Scanning...";
    elements.spinner.classList.remove('hidden');
    elements.downloadReportBtn.classList.add('hidden');
    
    // Ensure dashboard is visible but indicates loading
    elements.initialState.classList.add('hidden');
    elements.dashboardLeft.classList.remove('hidden');
    elements.dashboardRight.classList.remove('hidden');
    
    // Reset contents
    elements.riskScore.innerHTML = "--";
    elements.complianceScore.innerHTML = "--";
    elements.kpiScanTime.innerHTML = "-- s";
    elements.kpiRps.innerHTML = "--";
    elements.kpiDensity.innerHTML = "--";
    
    setProgress(0, '#94a3b8', elements.progressCircle);
    setProgress(0, '#94a3b8', elements.complianceCircle);
    elements.findingsBody.innerHTML = '<tr><td colspan="8" class="empty-state" style="text-align:center; padding: 3rem;">Scanning resources...</td></tr>';
}

function stopLoading() {
    isScanning = false;
    elements.btnScan.disabled = false;
    elements.btnText.textContent = "Run Scan";
    elements.spinner.classList.add('hidden');
}

function showError(msg) {
    showToast(msg, "error");
    elements.findingsBody.innerHTML = `<tr><td colspan="8" class="empty-state" style="text-align:center; padding: 3rem; color:#ef4444;">Scan Error: ${escapeHtml(msg)}</td></tr>`;
}

// Fetch scan history
async function loadHistory() {
    try {
        const res = await fetch(`${API_BASE}/history`);
        if (res.ok) {
            const history = await res.json();
            updateHistory(history);
        }
    } catch (err) {
        console.error("Failed to load history", err);
    }
}

// Animation for number
function animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        obj.innerHTML = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        } else {
            obj.innerHTML = end;
        }
    };
    window.requestAnimationFrame(step);
}

// Update the main dashboard UI
function renderDashboard(data) {
    if (!data) return;
    
    // Risk Score - EXACT match to backend SEVERITY_WEIGHTS + normalize_severity
    const score = data.risk_score || 0;
    
    let color = '#22c55e'; // Green (LOW)
    let statusText = 'Low Risk';
    
    // Match backend: CRITICAL >= 70, MEDIUM >= 30, LOW < 30
    if (score >= 70) {
        color = '#ef4444'; // Red
        statusText = 'Critical Risk';
    } else if (score >= 30) {
        color = '#eab308'; // Yellow
        statusText = 'Moderate Risk';
    } else if (score === 0 && (!data.findings || data.findings.length === 0)) {
        color = '#22c55e';
        statusText = 'Secure';
    }
    
    const scoreEl = elements.riskScore;
    const currentScore = parseInt(scoreEl.textContent) || 0;
    animateValue(scoreEl, currentScore, score, 1000);
    
    elements.riskStatus.textContent = statusText;
    elements.riskStatus.style.color = color;
    elements.riskStatus.style.backgroundColor = `${color}20`;
    
    setProgress(score, color, elements.progressCircle);
    
    // Compliance Score
    if (data.compliance) {
        const cScore = data.compliance.score || 0;
        let cColor = '#22c55e'; // Green
        let cStatusText = 'Compliant';
        
        if (cScore < 50) {
            cColor = '#ef4444'; // Red
            cStatusText = 'Non-Compliant';
        } else if (cScore < 80) {
            cColor = '#eab308'; // Yellow
            cStatusText = 'Partial Compliance';
        }
        
        const cScoreEl = elements.complianceScore;
        const currentCScore = parseInt(cScoreEl.textContent) || 0;
        animateValue(cScoreEl, currentCScore, cScore, 1000);
        
        elements.complianceStatus.textContent = cStatusText;
        elements.complianceStatus.style.color = cColor;
        elements.complianceStatus.style.backgroundColor = `${cColor}20`;
        
        setProgress(cScore, cColor, elements.complianceCircle);
    }
    
    // KPI Metrics
    if (data.metrics) {
        elements.kpiScanTime.textContent = (data.metrics.scan_time_sec || 0).toFixed(2) + ' s';
        elements.kpiRps.textContent = (data.metrics.resources_per_sec || 0).toFixed(1);
        elements.kpiDensity.textContent = (data.metrics.findings_density || 0).toFixed(2);
    }
    
    // Timestamp
    if (data.timestamp) {
        const date = new Date(data.timestamp);
        const istStr = date.toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
            dateStyle: "medium",
            timeStyle: "short"
        });
        elements.scanTimestamp.textContent = `Last scanned: ${istStr}`;
    }
    
    // Severity Breakdown
    updateSeverityChart(data.summary);
    
    // Findings Table
    updateFindingsTable(data.findings);

    // Summary message and provider badge
    renderSummary(data);
    updateProviderBadge(data.provider);
}

function renderSummary(data) {
    const critical = data.summary.critical || data.summary.CRITICAL || 0;
    const high = data.summary.high || data.summary.HIGH || 0;
    const medium = data.summary.medium || data.summary.MEDIUM || 0;
    const total = critical + high + medium;
    const hasFindings = data.findings && data.findings.length > 0;

    let message = "";
    let bgColor = "rgba(34, 197, 94, 0.1)";
    let borderColor = "#22c55e";

    if (!hasFindings) {
        message = "No security misconfigurations detected. High posture maturity confirmed.";
        bgColor = "rgba(34, 197, 94, 0.15)";
        borderColor = "#22c55e";
    } else if (critical > 0) {
        message = `${critical} critical misconfiguration${critical > 1 ? 's' : ''} detected exposing resources to severe risk. Immediate remediation required.`;
        bgColor = "rgba(239, 68, 68, 0.1)";
        borderColor = "#ef4444";
    } else if (high > 0) {
        message = `${high} high-risk misconfiguration${high > 1 ? 's' : ''} detected. Review and remediate before production deployment.`;
        bgColor = "rgba(249, 115, 22, 0.1)";
        borderColor = "#f97316";
    } else if (medium > 0) {
        message = `${medium} medium-risk finding${medium > 1 ? 's' : ''} detected. Security posture is acceptable but can be improved.`;
        bgColor = "rgba(234, 179, 8, 0.1)";
        borderColor = "#eab308";
    } else {
        message = "Only low-risk findings detected. Overall status remains within acceptable security thresholds.";
    }

    elements.summaryText.innerText = message;
    elements.summaryText.style.display = "block";
    elements.summaryText.style.background = bgColor;
    elements.summaryText.style.borderLeft = `4px solid ${borderColor}`;
}

function updateProviderBadge(provider) {
    if (!provider) return;
    const badge = elements.providerBadge;
    badge.innerText = provider.toUpperCase();
    badge.className = "badge";
    badge.classList.add(provider.toLowerCase());
}

// Update severity chart
function updateSeverityChart(summary) {
    if (!summary) summary = { critical: 0, high: 0, medium: 0, low: 0 };
    const chartParams = [
        { key: 'critical', label: 'Critical', cssClass: 'critical', count: summary.CRITICAL || summary.critical || 0 },
        { key: 'high', label: 'High', cssClass: 'high', count: summary.HIGH || summary.high || 0 },
        { key: 'medium', label: 'Medium', cssClass: 'medium', count: summary.MEDIUM || summary.medium || 0 },
        { key: 'low', label: 'Low', cssClass: 'low', count: summary.LOW || summary.low || 0 }
    ];
    
    const total = chartParams.reduce((sum, item) => sum + item.count, 0);
    
    if (total === 0) {
        elements.severityChart.innerHTML = '<div class="empty-state">No findings to display</div>';
        return;
    }
    
    let html = '';
    chartParams.forEach(item => {
        const percent = total > 0 ? (item.count / total) * 100 : 0;
        html += `
            <div class="severity-bar-item">
                <div class="severity-header">
                    <span class="severity-label lbl-${item.cssClass}">${item.label}</span>
                    <span class="severity-count">${item.count}</span>
                </div>
                <div class="bar-bg">
                    <div class="bar-fill fill-${item.cssClass}" style="width: 0%" data-width="${percent}%"></div>
                </div>
            </div>
        `;
    });
    
    elements.severityChart.innerHTML = html;
    
    // Trigger animation slightly after DOM injection
    setTimeout(() => {
        const bars = elements.severityChart.querySelectorAll('.bar-fill');
        bars.forEach(bar => {
            bar.style.width = bar.getAttribute('data-width');
        });
    }, 50);
}

// Update History
function updateHistory(historyList) {
    if (!historyList || historyList.length === 0) {
        elements.historyList.innerHTML = '<div class="empty-state">No history available</div>';
        return;
    }
    
    // Sort by timestamp desc, take top 10
    const sorted = [...historyList].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 10);
    
    elements.historyList.innerHTML = sorted.map(item => {
        const date = new Date(item.timestamp);
        const timeStr = date.toLocaleString("en-IN", {
            timeZone: "Asia/Kolkata",
            dateStyle: "medium",
            timeStyle: "short"
        });
        
        let colorClass = 'success';
        if (item.risk_score >= 70) colorClass = 'critical';
        else if (item.risk_score >= 30) colorClass = 'medium';
        
        return `
            <li class="history-item">
                <div class="hist-details">
                    <div class="hist-time">${timeStr} <span style="font-size:0.75rem; color:#64748b;">(${item.provider})</span></div>
                </div>
                <div class="hist-score badge badge-${colorClass}">${item.risk_score}</div>
            </li>
        `;
    }).join('');
}


// Update Findings Table — includes all 8 columns, no truncation on resource/severity
function updateFindingsTable(findings) {
    if (!findings || findings.length === 0) {
        elements.findingsBody.innerHTML = '<tr><td colspan="8" class="empty-state" style="text-align:center; padding: 3rem;">No findings available</td></tr>';
        return;
    }
    
    // Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
    const severityMap = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    const sorted = [...findings].sort((a, b) => {
        return (severityMap[b.severity] || 0) - (severityMap[a.severity] || 0);
    });
    
    elements.findingsBody.innerHTML = sorted.map(f => {
        const sevLower = (f.severity || '').toLowerCase();
        const resourceId = f.resource_id || 'N/A';
        const resType = f.type || f.resource_type || 'unknown';
        const severity = f.severity || 'LOW';
        const description = f.description || 'No description available';
        const impact = f.impact || 'No impact assessment available';
        const fixSuggestion = f.fix_suggestion || 'No fix suggestion available';
        const compliance = f.compliance || 'CIS Benchmark';
        
        return `
            <tr>
                <td class="cell-resource">${escapeHtml(resourceId)}</td>
                <td class="cell-type">${escapeHtml(resType)}</td>
                <td class="cell-severity"><span class="badge badge-${sevLower}">${escapeHtml(severity)}</span></td>
                <td class="cell-desc">${escapeHtml(description)}</td>
                <td class="cell-impact">${escapeHtml(impact)}</td>
                <td class="cell-fix">${escapeHtml(fixSuggestion)}</td>
                <td class="cell-compliance">${escapeHtml(compliance)}</td>
            </tr>
        `;
    }).join('');
}

// Utility to escape HTML
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return String(unsafe);
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}
