let isRunning = false;
let logPollInterval = null;
let statusPollInterval = null;
let lastLogCount = 0;
let currentLogs = [];

document.addEventListener('DOMContentLoaded', () => {
    checkStatus();
    fetchGateway();
    statusPollInterval = setInterval(checkStatus, 2000); // Check status every 2s
});

async function fetchGateway() {
    try {
        const response = await fetch('/api/gateway');
        const data = await response.json();
        if (data.gateway_ip) {
            document.getElementById('gateway-ip').value = data.gateway_ip;
        }
    } catch (e) {
        console.error("Failed to fetch gateway", e);
    }
}

async function checkStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        if (data.running !== isRunning) {
            toggleUI(data.running);
            if (data.running) {
                // If we just discovered it's running (e.g. reload page), start polling logs
                startLogPolling();
            } else {
                stopLogPolling();
            }
        }
    } catch (e) {
        console.error("Status check failed", e);
    }
}

async function scanNetwork() {
    const btn = document.getElementById('btn-scan');
    const tableBody = document.querySelector('#device-table tbody');

    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
    btn.disabled = true;
    tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Scanning in progress...</td></tr>';

    try {
        const response = await fetch('/api/scan', { method: 'POST' });
        const devices = await response.json();

        tableBody.innerHTML = '';
        if (devices.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No devices found.</td></tr>';
        } else {
            devices.forEach(d => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${d.ip}</td>
                    <td>${d.mac}</td>
                    <td><span class="badge" style="background:#444">${d.vendor || 'Unknown'}</span></td>
                    <td>${d.hostname || 'Unknown'}</td>
                    <td>
                        <button class="btn-sm primary" onclick="selectTarget('${d.ip}')">
                            Target
                        </button>
                    </td>
                `;
                tableBody.appendChild(tr);
            });
        }

    } catch (e) {
        console.error("Scan failed", e);
        tableBody.innerHTML = '<tr><td colspan="3" class="text-center text-muted" style="color:var(--danger)">Scan failed. Run as Sudo?</td></tr>';
    } finally {
        btn.innerHTML = '<i class="fa-solid fa-radar"></i> Scan Net';
        btn.disabled = false;
    }
}

function selectTarget(ip) {
    document.getElementById('target-ip').value = ip;
}

async function startAttack() {
    const target = document.getElementById('target-ip').value;
    const gateway = document.getElementById('gateway-ip').value;

    if (!target || !gateway) {
        alert("Please set Target and Gateway IPs");
        return;
    }

    try {
        const response = await fetch('/api/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_ip: target, gateway_ip: gateway })
        });

        const data = await response.json();
        if (response.ok) {
            toggleUI(true);
            startLogPolling();
            addSystemLog(`Attack started on ${target}`);
        } else {
            alert("Error: " + data.error);
        }
    } catch (e) {
        alert("Failed to start attack");
    }
}

async function stopAttack() {
    try {
        await fetch('/api/stop', { method: 'POST' });
        toggleUI(false);
        stopLogPolling();
        addSystemLog("Attack stopped.");
    } catch (e) {
        console.error("Stop failed", e);
    }
}

function toggleUI(running) {
    isRunning = running;

    // Header Status
    const indicator = document.getElementById('global-status');
    indicator.innerHTML = running ? '<span class="dot"></span> SNIFFING' : '<span class="dot"></span> IDLE';
    if (running) indicator.classList.add('active');
    else indicator.classList.remove('active');

    // Buttons
    document.getElementById('btn-start').classList.toggle('hidden', running);
    document.getElementById('btn-stop').classList.toggle('hidden', !running);
    document.getElementById('btn-scan').disabled = running;

    // Inputs
    document.getElementById('target-ip').disabled = running;
    document.getElementById('gateway-ip').disabled = running;
}

function startLogPolling() {
    if (logPollInterval) clearInterval(logPollInterval);
    logPollInterval = setInterval(fetchLogs, 100);
}

function stopLogPolling() {
    if (logPollInterval) clearInterval(logPollInterval);
    logPollInterval = null;
}

async function fetchLogs() {
    try {
        const response = await fetch('/api/logs');
        const logs = await response.json();
        currentLogs = logs;

        const consoleDiv = document.getElementById('log-console');

        // --- Smart DOM Update Strategy using IDs ---
        const existingIds = new Set();
        const existingElements = {};

        Array.from(consoleDiv.children).forEach(child => {
            if (child.dataset.id) {
                const id = parseInt(child.dataset.id);
                existingIds.add(id);
                existingElements[id] = child;
            }
        });

        const newLogIds = new Set(logs.map(l => l.id));

        // Remove old
        existingIds.forEach(id => {
            if (!newLogIds.has(id)) {
                if (existingElements[id]) existingElements[id].remove();
            }
        });

        // Append new or update
        logs.forEach((log, index) => {
            if (!existingIds.has(log.id)) {
                const entry = document.createElement('div');
                entry.className = `log-entry ${log.type}`;
                entry.dataset.id = log.id;

                // Content with Link Icon for HTTP/HTTPS
                let contentHtml = `<span class="time">[${log.time}]</span> <b>[${log.type}]</b> ${log.content}`;

                // Check if linkable
                if (log.type === 'HTTP' || (log.content && (log.content.startsWith('http') || log.type === 'DNS'))) {
                    let url = log.content;
                    if (log.type === 'DNS') url = 'http://' + log.content;
                    if (!url.startsWith('http')) url = 'http://' + url;

                    contentHtml += ` <a href="${url}" target="_blank" class="log-link" onclick="event.stopPropagation();" title="Open in new tab"><i class="fa-solid fa-arrow-up-right-from-square"></i></a>`;
                }

                entry.innerHTML = contentHtml;
                entry.onclick = () => showDetails(index);
                consoleDiv.appendChild(entry);
            } else {
                // Update click handler index
                existingElements[log.id].onclick = () => showDetails(index);
            }
        });

        // Auto-scroll logic (only if near bottom)
        const isNearBottom = consoleDiv.scrollHeight - consoleDiv.scrollTop - consoleDiv.clientHeight < 100;
        if (isNearBottom) {
            consoleDiv.scrollTop = consoleDiv.scrollHeight;
        }

        lastLogCount = logs.length;

    } catch (e) {
        console.error("Fetch logs error", e);
    }
}

function showDetails(index) {
    const log = currentLogs[index];
    if (!log || !log.details) return;

    const modal = document.getElementById('inspector-modal');
    const content = document.getElementById('modal-data');
    const modalContent = modal.querySelector('.modal-content');

    // Content
    content.textContent = log.details;

    // Determine URL
    let url = log.content;
    if (log.type === 'DNS') url = 'http://' + log.content;
    if (!url.startsWith('http')) url = 'http://' + url;

    // Footer with Button
    let footer = modalContent.querySelector('.modal-footer');
    if (!footer) {
        footer = document.createElement('div');
        footer.className = 'modal-footer';
        modalContent.appendChild(footer);
    }

    footer.innerHTML = `<a href="${url}" target="_blank" class="btn-sm primary" style="text-decoration:none; display:inline-block; padding:10px 20px; color:white;">Open URL <i class="fa-solid fa-external-link-alt"></i></a>`;

    modal.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('inspector-modal').classList.add('hidden');
}

let injectionEnabled = false;

async function toggleInjection() {
    const btn = document.getElementById('btn-inject');
    const code = document.getElementById('injection-code').value;

    injectionEnabled = !injectionEnabled;

    try {
        await fetch('/api/injection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: injectionEnabled, code: code })
        });

        if (injectionEnabled) {
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Injecting...';
            btn.style.background = 'var(--danger)';
            btn.style.color = '#fff';
            addSystemLog('Injection ENABLED (Port 80 -> Proxy)');
        } else {
            btn.innerHTML = '<i class="fa-solid fa-bug"></i> Enable Injection';
            btn.style.background = '';
            btn.style.color = '';
            addSystemLog('Injection DISABLED');
        }
    } catch (e) {
        console.error("Injection toggle failed", e);
        injectionEnabled = !injectionEnabled; // Revert
    }
}

let httpsBlockEnabled = false;

async function toggleHttpsBlock() {
    const btn = document.getElementById('btn-block-https');

    httpsBlockEnabled = !httpsBlockEnabled;

    try {
        await fetch('/api/block_https', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: httpsBlockEnabled })
        });

        if (httpsBlockEnabled) {
            btn.innerHTML = '<i class="fa-solid fa-lock"></i> HTTPS BLOCKED';
            btn.style.opacity = '1';
            addSystemLog('HTTPS Port 443 BLOCKED');
        } else {
            btn.innerHTML = '<i class="fa-solid fa-ban"></i> Block HTTPS';
            btn.style.opacity = '';
            addSystemLog('HTTPS Algo Allowed');
        }
    } catch (e) {
        console.error("Block toggle failed", e);
        httpsBlockEnabled = !httpsBlockEnabled;
    }
}

// Close on outside click
window.onclick = function (event) {
    const modal = document.getElementById('inspector-modal');
    if (event.target == modal) {
        closeModal();
    }
}

function addSystemLog(msg) {
    const consoleDiv = document.getElementById('log-console');
    const entry = document.createElement('div');
    entry.className = 'log-entry system';
    entry.style.color = '#fff';
    entry.innerHTML = `> ${msg}`;
    consoleDiv.appendChild(entry);
    consoleDiv.scrollTop = consoleDiv.scrollHeight;
}
