// Network Analyzer - Enhanced Dashboard JavaScript
const socket = io();

// State
let isCapturing = false;
let captureStartTime = null;
let lastPacketCount = 0;
let chartInstances = {};
let statsBuffer = [];
let allPackets = [];
let allAlerts = [];
let alertCounts = { critical: 0, warning: 0, info: 0 };
let ipStats = { sources: {}, destinations: {} };

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    loadInterfaces();
    updateStatusBadge('connected');

    // Load initial stats
    fetch('/api/stats')
        .then(r => r.json())
        .then(stats => updateStats(stats));

    // Add row animation styles
    addDynamicStyles();
});

// Add dynamic styles for animations
function addDynamicStyles() {
    const style = document.createElement('style');
    style.textContent = `
        .packet-row-enter {
            animation: rowSlideIn 0.3s ease forwards;
        }
        @keyframes rowSlideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
    `;
    document.head.appendChild(style);
}

// Chart Configuration
const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            position: 'bottom',
            labels: {
                padding: 15,
                font: { size: 11, weight: '500' },
                color: '#94a3b8',
                usePointStyle: true
            }
        }
    }
};

function initializeCharts() {
    // Protocol Distribution Chart (Doughnut)
    const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
    chartInstances.protocol = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#6366f1', '#8b5cf6', '#06b6d4', '#10b981',
                    '#f59e0b', '#ef4444', '#ec4899', '#14b8a6'
                ],
                borderColor: 'rgba(15, 23, 42, 0.8)',
                borderWidth: 3,
                hoverOffset: 10
            }]
        },
        options: {
            ...chartOptions,
            cutout: '65%',
            plugins: {
                ...chartOptions.plugins,
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.9)',
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                    padding: 12,
                    cornerRadius: 8
                }
            }
        }
    });

    // Packet Rate Chart (Line)
    const rateCtx = document.getElementById('rate-chart').getContext('2d');
    const gradient = rateCtx.createLinearGradient(0, 0, 0, 280);
    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.3)');
    gradient.addColorStop(1, 'rgba(99, 102, 241, 0)');

    chartInstances.rate = new Chart(rateCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets/sec',
                data: [],
                borderColor: '#6366f1',
                backgroundColor: gradient,
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 6,
                pointBackgroundColor: '#6366f1',
                pointBorderColor: '#fff',
                pointBorderWidth: 2
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(148, 163, 184, 0.1)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 10 }
                    }
                },
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 10 },
                        maxRotation: 0
                    }
                }
            }
        }
    });
}

// Load available network interfaces
async function loadInterfaces() {
    try {
        const response = await fetch('/api/interfaces');
        const interfaces = await response.json();

        const select = document.getElementById('interface-select');
        select.innerHTML = '';

        Object.entries(interfaces).forEach(([name, ip]) => {
            const option = document.createElement('option');
            option.value = name;
            option.textContent = `${name} (${ip})`;
            select.appendChild(option);
        });

        if (select.options.length > 0) {
            select.selectedIndex = 0;
        }
    } catch (error) {
        console.error('Error loading interfaces:', error);
        showToast('Failed to load network interfaces', 'error');
    }
}

// Start packet capture
async function startCapture() {
    const interfaceEl = document.getElementById('interface-select');
    const iface = interfaceEl.value;

    if (!iface) {
        showToast('Please select an interface', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/start-capture', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: iface })
        });

        const data = await response.json();

        if (response.ok && data.status !== 'already_running') {
            isCapturing = true;
            captureStartTime = Date.now();
            lastPacketCount = 0;
            document.getElementById('start-btn').disabled = true;
            document.getElementById('stop-btn').disabled = false;
            document.getElementById('interface-select').disabled = true;
            updateStatusBadge('capturing');
            showToast(`Started capturing on ${iface}`, 'success');
        } else if (data.status === 'already_running') {
            showToast('Capture is already running', 'info');
        }
    } catch (error) {
        console.error('Error starting capture:', error);
        showToast('Failed to start capture', 'error');
    }
}

// Stop packet capture
async function stopCapture() {
    try {
        const response = await fetch('/api/stop-capture', { method: 'POST' });
        if (response.ok) {
            isCapturing = false;
            document.getElementById('start-btn').disabled = false;
            document.getElementById('stop-btn').disabled = true;
            document.getElementById('interface-select').disabled = false;
            updateStatusBadge('stopped');
            showToast('Capture stopped', 'info');
        }
    } catch (error) {
        console.error('Error stopping capture:', error);
        showToast('Failed to stop capture', 'error');
    }
}

// Update status badge
function updateStatusBadge(status) {
    const badge = document.getElementById('status-badge');
    badge.className = 'badge status-badge';

    if (status === 'capturing') {
        badge.classList.add('capturing');
        badge.innerHTML = '<i class="fas fa-circle"></i> Capturing';
    } else if (status === 'connected') {
        badge.classList.add('connected');
        badge.innerHTML = '<i class="fas fa-circle"></i> Connected';
    } else {
        badge.innerHTML = '<i class="fas fa-circle"></i> Stopped';
    }
}

// Add packet to table
function addPacketToTable(packet) {
    const tbody = document.getElementById('packets-tbody');
    allPackets.push(packet);

    // Update packets count badge
    document.getElementById('packets-count-badge').textContent = allPackets.length;

    // Clear placeholder if exists
    const emptyRow = tbody.querySelector('.empty-row');
    if (emptyRow) {
        emptyRow.remove();
    }

    // Check if packet matches filters
    if (!matchesFilters(packet)) return;

    const row = document.createElement('tr');
    row.className = 'packet-row-enter';

    // Check for alerts
    const hasAlerts = packet.alerts && packet.alerts.length > 0;

    const time = new Date(packet.timestamp).toLocaleTimeString();
    const protocolClass = `protocol-${packet.protocol.toLowerCase()}`;
    const statusBadge = hasAlerts ?
        `<span class="status-alert">${packet.alerts[0]}</span>` :
        `<span class="status-normal">Normal</span>`;

    row.innerHTML = `
        <td><small>${time}</small></td>
        <td><code>${packet.source_ip}</code></td>
        <td><small>${packet.source_port}</small></td>
        <td><code>${packet.dest_ip}</code></td>
        <td><small>${packet.dest_port}</small></td>
        <td><span class="protocol-badge ${protocolClass}">${packet.protocol}</span></td>
        <td><small>${packet.packet_size} B</small></td>
        <td>${statusBadge}</td>
    `;

    tbody.insertBefore(row, tbody.firstChild);

    // Keep only last 100 rows
    while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }

    // Update filtered count
    updateFilteredCount();

    // Handle alerts
    if (hasAlerts) {
        handleAlert(packet);
    }

    // Track IP statistics
    ipStats.sources[packet.source_ip] = (ipStats.sources[packet.source_ip] || 0) + 1;
    ipStats.destinations[packet.dest_ip] = (ipStats.destinations[packet.dest_ip] || 0) + 1;

    // Update top IPs display every 10 packets
    if (allPackets.length % 10 === 0) {
        updateTopIPs();
    }
}

// Handle alert
function handleAlert(packet) {
    packet.alerts.forEach(alertType => {
        const alert = {
            type: alertType,
            severity: getSeverity(alertType),
            source_ip: packet.source_ip,
            dest_ip: packet.dest_ip,
            timestamp: packet.timestamp,
            protocol: packet.protocol
        };

        allAlerts.push(alert);
        alertCounts[alert.severity]++;

        // Update alert count displays
        document.getElementById('alert-count').textContent = allAlerts.length;
        document.getElementById('alerts-count-badge').textContent = allAlerts.length;
        document.getElementById('critical-alerts').textContent = alertCounts.critical;
        document.getElementById('warning-alerts').textContent = alertCounts.warning;
        document.getElementById('info-alerts').textContent = alertCounts.info;

        // Add to alerts list
        addAlertToList(alert);
    });
}

function getSeverity(alertType) {
    const critical = ['PORT_SCAN', 'INVALID_TCP_FLAGS'];
    const warning = ['TRAFFIC_SPIKE', 'NULL_TCP_FLAGS'];

    if (critical.includes(alertType)) return 'critical';
    if (warning.includes(alertType)) return 'warning';
    return 'info';
}

function addAlertToList(alert) {
    const list = document.getElementById('alerts-list');
    const emptyMsg = list.querySelector('.alert-empty');
    if (emptyMsg) emptyMsg.remove();

    const time = new Date(alert.timestamp).toLocaleTimeString();
    const item = document.createElement('div');
    item.className = `alert-item ${alert.severity}`;
    item.innerHTML = `
        <div>
            <strong>${alert.type}</strong>
            <small class="d-block text-muted">${alert.source_ip} → ${alert.dest_ip}</small>
        </div>
        <div class="text-end">
            <span class="badge bg-${alert.severity === 'critical' ? 'danger' : alert.severity === 'warning' ? 'warning' : 'info'}">${alert.severity.toUpperCase()}</span>
            <small class="d-block text-muted">${time}</small>
        </div>
    `;

    list.insertBefore(item, list.firstChild);
}

// Filter Functions
function matchesFilters(packet) {
    const protocol = document.getElementById('filter-protocol')?.value;
    const srcIp = document.getElementById('filter-src-ip')?.value;
    const dstIp = document.getElementById('filter-dst-ip')?.value;
    const port = document.getElementById('filter-port')?.value;

    if (protocol && packet.protocol !== protocol) return false;
    if (srcIp && !packet.source_ip.includes(srcIp)) return false;
    if (dstIp && !packet.dest_ip.includes(dstIp)) return false;
    if (port) {
        const portNum = parseInt(port);
        if (packet.source_port !== portNum && packet.dest_port !== portNum) return false;
    }

    return true;
}

function applyFilters() {
    const tbody = document.getElementById('packets-tbody');
    tbody.innerHTML = '';

    const filtered = allPackets.filter(matchesFilters);

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="8" class="text-center text-muted py-5">
                    <i class="fas fa-filter fa-3x mb-3 d-block opacity-50"></i>
                    No packets match the current filters
                </td>
            </tr>
        `;
    } else {
        // Show last 100 filtered packets
        filtered.slice(-100).reverse().forEach(packet => {
            const row = createPacketRow(packet);
            tbody.appendChild(row);
        });
    }

    updateFilteredCount();
}

function createPacketRow(packet) {
    const row = document.createElement('tr');
    const hasAlerts = packet.alerts && packet.alerts.length > 0;
    const time = new Date(packet.timestamp).toLocaleTimeString();
    const protocolClass = `protocol-${packet.protocol.toLowerCase()}`;
    const statusBadge = hasAlerts ?
        `<span class="status-alert">${packet.alerts[0]}</span>` :
        `<span class="status-normal">Normal</span>`;

    row.innerHTML = `
        <td><small>${time}</small></td>
        <td><code>${packet.source_ip}</code></td>
        <td><small>${packet.source_port}</small></td>
        <td><code>${packet.dest_ip}</code></td>
        <td><small>${packet.dest_port}</small></td>
        <td><span class="protocol-badge ${protocolClass}">${packet.protocol}</span></td>
        <td><small>${packet.packet_size} B</small></td>
        <td>${statusBadge}</td>
    `;
    return row;
}

function clearFilters() {
    document.getElementById('filter-protocol').value = '';
    document.getElementById('filter-src-ip').value = '';
    document.getElementById('filter-dst-ip').value = '';
    document.getElementById('filter-port').value = '';
    applyFilters();
    showToast('Filters cleared', 'info');
}

function updateFilteredCount() {
    const filtered = allPackets.filter(matchesFilters);
    document.getElementById('filtered-count').textContent = `Showing: ${Math.min(filtered.length, 100)} of ${allPackets.length}`;
}

// Update statistics display
function updateStats(stats) {
    const totalPackets = stats.total_packets || 0;
    const totalBytes = (stats.total_bytes / (1024 * 1024)).toFixed(2);
    const packetsPerSec = captureStartTime ?
        Math.round(totalPackets / ((Date.now() - captureStartTime) / 1000)) :
        0;

    // Animate counter updates
    animateCounter('total-packets', totalPackets);
    document.getElementById('total-bytes').textContent = `${totalBytes} MB`;
    document.getElementById('packets-per-sec').textContent = packetsPerSec;

    // Update protocol distribution chart
    if (stats.protocol_distribution) {
        const labels = Object.keys(stats.protocol_distribution);
        const data = Object.values(stats.protocol_distribution);

        chartInstances.protocol.data.labels = labels;
        chartInstances.protocol.data.datasets[0].data = data;
        chartInstances.protocol.update('none');
    }

    // Update packet rate chart
    statsBuffer.push({
        time: new Date().toLocaleTimeString().slice(0, 5),
        rate: packetsPerSec
    });

    if (statsBuffer.length > 20) {
        statsBuffer.shift();
    }

    chartInstances.rate.data.labels = statsBuffer.map(s => s.time);
    chartInstances.rate.data.datasets[0].data = statsBuffer.map(s => s.rate);
    chartInstances.rate.update('none');
}

function animateCounter(elementId, value) {
    const element = document.getElementById(elementId);
    const current = parseInt(element.textContent.replace(/,/g, '')) || 0;
    element.textContent = value.toLocaleString();
}

// Update Top IPs display
function updateTopIPs() {
    // Sort sources by count
    const topSources = Object.entries(ipStats.sources)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    // Sort destinations by count
    const topDests = Object.entries(ipStats.destinations)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    // Update Top Sources
    const sourcesEl = document.getElementById('top-sources');
    if (topSources.length > 0) {
        sourcesEl.innerHTML = topSources.map(([ip, count], i) => `
            <div class="top-item">
                <div class="d-flex align-items-center gap-2">
                    <span class="badge bg-primary">${i + 1}</span>
                    <code>${ip}</code>
                </div>
                <span class="badge bg-secondary">${count} pkts</span>
            </div>
        `).join('');
    }

    // Update Top Destinations
    const destsEl = document.getElementById('top-destinations');
    if (topDests.length > 0) {
        destsEl.innerHTML = topDests.map(([ip, count], i) => `
            <div class="top-item">
                <div class="d-flex align-items-center gap-2">
                    <span class="badge bg-success">${i + 1}</span>
                    <code>${ip}</code>
                </div>
                <span class="badge bg-secondary">${count} pkts</span>
            </div>
        `).join('');
    }
}

// Log functions
function loadLogFile(type) {
    // Highlight active log file
    document.querySelectorAll('.log-file-item').forEach(item => item.classList.remove('active'));
    event.currentTarget.classList.add('active');

    const viewer = document.getElementById('log-content');

    if (type === 'packets') {
        viewer.textContent = JSON.stringify(allPackets.slice(-50), null, 2);
    } else if (type === 'alerts') {
        viewer.textContent = JSON.stringify(allAlerts, null, 2);
    } else if (type === 'statistics') {
        fetch('/api/stats')
            .then(r => r.json())
            .then(stats => {
                viewer.textContent = JSON.stringify(stats, null, 2);
            });
    }
}

function refreshLogs() {
    const active = document.querySelector('.log-file-item.active');
    if (active) {
        active.click();
    }
    showToast('Logs refreshed', 'info');
}

function downloadLog() {
    const content = document.getElementById('log-content').textContent;
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `log_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Log downloaded', 'success');
}

// Export functions
function exportPackets() {
    exportToJSON();
}

function exportToJSON() {
    const data = { packets: allPackets, exportedAt: new Date().toISOString() };
    downloadData(JSON.stringify(data, null, 2), 'packets.json', 'application/json');
    showToast('Exported as JSON', 'success');
}

function exportToCSV() {
    const headers = ['Time', 'Source IP', 'Src Port', 'Dest IP', 'Dst Port', 'Protocol', 'Size', 'Alerts'];
    const rows = allPackets.map(p => [
        new Date(p.timestamp).toISOString(),
        p.source_ip,
        p.source_port,
        p.dest_ip,
        p.dest_port,
        p.protocol,
        p.packet_size,
        (p.alerts || []).join(';')
    ]);

    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    downloadData(csv, 'packets.csv', 'text/csv');
    showToast('Exported as CSV', 'success');
}

function exportToPDF() {
    showToast('PDF export coming soon', 'info');
}

function generateReport() {
    window.open('/api/report', '_blank');
    showToast('Generating report...', 'info');
}

function downloadData(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

function clearAlerts() {
    allAlerts = [];
    alertCounts = { critical: 0, warning: 0, info: 0 };
    document.getElementById('alert-count').textContent = '0';
    document.getElementById('alerts-count-badge').textContent = '0';
    document.getElementById('critical-alerts').textContent = '0';
    document.getElementById('warning-alerts').textContent = '0';
    document.getElementById('info-alerts').textContent = '0';
    document.getElementById('alerts-list').innerHTML = `
        <div class="alert-empty text-center text-muted py-5">
            <i class="fas fa-shield-check fa-3x mb-3 d-block opacity-50"></i>
            No alerts detected. Your network is secure.
        </div>
    `;
    showToast('Alerts cleared', 'info');
}

// Toast notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast show`;
    toast.setAttribute('role', 'alert');

    const iconMap = {
        success: 'fa-check-circle text-success',
        error: 'fa-times-circle text-danger',
        warning: 'fa-exclamation-triangle text-warning',
        info: 'fa-info-circle text-info'
    };

    toast.innerHTML = `
        <div class="toast-header">
            <i class="fas ${iconMap[type]} me-2"></i>
            <strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
        </div>
        <div class="toast-body">${message}</div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// Socket.io event handlers
socket.on('connect', () => {
    console.log('Connected to server');
    updateStatusBadge('connected');
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
    updateStatusBadge('stopped');
    isCapturing = false;
});

socket.on('status', (data) => {
    console.log('Status:', data);
    if (data.status === 'capturing') {
        updateStatusBadge('capturing');
    } else if (data.status === 'stopped') {
        updateStatusBadge('stopped');
        isCapturing = false;
        document.getElementById('start-btn').disabled = false;
        document.getElementById('stop-btn').disabled = true;
        document.getElementById('interface-select').disabled = false;
    }
});

socket.on('packet_update', (packet) => {
    addPacketToTable(packet);
});

socket.on('stats_update', (stats) => {
    updateStats(stats);
});

socket.on('error', (data) => {
    showToast(`Error: ${data.message}`, 'error');
    isCapturing = false;
    document.getElementById('start-btn').disabled = false;
    document.getElementById('stop-btn').disabled = true;
});
