// CryptoPDC Frontend JavaScript
const socket = io();
let algorithms = [];
let tasks = {};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
    setupSocketListeners();
});

async function initializeApp() {
    await loadAlgorithms();
    await loadTasks();
    updateCharsetField();
    calculateKeyspace();
}

// Load available algorithms
async function loadAlgorithms() {
    try {
        const response = await fetch('/api/algorithms');
        algorithms = await response.json();

        const select = document.getElementById('algorithm');
        algorithms.forEach(algo => {
            const option = document.createElement('option');
            option.value = algo.id;
            option.textContent = `${algo.name} (${algo.type}, ${algo.output_size})`;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load algorithms:', error);
    }
}

// Load existing tasks
async function loadTasks() {
    try {
        const response = await fetch('/api/tasks');
        const taskList = await response.json();

        taskList.forEach(task => {
            tasks[task.task_id] = task;
            renderTask(task);
        });

        updateStats();
    } catch (error) {
        console.error('Failed to load tasks:', error);
    }
}

// Event Listeners
function setupEventListeners() {
    // Form submission
    document.getElementById('task-form').addEventListener('submit', handleSubmit);

    // Charset preset change
    document.getElementById('charset-preset').addEventListener('change', updateCharsetField);

    // Keyspace calculation
    ['charset-preset', 'charset-custom', 'max-length'].forEach(id => {
        document.getElementById(id).addEventListener('input', calculateKeyspace);
    });
}

// Socket.IO Listeners
function setupSocketListeners() {
    socket.on('connect', () => {
        updateConnectionStatus(true);
    });

    socket.on('disconnect', () => {
        updateConnectionStatus(false);
    });

    socket.on('task_created', (task) => {
        tasks[task.task_id] = task;
        renderTask(task);
        updateStats();
    });

    socket.on('task_update', (task) => {
        tasks[task.task_id] = task;
        updateTaskCard(task);
        updateStats();

        // Show notification for completed tasks
        if (task.status === 'found') {
            showNotification(`Task completed! Found: ${task.result}`, 'success');
        }
    });
}

// Update connection status
function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    const dotEl = document.querySelector('.status-dot');

    if (connected) {
        statusEl.textContent = 'Connected';
        dotEl.style.background = 'var(--success)';
    } else {
        statusEl.textContent = 'Disconnected';
        dotEl.style.background = 'var(--error)';
    }
}

// Handle form submission
async function handleSubmit(e) {
    e.preventDefault();

    const charset = getCharset();
    const maxLen = parseInt(document.getElementById('max-length').value);
    const minLen = parseInt(document.getElementById('min-length').value);

    // Calculate total keyspace for all lengths from min to max
    let totalKeyspace = 0;
    for (let len = minLen; len <= maxLen; len++) {
        totalKeyspace += Math.pow(charset.length, len);
    }

    const formData = {
        algorithm: document.getElementById('algorithm').value,
        attack_mode: document.getElementById('attack-mode').value,
        target: document.getElementById('target').value.trim(),
        charset: charset,
        min_length: minLen,
        max_length: maxLen,
        keyspace_size: totalKeyspace
    };

    // Validation
    if (!formData.algorithm || !formData.target) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }

    try {
        const response = await fetch('/api/tasks', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        if (response.ok) {
            showNotification('Task submitted successfully!', 'success');
            document.getElementById('task-form').reset();
            calculateKeyspace();
        } else {
            showNotification('Failed to submit task', 'error');
        }
    } catch (error) {
        console.error('Submit error:', error);
        showNotification('Network error', 'error');
    }
}

// Get current charset
function getCharset() {
    const preset = document.getElementById('charset-preset').value;
    if (preset === 'custom') {
        return document.getElementById('charset-custom').value;
    }
    return preset;
}

// Update charset field based on preset
function updateCharsetField() {
    const preset = document.getElementById('charset-preset').value;
    const customField = document.getElementById('charset-custom');

    if (preset === 'custom') {
        customField.disabled = false;
        customField.focus();
    } else {
        customField.disabled = true;
        customField.value = '';
    }
}

// Calculate keyspace size
function calculateKeyspace() {
    const charset = getCharset();
    const length = parseInt(document.getElementById('max-length').value) || 0;

    if (charset && length > 0) {
        const size = Math.pow(charset.length, length);
        const formatted = formatNumber(size);
        document.getElementById('keyspace-size').textContent =
            `Keyspace: ${formatted} combinations (${charset.length}^${length})`;
    } else {
        document.getElementById('keyspace-size').textContent = 'Keyspace: Calculating...';
    }
}

// Render task card
function renderTask(task) {
    const container = document.getElementById('tasks-container');

    // Remove empty state
    const emptyState = container.querySelector('.empty-state');
    if (emptyState) {
        emptyState.remove();
    }

    const card = document.createElement('div');
    card.className = 'task-card';
    card.id = `task-${task.task_id}`;
    card.innerHTML = getTaskHTML(task);

    container.insertBefore(card, container.firstChild);
}

// Update existing task card
function updateTaskCard(task) {
    const card = document.getElementById(`task-${task.task_id}`);
    if (card) {
        card.innerHTML = getTaskHTML(task);
    }
}

// Generate task HTML
function getTaskHTML(task) {
    const statusClass = `status-${task.status}`;
    const statusText = task.status.toUpperCase();
    const backend = task.backend || 'CPU';
    const backendClass = backend === 'GPU' ? 'backend-gpu' : 'backend-cpu';
    const attackMode = task.attack_mode || 'brute';

    let resultHTML = '';
    if (task.result) {
        const iterations = task.iterations || task.keyspace?.total || 0;
        resultHTML = `
            <div class="task-result">
                <div class="result-label">Recovered Plaintext</div>
                <div class="result-value">${escapeHtml(task.result)}</div>
                ${task.duration ? `<div class="help-text">Found in ${task.duration.toFixed(2)}s (${formatNumber(iterations)} iterations)</div>` : ''}
            </div>
        `;
    }

    const keyspaceTotal = task.keyspace?.total || 0;
    const progress = task.progress || 0;

    return `
        <div class="task-header">
            <div class="task-id">${task.task_id.substring(0, 8)}</div>
            <div class="task-badges">
                <span class="backend-badge ${backendClass}">${backend}</span>
                <span class="task-status ${statusClass}">${statusText}</span>
            </div>
        </div>
        <div class="task-info">
            <div class="task-row">
                <span class="task-label">Algorithm:</span>
                <span class="task-value">${task.algorithm.toUpperCase()}</span>
            </div>
            <div class="task-row">
                <span class="task-label">Attack Mode:</span>
                <span class="task-value">${attackMode.charAt(0).toUpperCase() + attackMode.slice(1)}</span>
            </div>
            <div class="task-row">
                <span class="task-label">Target:</span>
                <span class="task-value">${task.target.substring(0, 32)}${task.target.length > 32 ? '...' : ''}</span>
            </div>
            <div class="task-row">
                <span class="task-label">Keyspace:</span>
                <span class="task-value">${formatNumber(keyspaceTotal)} combinations</span>
            </div>
            <div class="task-row">
                <span class="task-label">Worker:</span>
                <span class="task-value">${task.worker_id || 'Pending'}</span>
            </div>
            <div class="task-row">
                <span class="task-label">Submitted:</span>
                <span class="task-value">${formatTime(task.submitted_at)}</span>
            </div>
        </div>
        ${resultHTML}
    `;
}

// Update statistics
function updateStats() {
    const taskList = Object.values(tasks);
    const total = taskList.length;
    const completed = taskList.filter(t => t.status === 'found').length;
    const successRate = total > 0 ? ((completed / total) * 100).toFixed(0) : 0;

    document.getElementById('total-tasks').textContent = total;
    document.getElementById('completed-tasks').textContent = completed;
    document.getElementById('success-rate').textContent = `${successRate}%`;
    document.getElementById('task-count').textContent = total;
}

// Utility functions
function formatNumber(num) {
    if (num >= 1e12) return (num / 1e12).toFixed(2) + 'T';
    if (num >= 1e9) return (num / 1e9).toFixed(2) + 'B';
    if (num >= 1e6) return (num / 1e6).toFixed(2) + 'M';
    if (num >= 1e3) return (num / 1e3).toFixed(2) + 'K';
    return num.toString();
}

function formatTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleTimeString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showNotification(message, type = 'info') {
    // Simple console notification for now
    console.log(`[${type.toUpperCase()}] ${message}`);

    // Could implement toast notifications here
    alert(message);
}
