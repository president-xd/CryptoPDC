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
    await loadWordlists(); // Load wordlists
    await loadTasks();
    updateCharsetField();
    updateAttackModeFields(); // Initial state
    calculateKeyspace();
}

// Load available wordlists
async function loadWordlists() {
    try {
        const response = await fetch('/api/wordlists');
        const lists = await response.json();

        const select = document.getElementById('wordlist');
        select.innerHTML = ''; // Clear default
        lists.forEach(l => {
            const option = document.createElement('option');
            option.value = l.id;
            option.textContent = l.name;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load wordlists:', error);
    }
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

// Load existing tasks from server
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

// Setup Socket.IO listeners for real-time updates
function setupSocketListeners() {
    socket.on('connect', () => {
        console.log('Connected to server');
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
    });

    socket.on('connection_response', (data) => {
        console.log('Server response:', data);
    });

    // When a new task is created (from another client or broadcast)
    socket.on('task_created', (task) => {
        console.log('New task created:', task);
        // Only render if we don't already have this task displayed
        const existingCard = document.getElementById(`task-${task.task_id}`);
        if (!existingCard) {
            tasks[task.task_id] = task;
            renderTask(task);
            updateStats();
        }
    });

    // When a task is updated (progress, completion, etc.)
    socket.on('task_update', (task) => {
        console.log('Task updated:', task);
        const previousTask = tasks[task.task_id];
        tasks[task.task_id] = task;
        
        // Update existing card
        const existingCard = document.getElementById(`task-${task.task_id}`);
        if (existingCard) {
            updateTaskCard(task);
        }
        
        updateStats();
        
        // Show notification for completed tasks (only if status changed)
        if (task.status === 'found' && task.result && (!previousTask || previousTask.status !== 'found')) {
            showNotification(`✓ Password found: ${task.result}`, 'success');
        } else if (task.status === 'completed' && !task.result && (!previousTask || previousTask.status !== 'completed')) {
            showNotification('Task completed - password not found', 'warning');
        } else if (task.status === 'cancelled' && (!previousTask || previousTask.status !== 'cancelled')) {
            showNotification('Task cancelled', 'info');
        } else if (task.status === 'error' && (!previousTask || previousTask.status !== 'error')) {
            showNotification(`Task error: ${task.error || 'Unknown error'}`, 'error');
        }
    });

    // When a task is deleted
    socket.on('task_deleted', (data) => {
        console.log('Task deleted:', data.task_id);
        delete tasks[data.task_id];
        const card = document.getElementById(`task-${data.task_id}`);
        if (card) {
            card.remove();
        }
        updateStats();
    });
}

// Event Listeners
function setupEventListeners() {
    // Form submission
    document.getElementById('task-form').addEventListener('submit', handleSubmit);

    // Charset preset change
    document.getElementById('charset-preset').addEventListener('change', updateCharsetField);

    // Attack Mode change
    document.getElementById('attack-mode').addEventListener('change', updateAttackModeFields);

    // Algorithm change (for AES options)
    document.getElementById('algorithm').addEventListener('change', updateAlgorithmOptions);

    // Keyspace calculation
    ['charset-preset', 'charset-custom', 'max-length', 'include-separators'].forEach(id => {
        document.getElementById(id).addEventListener('input', calculateKeyspace);
    });
}

function updateAttackModeFields() {
    const mode = document.getElementById('attack-mode').value;
    const bruteOpts = document.getElementById('brute-force-options');
    const dictOpts = document.getElementById('dictionary-options');

    if (mode === 'dictionary') {
        bruteOpts.style.display = 'none';
        dictOpts.style.display = 'block';
    } else {
        bruteOpts.style.display = 'block';
        dictOpts.style.display = 'none';
    }
}

// Show/hide AES options based on selected algorithm
function updateAlgorithmOptions() {
    const algo = document.getElementById('algorithm').value;
    const aesOpts = document.getElementById('aes-options');
    
    // Show AES options for AES algorithms
    if (algo && algo.toLowerCase().startsWith('aes')) {
        aesOpts.style.display = 'block';
    } else {
        aesOpts.style.display = 'none';
    }
}

// Handle form submission
async function handleSubmit(e) {
    e.preventDefault();

    const charset = getCharset();
    const maxLen = parseInt(document.getElementById('max-length').value);
    const minLen = parseInt(document.getElementById('min-length').value);
    const attackMode = document.getElementById('attack-mode').value;
    const wordlist = document.getElementById('wordlist').value;

    // Calculate total keyspace for all lengths from min to max
    let totalKeyspace = 0;
    if (attackMode === 'brute') {
        for (let len = minLen; len <= maxLen; len++) {
            totalKeyspace += Math.pow(charset.length, len);
        }
    } else {
        totalKeyspace = 1000000; // Estimated
    }

    const formData = {
        algorithm: document.getElementById('algorithm').value,
        attack_mode: attackMode,
        target: document.getElementById('target').value.trim(),
        charset: charset,
        min_length: minLen,
        max_length: maxLen,
        wordlist: wordlist,
        keyspace_size: totalKeyspace
    };

    // Add AES key size if AES algorithm is selected
    const algo = formData.algorithm.toLowerCase();
    if (algo.startsWith('aes')) {
        formData.aes_key_size = parseInt(document.getElementById('aes-key-size').value);
    }

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
            const task = await response.json();
            // Add task to local state and render it
            tasks[task.task_id] = task;
            renderTask(task);
            updateStats();
            
            showNotification('Task submitted successfully!', 'success');
            document.getElementById('task-form').reset();
            updateCharsetField();
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
    let charset;
    if (preset === 'custom') {
        charset = document.getElementById('charset-custom').value;
    } else {
        charset = preset;
    }
    
    // Add separators if checkbox is checked
    const includeSeparators = document.getElementById('include-separators')?.checked;
    if (includeSeparators) {
        charset += ' _-';  // space, underscore, dash
    }
    
    return charset;
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
    
    // Check if card already exists - if so, update instead of creating
    const existingCard = document.getElementById(`task-${task.task_id}`);
    if (existingCard) {
        existingCard.innerHTML = getTaskHTML(task);
        return;
    }

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
                <span class="task-value">${(task.algorithm_display || task.algorithm).toUpperCase()}</span>
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
        ${task.error ? `
            <div class="task-error">
                <div class="error-label">Error</div>
                <div class="error-value">${escapeHtml(task.error)}</div>
            </div>
        ` : ''}
        ${task.status === 'queued' || task.status === 'running' || task.status === 'processing' ? `
            <div class="task-actions">
                <button class="btn btn-cancel" onclick="cancelTask('${task.task_id}')">
                    Cancel Task
                </button>
            </div>
        ` : ''}
    `;
}

// Cancel a task by ID
async function cancelTask(taskId) {
    if (!confirm('Are you sure you want to cancel this task?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/tasks/${taskId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showNotification('Task cancelled successfully', 'success');
        } else {
            const data = await response.json();
            showNotification(data.error || 'Failed to cancel task', 'error');
        }
    } catch (error) {
        console.error('Cancel error:', error);
        showNotification('Network error while cancelling task', 'error');
    }
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
    console.log(`[${type.toUpperCase()}] ${message}`);

    // Create toast notification
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-message">${escapeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    // Add to page or create container
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;';
        document.body.appendChild(container);
    }
    
    // Style the toast
    toast.style.cssText = `
        padding: 12px 20px;
        border-radius: 8px;
        color: white;
        display: flex;
        align-items: center;
        gap: 10px;
        animation: slideIn 0.3s ease;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#3b82f6'};
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}
