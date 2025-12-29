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
    await loadWordlists();
    await loadTasks();
    updateCharsetField();
}

// Algorithm information for user guidance
const algorithmInfo = {
    'md5': {
        type: 'hash',
        name: 'MD5',
        description: 'You have an MD5 hash and want to find the original password/text that produced it.',
        targetLabel: 'MD5 Hash to Crack',
        targetPlaceholder: 'e.g., 5d41402abc4b2a76b9719d911017c592',
        targetExample: 'Example: "hello" produces 5d41402abc4b2a76b9719d911017c592',
        hashLength: 32,
        gpuSupported: true
    },
    'sha1': {
        type: 'hash',
        name: 'SHA-1',
        description: 'You have a SHA-1 hash and want to find the original password/text that produced it.',
        targetLabel: 'SHA-1 Hash to Crack',
        targetPlaceholder: 'e.g., aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
        targetExample: 'Example: "hello" produces aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
        hashLength: 40,
        gpuSupported: true
    },
    'sha256': {
        type: 'hash',
        name: 'SHA-256',
        description: 'You have a SHA-256 hash and want to find the original password/text that produced it.',
        targetLabel: 'SHA-256 Hash to Crack',
        targetPlaceholder: 'e.g., 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
        targetExample: 'Example: "hello" produces 2cf24dba5fb0a30e26e83b2ac5b9e29e...',
        hashLength: 64,
        gpuSupported: true
    },
    'sha512': {
        type: 'hash',
        name: 'SHA-512',
        description: 'You have a SHA-512 hash and want to find the original password/text that produced it.',
        targetLabel: 'SHA-512 Hash to Crack',
        targetPlaceholder: 'Enter 128-character hex hash',
        targetExample: 'Example: "hello" produces 9b71d224bd62f3785d96d46ad3ea3d73...',
        hashLength: 128,
        gpuSupported: true
    },
    'aes': {
        type: 'symmetric',
        name: 'AES',
        description: 'Known-Plaintext Attack: You have BOTH the original data (plaintext) AND the encrypted result (ciphertext), and want to find the encryption KEY that was used.',
        targetLabel: 'Ciphertext',
        targetPlaceholder: '32 hex characters (16 bytes)',
        hashLength: 32,
        gpuSupported: true,
        keySizes: [128, 192, 256]
    },
    'des': {
        type: 'symmetric',
        name: 'DES',
        description: 'DES encryption (legacy, 56-bit effective key). Not recommended for security.',
        targetLabel: 'Ciphertext',
        targetPlaceholder: '16 hex characters (8 bytes)',
        hashLength: 16,
        gpuSupported: false,
        keySizes: [64]
    },
    '3des': {
        type: 'symmetric',
        name: '3DES',
        description: 'Triple DES encryption. Uses 3 DES operations with 2 or 3 keys.',
        targetLabel: 'Ciphertext',
        targetPlaceholder: '16 hex characters (8 bytes)',
        hashLength: 16,
        gpuSupported: false,
        keySizes: [128, 192]
    }
};

// Load available wordlists
async function loadWordlists() {
    try {
        const response = await fetch('/api/wordlists');
        const lists = await response.json();

        const select = document.getElementById('wordlist');
        select.innerHTML = '';
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
        updateConnectionStatus(true);
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
        updateConnectionStatus(false);
    });

    socket.on('connection_response', (data) => {
        console.log('Server response:', data);
    });

    socket.on('task_created', (task) => {
        console.log('New task created:', task);
        const existingCard = document.getElementById(`task-${task.task_id}`);
        if (!existingCard) {
            tasks[task.task_id] = task;
            renderTask(task);
            updateStats();
        }
    });

    socket.on('task_update', (task) => {
        console.log('Task updated:', task);
        const previousTask = tasks[task.task_id];
        tasks[task.task_id] = task;
        
        const existingCard = document.getElementById(`task-${task.task_id}`);
        if (existingCard) {
            updateTaskCard(task);
        }
        
        updateStats();
        
        if (task.status === 'found' && task.result && (!previousTask || previousTask.status !== 'found')) {
            showNotification(`Password found: ${task.result}`, 'success');
        } else if (task.status === 'completed' && !task.result && (!previousTask || previousTask.status !== 'completed')) {
            showNotification('Task completed - password not found', 'warning');
        } else if (task.status === 'cancelled' && (!previousTask || previousTask.status !== 'cancelled')) {
            showNotification('Task cancelled', 'info');
        } else if (task.status === 'error' && (!previousTask || previousTask.status !== 'error')) {
            showNotification(`Task error: ${task.error || 'Unknown error'}`, 'error');
        }
    });

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

function updateConnectionStatus(connected) {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.getElementById('connection-status');
    if (connected) {
        statusDot.style.background = '#10b981';
        statusText.textContent = 'Connected';
    } else {
        statusDot.style.background = '#ef4444';
        statusText.textContent = 'Disconnected';
    }
}

// Event Listeners
function setupEventListeners() {
    const form = document.getElementById('task-form');
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        e.stopPropagation();
        handleSubmit(e);
        return false;
    });
    document.getElementById('charset-preset').addEventListener('change', updateCharsetField);
    document.getElementById('attack-mode').addEventListener('change', updateAttackModeFields);
    document.getElementById('algorithm').addEventListener('change', updateAlgorithmOptions);

    // AES specific listeners
    const cipherMode = document.getElementById('cipher-mode');
    if (cipherMode) {
        cipherMode.addEventListener('change', updateAESOptions);
    }
    
    const aesKeySize = document.getElementById('aes-key-size');
    if (aesKeySize) {
        aesKeySize.addEventListener('change', updateAESOptions);
    }

    // Knowledge radio buttons
    document.querySelectorAll('input[name="key-knowledge"]').forEach(radio => {
        radio.addEventListener('change', updateAESOptions);
    });
    document.querySelectorAll('input[name="iv-knowledge"]').forEach(radio => {
        radio.addEventListener('change', updateAESOptions);
    });
    document.querySelectorAll('input[name="plaintext-knowledge"]').forEach(radio => {
        radio.addEventListener('change', updateAESOptions);
    });

    // Keyspace calculation
    ['charset-preset', 'charset-custom', 'min-length', 'max-length', 'include-separators'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', calculateKeyspace);
    });
}

function updateAttackModeFields() {
    const mode = document.getElementById('attack-mode').value;
    const bruteOpts = document.getElementById('brute-force-options');
    const dictOpts = document.getElementById('dictionary-options');
    const keyspaceInfo = document.getElementById('keyspace-info');

    if (mode === 'dictionary') {
        bruteOpts.style.display = 'none';
        dictOpts.style.display = 'block';
        if (keyspaceInfo) keyspaceInfo.style.display = 'none';
    } else {
        bruteOpts.style.display = 'block';
        dictOpts.style.display = 'none';
        if (keyspaceInfo) {
            keyspaceInfo.style.display = 'block';
            calculateKeyspace();
        }
    }
}

// Update AES-specific options based on user selections
function updateAESOptions() {
    const cipherMode = document.getElementById('cipher-mode')?.value;
    const keySize = document.getElementById('aes-key-size')?.value;
    const keyKnowledge = document.querySelector('input[name="key-knowledge"]:checked')?.value;
    const ivKnowledge = document.querySelector('input[name="iv-knowledge"]:checked')?.value;
    const plaintextKnowledge = document.querySelector('input[name="plaintext-knowledge"]:checked')?.value;
    
    // Show/hide IV section based on cipher mode
    const ivKnowledgeSection = document.getElementById('iv-knowledge-section');
    const ivInputSection = document.getElementById('iv-input-section');
    const cipherModeHelp = document.getElementById('cipher-mode-help');
    
    if (cipherMode === 'ecb') {
        // ECB doesn't need IV
        if (ivKnowledgeSection) ivKnowledgeSection.style.display = 'none';
        if (ivInputSection) ivInputSection.style.display = 'none';
        if (cipherModeHelp) cipherModeHelp.textContent = 'ECB mode: No IV needed, but less secure';
    } else {
        // CBC and other modes need IV
        if (ivKnowledgeSection) ivKnowledgeSection.style.display = 'block';
        if (cipherModeHelp) cipherModeHelp.textContent = 'CBC mode: Requires IV for proper decryption';
        
        // Show IV input if user has the IV
        if (ivKnowledge === 'known') {
            if (ivInputSection) ivInputSection.style.display = 'block';
        } else {
            if (ivInputSection) ivInputSection.style.display = 'none';
        }
    }
    
    // Show/hide key input based on key knowledge
    const keyInputSection = document.getElementById('key-input-section');
    const keyLengthHelp = document.getElementById('key-length-help');
    if (keyKnowledge === 'known') {
        if (keyInputSection) keyInputSection.style.display = 'block';
        // Update key length help based on selected key size
        const keyBytes = parseInt(keySize) / 8;
        const keyHexChars = keyBytes * 2;
        if (keyLengthHelp) keyLengthHelp.textContent = `${keyBytes} bytes (${keyHexChars} hex chars) for AES-${keySize}`;
    } else {
        if (keyInputSection) keyInputSection.style.display = 'none';
    }
    
    // Show/hide plaintext input
    const plaintextInputSection = document.getElementById('plaintext-input-section');
    if (plaintextKnowledge === 'known') {
        if (plaintextInputSection) plaintextInputSection.style.display = 'block';
    } else {
        if (plaintextInputSection) plaintextInputSection.style.display = 'none';
    }
    
    // Update attack strategy info
    updateAttackStrategy(cipherMode, keyKnowledge, ivKnowledge, plaintextKnowledge);
}

// Update the attack strategy information panel
function updateAttackStrategy(cipherMode, keyKnowledge, ivKnowledge, plaintextKnowledge) {
    const strategyText = document.getElementById('attack-strategy-text');
    if (!strategyText) return;
    
    let strategy = '';
    let attackType = '';
    let possible = true;
    
    if (keyKnowledge === 'known') {
        // User has the key - this is decrypt/verify mode
        if (cipherMode === 'cbc' && ivKnowledge !== 'known') {
            strategy = 'You have the key. Attack will brute-force the IV to decrypt the ciphertext.';
            attackType = 'IV Recovery';
        } else {
            strategy = 'You have the key and IV. This will decrypt the ciphertext directly (no cracking needed).';
            attackType = 'Direct Decryption';
        }
    } else {
        // User doesn't have the key - need to crack it
        if (plaintextKnowledge === 'known') {
            // Known-Plaintext Attack
            strategy = 'Known-Plaintext Attack (KPA): Using known plaintext-ciphertext pair to find the key.';
            attackType = 'Key Recovery (KPA)';
            
            if (cipherMode === 'cbc' && ivKnowledge !== 'known') {
                strategy += ' Note: Without the IV, CBC mode makes this significantly harder.';
            }
        } else {
            // No plaintext - ciphertext-only attack
            if (cipherMode === 'ecb') {
                strategy = 'Ciphertext-Only Attack: Will try to identify patterns in ECB mode. Very difficult without known plaintext.';
                attackType = 'Pattern Analysis';
            } else {
                strategy = 'Ciphertext-Only Attack: Very difficult without known plaintext. Consider if you have any partial plaintext knowledge.';
                attackType = 'Ciphertext-Only';
                possible = false;
            }
        }
    }
    
    strategyText.textContent = strategy;
    
    // Update submit button text
    const submitBtn = document.getElementById('submit-btn');
    if (submitBtn) {
        if (!possible) {
            submitBtn.disabled = true;
            submitBtn.textContent = 'More Information Required';
        } else {
            submitBtn.disabled = false;
            submitBtn.textContent = `Start ${attackType}`;
        }
    }
}

// Main function to update UI based on selected algorithm
function updateAlgorithmOptions() {
    const algo = document.getElementById('algorithm').value;
    const info = algorithmInfo[algo];
    
    // UI Elements
    const algorithmInfoPanel = document.getElementById('algorithm-info');
    const hashTargetSection = document.getElementById('hash-target-section');
    const aesTargetSection = document.getElementById('aes-target-section');
    const attackModeSection = document.getElementById('attack-mode-section');
    const backendOptions = document.getElementById('backend-options');
    const backendHelp = document.getElementById('backend-help');
    const submitBtn = document.getElementById('submit-btn');
    const keyspaceInfo = document.getElementById('keyspace-info');
    
    // Hide everything first
    if (algorithmInfoPanel) algorithmInfoPanel.style.display = 'none';
    if (hashTargetSection) hashTargetSection.style.display = 'none';
    if (aesTargetSection) aesTargetSection.style.display = 'none';
    if (attackModeSection) attackModeSection.style.display = 'none';
    if (backendOptions) backendOptions.style.display = 'none';
    if (keyspaceInfo) keyspaceInfo.style.display = 'none';
    document.getElementById('brute-force-options').style.display = 'none';
    document.getElementById('dictionary-options').style.display = 'none';
    
    if (!algo || !info) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Select an Algorithm';
        return;
    }
    
    // Show algorithm info panel
    if (algorithmInfoPanel) {
        algorithmInfoPanel.style.display = 'block';
        document.getElementById('algorithm-info-title').textContent = `${info.name} - What you need`;
        document.getElementById('algorithm-info-text').textContent = info.description;
    }
    
    // Show appropriate sections based on algorithm type
    if (info.type === 'hash') {
        // Hash algorithms
        if (hashTargetSection) hashTargetSection.style.display = 'block';
        if (attackModeSection) attackModeSection.style.display = 'block';
        
        const targetLabel = document.querySelector('label[for="target"]');
        if (targetLabel) targetLabel.textContent = info.targetLabel;
        document.getElementById('target').placeholder = info.targetPlaceholder;
        const targetExample = document.getElementById('target-example');
        if (targetExample) targetExample.textContent = info.targetExample;
        
        const attackModeHelp = document.getElementById('attack-mode-help');
        if (attackModeHelp) attackModeHelp.textContent = 
            'Brute Force: Try all character combinations | Dictionary: Use common passwords';
        
        updateAttackModeFields();
        
        submitBtn.disabled = false;
        submitBtn.textContent = `Start ${info.name} Attack`;
        
    } else if (info.type === 'symmetric') {
        // Symmetric encryption (AES, DES, etc.)
        if (aesTargetSection) aesTargetSection.style.display = 'block';
        if (attackModeSection) attackModeSection.style.display = 'block';
        
        const attackModeHelp = document.getElementById('attack-mode-help');
        if (attackModeHelp) attackModeHelp.textContent = 
            'Brute Force: Try key combinations | Dictionary: Use common keys/passwords';
        
        // Initialize AES-specific options
        updateAESOptions();
        updateAttackModeFields();
    }
    
    // Show backend options
    if (backendOptions) backendOptions.style.display = 'block';
    
    // Update backend help text
    if (backendHelp) {
        if (info.gpuSupported) {
            backendHelp.textContent = `GPU acceleration available for ${info.name}`;
            backendHelp.style.color = '#10b981';
        } else {
            backendHelp.textContent = `GPU not available for ${info.name} - will use CPU`;
            backendHelp.style.color = '#f59e0b';
        }
    }
}

// Handle form submission
async function handleSubmit(e) {
    alert('Button clicked! handleSubmit called');
    console.log('=== FORM SUBMIT CALLED ===');
    if (e) {
        e.preventDefault();
        e.stopPropagation();
    }

    try {
        const algo = document.getElementById('algorithm').value;
        const info = algorithmInfo[algo];
        
        console.log('Algorithm:', algo);
        console.log('Info:', info);
        
        if (!algo || !info) {
            showNotification('Please select an algorithm', 'error');
            return false;
        }

        const charset = getCharset();
        const maxLen = parseInt(document.getElementById('max-length').value);
        const minLen = parseInt(document.getElementById('min-length').value);
        const attackMode = document.getElementById('attack-mode').value;
        const wordlist = document.getElementById('wordlist').value;
        const backendSelection = document.getElementById('backend').value;
        
        console.log('Form data:', { charset, maxLen, minLen, attackMode, wordlist, backendSelection });

        // Calculate total keyspace
        let totalKeyspace = 0;
        if (attackMode === 'brute') {
            for (let len = minLen; len <= maxLen; len++) {
                totalKeyspace += Math.pow(charset.length, len);
            }
        } else {
            totalKeyspace = 1000000;
        }

        // Build form data
        const formData = {
            algorithm: algo,
            attack_mode: attackMode,
            charset: charset,
            min_length: minLen,
            max_length: maxLen,
            wordlist: wordlist,
            keyspace_size: totalKeyspace,
            backend: backendSelection
        };

        // Handle based on algorithm type
        if (info.type === 'hash') {
            const target = document.getElementById('target').value.trim();
            formData.target = target;
            
            if (target.length !== info.hashLength) {
                showNotification(`Invalid ${info.name} hash length. Expected ${info.hashLength} characters, got ${target.length}`, 'error');
                return false;
            }
            
            if (!/^[a-fA-F0-9]+$/.test(target)) {
                showNotification('Hash must contain only hexadecimal characters (0-9, a-f)', 'error');
                return false;
            }
            
        } else if (info.type === 'symmetric') {
            // Symmetric encryption
            const keySize = parseInt(document.getElementById('aes-key-size').value);
            const cipherMode = document.getElementById('cipher-mode').value;
            const padding = document.getElementById('padding').value;
            const ciphertext = document.getElementById('aes-ciphertext').value.trim();
            
            const keyKnowledge = document.querySelector('input[name="key-knowledge"]:checked')?.value;
            const ivKnowledge = document.querySelector('input[name="iv-knowledge"]:checked')?.value;
            const plaintextKnowledge = document.querySelector('input[name="plaintext-knowledge"]:checked')?.value;
            
            // Validate ciphertext
            if (!ciphertext || ciphertext.length !== 32) {
                showNotification('Ciphertext must be 32 hex characters (16 bytes)', 'error');
                return false;
            }
            
            if (!/^[a-fA-F0-9]+$/.test(ciphertext)) {
                showNotification('Ciphertext must contain only hexadecimal characters', 'error');
                return false;
            }
            
            formData.target = ciphertext;
            formData.aes_key_size = keySize;
            formData.cipher_mode = cipherMode;
            formData.padding = padding;
            formData.key_knowledge = keyKnowledge;
            formData.iv_knowledge = ivKnowledge;
            formData.plaintext_knowledge = plaintextKnowledge;
            
            // Add known values if user has them
            if (keyKnowledge === 'known') {
                const key = document.getElementById('aes-key').value.trim();
                const expectedKeyLen = (keySize / 8) * 2; // hex chars
                if (!key || key.length !== expectedKeyLen) {
                    showNotification(`Key must be ${expectedKeyLen} hex characters for AES-${keySize}`, 'error');
                    return false;
                }
                if (!/^[a-fA-F0-9]+$/.test(key)) {
                    showNotification('Key must contain only hexadecimal characters', 'error');
                    return false;
                }
                formData.aes_key = key;
            }
            
            if (cipherMode !== 'ecb' && ivKnowledge === 'known') {
                const iv = document.getElementById('aes-iv').value.trim();
                if (!iv || iv.length !== 32) {
                    showNotification('IV must be 32 hex characters (16 bytes)', 'error');
                    return false;
                }
                if (!/^[a-fA-F0-9]+$/.test(iv)) {
                    showNotification('IV must contain only hexadecimal characters', 'error');
                    return false;
                }
                formData.aes_iv = iv;
            }
            
            if (plaintextKnowledge === 'known') {
                const plaintext = document.getElementById('aes-plaintext').value.trim();
                if (!plaintext || plaintext.length !== 32) {
                    showNotification('Plaintext must be 32 hex characters (16 bytes)', 'error');
                    return false;
                }
                if (!/^[a-fA-F0-9]+$/.test(plaintext)) {
                    showNotification('Plaintext must contain only hexadecimal characters', 'error');
                    return false;
                }
                formData.aes_plaintext = plaintext;
            }
        }

        // Final validation
        if (!formData.target) {
            showNotification('Please fill in all required fields', 'error');
            return false;
        }

        console.log('Submitting formData:', formData);
        console.log('Making fetch request to /api/tasks...');
        
        const response = await fetch('/api/tasks', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        console.log('Response status:', response.status);

        if (response.ok) {
            const task = await response.json();
            console.log('Task created:', task);
            tasks[task.task_id] = task;
            renderTask(task);
            updateStats();
            
            showNotification('Task submitted successfully!', 'success');
            const savedAlgo = document.getElementById('algorithm').value;
            document.getElementById('task-form').reset();
            document.getElementById('algorithm').value = savedAlgo;
            updateAlgorithmOptions();
        } else {
            const errData = await response.json().catch(() => ({}));
            showNotification(errData.error || 'Failed to submit task', 'error');
        }
    } catch (error) {
        console.error('Submit error:', error);
        showNotification('Error: ' + error.message, 'error');
    }
    return false;
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
    
    const includeSeparators = document.getElementById('include-separators')?.checked;
    if (includeSeparators) {
        charset += ' _-';
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
    const minLen = parseInt(document.getElementById('min-length').value) || 1;
    const maxLen = parseInt(document.getElementById('max-length').value) || 6;

    if (charset && maxLen > 0) {
        let total = 0;
        for (let len = minLen; len <= maxLen; len++) {
            total += Math.pow(charset.length, len);
        }
        const formatted = formatNumber(total);
        document.getElementById('keyspace-size').textContent =
            `Keyspace: ${formatted} combinations (lengths ${minLen}-${maxLen})`;
    } else {
        document.getElementById('keyspace-size').textContent = 'Keyspace: Calculating...';
    }
}

// Render task card
function renderTask(task) {
    const container = document.getElementById('tasks-container');
    
    const existingCard = document.getElementById(`task-${task.task_id}`);
    if (existingCard) {
        existingCard.innerHTML = getTaskHTML(task);
        return;
    }

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
                <div class="result-label">Recovered Value</div>
                <div class="result-value">${escapeHtml(task.result)}</div>
                ${task.duration ? `<div class="help-text">Found in ${task.duration.toFixed(2)}s (${formatNumber(iterations)} iterations)</div>` : ''}
            </div>
        `;
    }

    const keyspaceTotal = task.keyspace?.total || 0;
    
    // Additional info for symmetric encryption
    let extraInfo = '';
    if (task.cipher_mode) {
        extraInfo += `
            <div class="task-row">
                <span class="task-label">Cipher Mode:</span>
                <span class="task-value">${task.cipher_mode.toUpperCase()}</span>
            </div>
        `;
    }
    if (task.padding) {
        extraInfo += `
            <div class="task-row">
                <span class="task-label">Padding:</span>
                <span class="task-value">${task.padding.toUpperCase()}</span>
            </div>
        `;
    }

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
            ${extraInfo}
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

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-message">${escapeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">x</button>
    `;
    
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;';
        document.body.appendChild(container);
    }
    
    const colors = {
        success: '#10b981',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6'
    };
    
    toast.style.cssText = `
        padding: 12px 20px;
        border-radius: 8px;
        color: white;
        display: flex;
        align-items: center;
        gap: 10px;
        animation: slideIn 0.3s ease;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        background: ${colors[type] || colors.info};
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}
