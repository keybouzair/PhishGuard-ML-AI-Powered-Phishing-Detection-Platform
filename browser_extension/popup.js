// Phishing Detector Browser Extension - Popup Script

const API_BASE_URL = 'http://localhost:5000';

// DOM Elements
const currentUrlEl = document.getElementById('currentUrl');
const statusIcon = document.getElementById('statusIcon');
const statusText = document.getElementById('statusText');
const statusScore = document.getElementById('statusScore');
const checkBtn = document.getElementById('checkBtn');
const checkUrlBtn = document.getElementById('checkUrlBtn');
const urlInput = document.getElementById('urlInput');
const details = document.getElementById('details');
const riskBar = document.getElementById('riskBar');
const riskFill = document.getElementById('riskFill');
const autoScan = document.getElementById('autoScan');
const showNotifications = document.getElementById('showNotifications');
const totalScans = document.getElementById('totalScans');
const safeCount = document.getElementById('safeCount');
const blockedCount = document.getElementById('blockedCount');
const openDashboard = document.getElementById('openDashboard');

// Status configurations
const STATUS = {
    safe: {
        icon: '✅',
        text: 'Safe',
        class: 'safe',
        color: '#28a745'
    },
    warning: {
        icon: '⚠️',
        text: 'Suspicious',
        class: 'warning',
        color: '#ffc107'
    },
    danger: {
        icon: '🚨',
        text: 'Dangerous!',
        class: 'danger',
        color: '#dc3545'
    },
    checking: {
        icon: '🔍',
        text: 'Checking...',
        class: 'checking',
        color: '#007bff'
    },
    error: {
        icon: '❌',
        text: 'Error',
        class: 'danger',
        color: '#dc3545'
    }
};

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
    // Load settings
    const settings = await chrome.storage.local.get(['autoScan', 'showNotifications', 'stats']);
    autoScan.checked = settings.autoScan || false;
    showNotifications.checked = settings.showNotifications !== false;
    
    // Load stats
    if (settings.stats) {
        totalScans.textContent = settings.stats.total || 0;
        safeCount.textContent = settings.stats.safe || 0;
        blockedCount.textContent = settings.stats.blocked || 0;
    }
    
    // Get current tab URL
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
        currentUrlEl.textContent = tab.url;
        
        // Check if already scanned
        const cache = await chrome.storage.local.get(['urlCache']);
        if (cache.urlCache && cache.urlCache[tab.url]) {
            displayResult(cache.urlCache[tab.url]);
        }
    }
});

// Check current page
checkBtn.addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
        await checkUrl(tab.url);
    }
});

// Check entered URL
checkUrlBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (url) {
        await checkUrl(url);
    }
});

// Enter key for URL input
urlInput.addEventListener('keypress', async (e) => {
    if (e.key === 'Enter') {
        const url = urlInput.value.trim();
        if (url) {
            await checkUrl(url);
        }
    }
});

// Save settings
autoScan.addEventListener('change', () => {
    chrome.storage.local.set({ autoScan: autoScan.checked });
    chrome.runtime.sendMessage({ type: 'settingsChanged', autoScan: autoScan.checked });
});

showNotifications.addEventListener('change', () => {
    chrome.storage.local.set({ showNotifications: showNotifications.checked });
});

// Open dashboard
openDashboard.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: `${API_BASE_URL}/user_dashboard` });
});

// Check URL function
async function checkUrl(url) {
    setStatus('checking');
    checkBtn.disabled = true;
    checkUrlBtn.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/check_url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) {
            throw new Error('API request failed');
        }
        
        const result = await response.json();
        
        // Cache result
        const cache = await chrome.storage.local.get(['urlCache']);
        const urlCache = cache.urlCache || {};
        urlCache[url] = result;
        await chrome.storage.local.set({ urlCache });
        
        // Update stats
        await updateStats(result.is_phishing);
        
        // Display result
        displayResult(result);
        
        // Send to background for notification
        chrome.runtime.sendMessage({
            type: 'urlChecked',
            url,
            result
        });
        
    } catch (error) {
        console.error('Check failed:', error);
        setStatus('error');
        statusScore.textContent = 'Could not connect to server. Make sure the server is running.';
    }
    
    checkBtn.disabled = false;
    checkUrlBtn.disabled = false;
}

// Display result
function displayResult(result) {
    const score = result.prediction_score || 0;
    
    let status;
    if (score >= 70) {
        status = 'danger';
    } else if (score >= 40) {
        status = 'warning';
    } else {
        status = 'safe';
    }
    
    setStatus(status);
    statusScore.textContent = `Threat Score: ${score.toFixed(1)}%`;
    
    // Show risk bar
    riskBar.classList.remove('hidden');
    riskFill.style.width = `${score}%`;
    riskFill.style.background = STATUS[status].color;
    
    // Show details
    details.classList.remove('hidden');
    document.getElementById('threatScore').textContent = `${score.toFixed(1)}%`;
    document.getElementById('sslStatus').textContent = result.url?.startsWith('https') ? '🔒 Secure' : '⚠️ Not Secure';
    document.getElementById('domainAge').textContent = result.domain_age || 'Unknown';
}

// Set status display
function setStatus(statusKey) {
    const status = STATUS[statusKey];
    
    // Reset classes
    statusIcon.className = 'status-icon ' + status.class;
    statusText.className = 'status-text ' + status.class;
    
    // Set content
    statusIcon.textContent = status.icon;
    statusText.textContent = status.text;
}

// Update statistics
async function updateStats(isPhishing) {
    const storage = await chrome.storage.local.get(['stats']);
    const stats = storage.stats || { total: 0, safe: 0, blocked: 0 };
    
    stats.total++;
    if (isPhishing) {
        stats.blocked++;
    } else {
        stats.safe++;
    }
    
    await chrome.storage.local.set({ stats });
    
    totalScans.textContent = stats.total;
    safeCount.textContent = stats.safe;
    blockedCount.textContent = stats.blocked;
}
