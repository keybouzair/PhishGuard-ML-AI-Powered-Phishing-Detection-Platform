// Phishing Detector Browser Extension - Popup Script

let API_BASE_URL = 'http://localhost:5001';
let API_KEY = '';

// DOM Elements
let currentUrlEl;
let statusIcon;
let statusText;
let statusScore;
let checkBtn;
let checkUrlBtn;
let urlInput;
let details;
let riskBar;
let riskFill;
let autoScan;
let showNotifications;
let totalScans;
let safeCount;
let blockedCount;
let openDashboard;

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
    // Assign DOM Elements
    currentUrlEl = document.getElementById('currentUrl');
    statusIcon = document.getElementById('statusIcon');
    statusText = document.getElementById('statusText');
    statusScore = document.getElementById('statusScore');
    checkBtn = document.getElementById('checkBtn');
    checkUrlBtn = document.getElementById('checkUrlBtn');
    urlInput = document.getElementById('urlInput');
    details = document.getElementById('details');
    riskBar = document.getElementById('riskBar');
    riskFill = document.getElementById('riskFill');
    autoScan = document.getElementById('autoScan');
    showNotifications = document.getElementById('showNotifications');
    totalScans = document.getElementById('totalScans');
    safeCount = document.getElementById('safeCount');
    blockedCount = document.getElementById('blockedCount');
    openDashboard = document.getElementById('openDashboard');

    // Load configuration
    const config = await chrome.storage.sync.get(['apiBaseUrl', 'apiKey']);
    API_BASE_URL = config.apiBaseUrl || '';
    API_KEY = config.apiKey || '';

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
        const base = API_BASE_URL || 'http://localhost:5001';
        chrome.tabs.create({ url: `${base}/user_dashboard` });
    });
});

// Check URL function
async function checkUrl(url) {
    setStatus('checking');
    checkBtn.disabled = true;
    checkUrlBtn.disabled = true;

    // Prompt if API_BASE_URL is not set
    if (!API_BASE_URL) {
        const inputUrl = prompt("Please enter the PhishGuard API Base URL:", "http://localhost:5001");
        if (inputUrl) {
            API_BASE_URL = inputUrl.trim();
            await chrome.storage.sync.set({ apiBaseUrl: API_BASE_URL });
        } else {
            setStatus('error');
            statusScore.textContent = 'API Base URL is required to check URLs.';
            checkBtn.disabled = false;
            checkUrlBtn.disabled = false;
            return;
        }
    }
    
    try {
        const headers = {
            'Content-Type': 'application/json'
        };
        if (API_KEY) {
            headers['Authorization'] = `Bearer ${API_KEY}`;
        }

        const response = await fetch(`${API_BASE_URL}/api/check`, {
            method: 'POST',
            headers: headers,
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
