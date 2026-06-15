// Phishing Detector Browser Extension - Background Service Worker

const API_BASE_URL = 'http://localhost:5000';

// Context menu setup
chrome.runtime.onInstalled.addListener(() => {
    // Create context menu for checking links
    chrome.contextMenus.create({
        id: 'checkLink',
        title: '🔒 Check this link for phishing',
        contexts: ['link']
    });
    
    chrome.contextMenus.create({
        id: 'checkPage',
        title: '🔒 Check this page for phishing',
        contexts: ['page']
    });
    
    chrome.contextMenus.create({
        id: 'checkSelection',
        title: '🔒 Check selected URL',
        contexts: ['selection']
    });
    
    // Initialize stats
    chrome.storage.local.get(['stats'], (result) => {
        if (!result.stats) {
            chrome.storage.local.set({
                stats: { total: 0, safe: 0, blocked: 0 }
            });
        }
    });
    
    console.log('Phishing Detector extension installed');
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    let urlToCheck;
    
    switch (info.menuItemId) {
        case 'checkLink':
            urlToCheck = info.linkUrl;
            break;
        case 'checkPage':
            urlToCheck = info.pageUrl;
            break;
        case 'checkSelection':
            urlToCheck = info.selectionText;
            break;
    }
    
    if (urlToCheck) {
        const result = await checkUrl(urlToCheck);
        
        // Show notification
        showNotification(urlToCheck, result);
        
        // Update badge
        updateBadge(result);
    }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'urlChecked') {
        updateBadge(message.result);
        
        if (message.result.is_phishing) {
            chrome.storage.local.get(['showNotifications'], (settings) => {
                if (settings.showNotifications !== false) {
                    showNotification(message.url, message.result);
                }
            });
        }
    }
    
    if (message.type === 'settingsChanged') {
        // Handle settings changes
        if (message.autoScan) {
            enableAutoScan();
        } else {
            disableAutoScan();
        }
    }
    
    if (message.type === 'checkUrl') {
        checkUrl(message.url).then(result => {
            sendResponse(result);
        });
        return true; // Keep channel open for async response
    }
});

// Check URL against API
async function checkUrl(url) {
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
        
        // Update stats
        const storage = await chrome.storage.local.get(['stats']);
        const stats = storage.stats || { total: 0, safe: 0, blocked: 0 };
        stats.total++;
        if (result.is_phishing) {
            stats.blocked++;
        } else {
            stats.safe++;
        }
        await chrome.storage.local.set({ stats });
        
        return result;
        
    } catch (error) {
        console.error('Check failed:', error);
        return {
            error: true,
            message: 'Could not check URL',
            is_phishing: false
        };
    }
}

// Show notification
function showNotification(url, result) {
    const score = result.prediction_score || 0;
    
    let title, message, iconUrl;
    
    if (result.is_phishing || score >= 50) {
        title = '🚨 Phishing Alert!';
        message = `Warning: This URL may be dangerous!\n\nThreat Score: ${score.toFixed(1)}%\n\n${url.substring(0, 50)}...`;
        iconUrl = 'icons/icon-danger.png';
    } else {
        title = '✅ URL is Safe';
        message = `This URL appears to be safe.\n\nThreat Score: ${score.toFixed(1)}%`;
        iconUrl = 'icons/icon-safe.png';
    }
    
    chrome.notifications.create({
        type: 'basic',
        iconUrl: iconUrl || 'icons/icon128.png',
        title: title,
        message: message,
        priority: result.is_phishing ? 2 : 0
    });
}

// Update extension badge
function updateBadge(result) {
    const score = result.prediction_score || 0;
    
    if (result.is_phishing || score >= 70) {
        chrome.action.setBadgeText({ text: '!' });
        chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
    } else if (score >= 40) {
        chrome.action.setBadgeText({ text: '?' });
        chrome.action.setBadgeBackgroundColor({ color: '#ffc107' });
    } else {
        chrome.action.setBadgeText({ text: '✓' });
        chrome.action.setBadgeBackgroundColor({ color: '#28a745' });
    }
    
    // Clear badge after 5 seconds
    setTimeout(() => {
        chrome.action.setBadgeText({ text: '' });
    }, 5000);
}

// Auto-scan functionality
let autoScanEnabled = false;

function enableAutoScan() {
    autoScanEnabled = true;
    
    // Listen for tab updates
    chrome.tabs.onUpdated.addListener(autoScanHandler);
    
    console.log('Auto-scan enabled');
}

function disableAutoScan() {
    autoScanEnabled = false;
    chrome.tabs.onUpdated.removeListener(autoScanHandler);
    console.log('Auto-scan disabled');
}

async function autoScanHandler(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab.url) {
        // Skip internal pages
        if (tab.url.startsWith('chrome://') || 
            tab.url.startsWith('chrome-extension://') ||
            tab.url.startsWith('about:')) {
            return;
        }
        
        // Check if already cached
        const cache = await chrome.storage.local.get(['urlCache']);
        if (cache.urlCache && cache.urlCache[tab.url]) {
            updateBadge(cache.urlCache[tab.url]);
            return;
        }
        
        // Check the URL
        const result = await checkUrl(tab.url);
        
        // Cache result
        const urlCache = cache.urlCache || {};
        urlCache[tab.url] = result;
        await chrome.storage.local.set({ urlCache });
        
        // Update badge
        updateBadge(result);
        
        // Show notification if dangerous
        if (result.is_phishing) {
            const settings = await chrome.storage.local.get(['showNotifications']);
            if (settings.showNotifications !== false) {
                showNotification(tab.url, result);
            }
        }
    }
}

// Initialize auto-scan setting
chrome.storage.local.get(['autoScan'], (result) => {
    if (result.autoScan) {
        enableAutoScan();
    }
});

// Periodic cache cleanup (every hour)
chrome.alarms.create('cacheCleanup', { periodInMinutes: 60 });

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'cacheCleanup') {
        chrome.storage.local.get(['urlCache'], (result) => {
            // Keep only last 100 entries
            const cache = result.urlCache || {};
            const entries = Object.entries(cache);
            
            if (entries.length > 100) {
                const newCache = Object.fromEntries(entries.slice(-100));
                chrome.storage.local.set({ urlCache: newCache });
            }
        });
    }
});

console.log('Phishing Detector background service started');
