// Phishing Detector Browser Extension - Content Script

(function() {
    'use strict';
    
    const API_BASE_URL = 'http://localhost:5000';
    
    // Configuration
    const CONFIG = {
        highlightLinks: true,
        showTooltips: true,
        checkOnHover: false,
        hoverDelay: 500
    };
    
    // Cache for checked URLs
    const urlCache = new Map();
    
    // Styles for link highlighting
    const styles = `
        .phishing-safe {
            position: relative;
        }
        .phishing-safe::after {
            content: '✓';
            color: #28a745;
            font-size: 10px;
            margin-left: 3px;
        }
        .phishing-warning {
            position: relative;
            background-color: rgba(255, 193, 7, 0.1) !important;
        }
        .phishing-warning::after {
            content: '⚠';
            color: #ffc107;
            font-size: 10px;
            margin-left: 3px;
        }
        .phishing-danger {
            position: relative;
            background-color: rgba(220, 53, 69, 0.1) !important;
            text-decoration: line-through !important;
        }
        .phishing-danger::after {
            content: '🚨';
            font-size: 10px;
            margin-left: 3px;
        }
        .phishing-tooltip {
            position: absolute;
            background: #333;
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-family: Arial, sans-serif;
            z-index: 999999;
            max-width: 300px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            pointer-events: none;
        }
        .phishing-tooltip::before {
            content: '';
            position: absolute;
            bottom: -6px;
            left: 20px;
            border-left: 6px solid transparent;
            border-right: 6px solid transparent;
            border-top: 6px solid #333;
        }
        .phishing-tooltip.safe { border-left: 3px solid #28a745; }
        .phishing-tooltip.warning { border-left: 3px solid #ffc107; }
        .phishing-tooltip.danger { border-left: 3px solid #dc3545; }
        
        .phishing-warning-banner {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
            padding: 15px 20px;
            z-index: 999999;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        .phishing-warning-banner h3 {
            margin: 0 0 5px;
            font-size: 18px;
        }
        .phishing-warning-banner p {
            margin: 0;
            font-size: 14px;
            opacity: 0.9;
        }
        .phishing-warning-banner button {
            background: white;
            color: #dc3545;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        .phishing-warning-banner .dismiss {
            background: transparent;
            color: white;
            border: 1px solid white;
            margin-left: 10px;
        }
    `;
    
    // Inject styles
    const styleSheet = document.createElement('style');
    styleSheet.textContent = styles;
    document.head.appendChild(styleSheet);
    
    // Tooltip element
    let tooltip = null;
    
    function createTooltip() {
        tooltip = document.createElement('div');
        tooltip.className = 'phishing-tooltip';
        tooltip.style.display = 'none';
        document.body.appendChild(tooltip);
    }
    
    function showTooltip(element, result) {
        if (!tooltip) createTooltip();
        
        const score = result.prediction_score || 0;
        let status, message;
        
        if (score >= 70) {
            status = 'danger';
            message = `🚨 DANGEROUS! Threat Score: ${score.toFixed(1)}%<br>This link is likely a phishing attempt!`;
        } else if (score >= 40) {
            status = 'warning';
            message = `⚠️ Suspicious - Threat Score: ${score.toFixed(1)}%<br>Proceed with caution.`;
        } else {
            status = 'safe';
            message = `✅ Safe - Threat Score: ${score.toFixed(1)}%<br>This link appears to be legitimate.`;
        }
        
        tooltip.innerHTML = message;
        tooltip.className = `phishing-tooltip ${status}`;
        
        const rect = element.getBoundingClientRect();
        tooltip.style.left = `${rect.left + window.scrollX}px`;
        tooltip.style.top = `${rect.top + window.scrollY - tooltip.offsetHeight - 10}px`;
        tooltip.style.display = 'block';
    }
    
    function hideTooltip() {
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    }
    
    // Check URL
    async function checkUrl(url) {
        // Check cache first
        if (urlCache.has(url)) {
            return urlCache.get(url);
        }
        
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
            urlCache.set(url, result);
            
            return result;
            
        } catch (error) {
            console.error('Phishing check failed:', error);
            return null;
        }
    }
    
    // Highlight link based on result
    function highlightLink(link, result) {
        if (!CONFIG.highlightLinks) return;
        
        const score = result.prediction_score || 0;
        
        // Remove existing classes
        link.classList.remove('phishing-safe', 'phishing-warning', 'phishing-danger');
        
        if (score >= 70) {
            link.classList.add('phishing-danger');
        } else if (score >= 40) {
            link.classList.add('phishing-warning');
        } else {
            link.classList.add('phishing-safe');
        }
    }
    
    // Show warning banner for dangerous page
    function showWarningBanner(score) {
        // Check if banner already exists
        if (document.querySelector('.phishing-warning-banner')) return;
        
        const banner = document.createElement('div');
        banner.className = 'phishing-warning-banner';
        banner.innerHTML = `
            <div>
                <h3>🚨 Phishing Warning!</h3>
                <p>This page has been detected as potentially dangerous (Threat Score: ${score.toFixed(1)}%). Proceed with extreme caution.</p>
            </div>
            <div>
                <button onclick="window.history.back()">← Go Back</button>
                <button class="dismiss" onclick="this.parentElement.parentElement.remove()">Dismiss</button>
            </div>
        `;
        
        document.body.insertBefore(banner, document.body.firstChild);
        document.body.style.marginTop = `${banner.offsetHeight}px`;
    }
    
    // Process all links on page
    async function processLinks() {
        const links = document.querySelectorAll('a[href]');
        
        for (const link of links) {
            const href = link.href;
            
            // Skip internal links and javascript
            if (!href || 
                href.startsWith('javascript:') || 
                href.startsWith('#') ||
                href.startsWith('mailto:') ||
                href.startsWith('tel:')) {
                continue;
            }
            
            // Add hover handlers
            if (CONFIG.checkOnHover) {
                let hoverTimeout;
                
                link.addEventListener('mouseenter', async () => {
                    hoverTimeout = setTimeout(async () => {
                        const result = await checkUrl(href);
                        if (result) {
                            highlightLink(link, result);
                            if (CONFIG.showTooltips) {
                                showTooltip(link, result);
                            }
                        }
                    }, CONFIG.hoverDelay);
                });
                
                link.addEventListener('mouseleave', () => {
                    clearTimeout(hoverTimeout);
                    hideTooltip();
                });
            }
            
            // Add click warning for dangerous links
            link.addEventListener('click', async (e) => {
                const result = await checkUrl(href);
                
                if (result && result.is_phishing) {
                    e.preventDefault();
                    
                    const proceed = confirm(
                        `⚠️ PHISHING WARNING!\n\n` +
                        `This link has been detected as potentially dangerous.\n` +
                        `Threat Score: ${result.prediction_score.toFixed(1)}%\n\n` +
                        `URL: ${href.substring(0, 50)}...\n\n` +
                        `Do you still want to proceed?`
                    );
                    
                    if (proceed) {
                        window.location.href = href;
                    }
                }
            });
        }
    }
    
    // Check current page
    async function checkCurrentPage() {
        const result = await checkUrl(window.location.href);
        
        if (result && result.is_phishing) {
            showWarningBanner(result.prediction_score);
            
            // Notify background script
            chrome.runtime.sendMessage({
                type: 'pagePhishing',
                url: window.location.href,
                result
            });
        }
        
        return result;
    }
    
    // Initialize
    async function init() {
        // Load settings
        chrome.storage.local.get(['settings'], (data) => {
            if (data.settings) {
                Object.assign(CONFIG, data.settings);
            }
        });
        
        // Check current page
        await checkCurrentPage();
        
        // Process links after page load
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', processLinks);
        } else {
            processLinks();
        }
        
        // Watch for dynamically added links
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        if (node.tagName === 'A') {
                            // Process the link
                        } else {
                            const links = node.querySelectorAll('a[href]');
                            // Process all links in the added node
                        }
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    // Listen for messages from background
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === 'checkPage') {
            checkCurrentPage().then(result => {
                sendResponse(result);
            });
            return true;
        }
        
        if (message.type === 'processLinks') {
            processLinks();
        }
    });
    
    // Start
    init();
    
})();
