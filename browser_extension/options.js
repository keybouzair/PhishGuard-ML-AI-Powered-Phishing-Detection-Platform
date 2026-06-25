// PhishGuard Options Page Logic

document.addEventListener('DOMContentLoaded', () => {
    const apiBaseUrlInput = document.getElementById('apiBaseUrl');
    const apiKeyInput = document.getElementById('apiKey');
    const scanAllowlistInput = document.getElementById('scanAllowlist');
    const saveBtn = document.getElementById('saveBtn');
    const statusMsg = document.getElementById('statusMsg');

    // Load saved settings
    chrome.storage.sync.get(['apiBaseUrl', 'apiKey', 'scanAllowlist'], (items) => {
        apiBaseUrlInput.value = items.apiBaseUrl || 'http://localhost:5001';
        apiKeyInput.value = items.apiKey || '';
        scanAllowlistInput.value = items.scanAllowlist || '';
    });

    // Save settings
    saveBtn.addEventListener('click', () => {
        const apiBaseUrl = apiBaseUrlInput.value.trim();
        const apiKey = apiKeyInput.value.trim();
        const scanAllowlist = scanAllowlistInput.value.trim();

        chrome.storage.sync.set({
            apiBaseUrl: apiBaseUrl,
            apiKey: apiKey,
            scanAllowlist: scanAllowlist
        }, () => {
            statusMsg.className = 'status-message status-success';
            statusMsg.style.display = 'block';
            setTimeout(() => {
                statusMsg.style.display = 'none';
            }, 3000);
        });
    });
});
