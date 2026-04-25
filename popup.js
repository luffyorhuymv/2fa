/**
 * 2FA Authenticator - Chrome Extension
 * TOTP (Time-based One-Time Password) Generator
 */

// ============================================
// TOTP ALGORITHM (RFC 6238)
// ============================================

// Base32 decoding table
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(str) {
    str = str.toUpperCase().replace(/\s+/g, '').replace(/=+$/, '');
    let bits = '';

    for (let char of str) {
        const val = BASE32_CHARS.indexOf(char);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }

    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
    }

    return bytes;
}

// Normalize algorithm name to Web Crypto format
function normalizeAlgorithm(algo) {
    if (!algo) return 'SHA-1';
    const a = String(algo).toUpperCase().replace(/-/g, '');
    if (a === 'SHA1') return 'SHA-1';
    if (a === 'SHA256') return 'SHA-256';
    if (a === 'SHA512') return 'SHA-512';
    return 'SHA-1';
}

// HMAC implementation supporting SHA-1 / SHA-256 / SHA-512
async function hmac(key, message, algorithm = 'SHA-1') {
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: algorithm },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
}

// Generate TOTP code (RFC 6238) with configurable algorithm/digits/period
async function generateTOTP(secret, options = {}) {
    const period = options.period || 30;
    const digits = options.digits || 6;
    const algorithm = normalizeAlgorithm(options.algorithm);

    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 1000 / period);

    // Convert time to 8-byte big-endian buffer
    const timeBuffer = new ArrayBuffer(8);
    const view = new DataView(timeBuffer);
    view.setUint32(4, time, false);

    const hash = await hmac(key, new Uint8Array(timeBuffer), algorithm);

    // Dynamic truncation (works for SHA-1/256/512: offset & 0x0f ≤ 15, +3 < 20/32/64)
    const offset = hash[hash.length - 1] & 0x0f;
    const code = (
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff)
    ) % Math.pow(10, digits);

    return code.toString().padStart(digits, '0');
}

// Get remaining seconds in current period
function getRemainingSeconds(timeStep = 30) {
    return timeStep - (Math.floor(Date.now() / 1000) % timeStep);
}

// Format OTP code into readable groups based on length
function formatOtpCode(code) {
    if (code.length <= 4) return code;
    const mid = Math.ceil(code.length / 2);
    return code.slice(0, mid) + ' ' + code.slice(mid);
}

// Normalize secret (Base32 chars only, uppercase, no whitespace)
function normalizeSecret(secret) {
    return String(secret).replace(/\s+/g, '').toUpperCase();
}

// ============================================
// STORAGE MANAGEMENT
// ============================================

// Lock to prevent concurrent storage operations
let storageLock = Promise.resolve();

async function withStorageLock(fn) {
    const previousLock = storageLock;
    let releaseLock;
    storageLock = new Promise(resolve => { releaseLock = resolve; });
    await previousLock;
    try {
        return await fn();
    } finally {
        releaseLock();
    }
}

async function getAccounts() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['accounts'], (result) => {
            const accounts = result.accounts || [];
            resolve(accounts);
        });
    });
}

async function saveAccounts(accounts) {
    return new Promise((resolve, reject) => {
        chrome.storage.local.set({ accounts: accounts }, () => {
            if (chrome.runtime.lastError) {
                reject(chrome.runtime.lastError);
            } else {
                resolve();
            }
        });
    });
}

// Categories
const CATEGORIES = {
    'google': { name: 'Google', icon: '🔍', color: '#4285f4' },
    'microsoft': { name: 'Microsoft', icon: '⊞', color: '#00a4ef' },
    'finance': { name: 'Tài chính', icon: '💰', color: '#10b981' },
    'social': { name: 'Mạng xã hội', icon: '💬', color: '#8b5cf6' },
    'work': { name: 'Công việc', icon: '💼', color: '#f59e0b' },
    'game': { name: 'Game', icon: '🎮', color: '#ec4899' },
    'other': { name: 'Khác', icon: '📌', color: '#6b7280' }
};

async function addAccount(name, secret, email = '', category = 'other', extra = {}) {
    return withStorageLock(async () => {
        const accounts = await getAccounts();
        const id = Date.now().toString(36) + Math.random().toString(36).substr(2);
        const newAccount = {
            id,
            name,
            secret: normalizeSecret(secret),
            email: email || '',
            category: category || 'other',
            createdAt: Date.now()
        };
        if (extra.algorithm) newAccount.algorithm = extra.algorithm;
        if (extra.digits && extra.digits !== 6) newAccount.digits = extra.digits;
        if (extra.period && extra.period !== 30) newAccount.period = extra.period;
        accounts.push(newAccount);
        await saveAccounts(accounts);
        return accounts;
    });
}

async function deleteAccount(id) {
    return withStorageLock(async () => {
        const accounts = await getAccounts();
        const acc = accounts.find(a => a.id === id);
        if (acc) {
            const tombstones = pruneTombstones(await getTombstones());
            const ns = normalizeSecret(acc.secret);
            // Replace existing tombstone for same secret with newer one
            const filtered = tombstones.filter(t => t.secret !== ns);
            filtered.push({ secret: ns, deletedAt: Date.now() });
            await saveTombstones(filtered);
        }
        const remaining = accounts.filter(a => a.id !== id);
        await saveAccounts(remaining);
        return remaining;
    });
}

// ============================================
// TOMBSTONE MANAGEMENT (delete propagation)
// ============================================

const TOMBSTONE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

async function getTombstones() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['tombstones'], (result) => {
            resolve(Array.isArray(result.tombstones) ? result.tombstones : []);
        });
    });
}

async function saveTombstones(tombstones) {
    return new Promise((resolve, reject) => {
        chrome.storage.local.set({ tombstones }, () => {
            if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
            else resolve();
        });
    });
}

function pruneTombstones(tombstones) {
    const cutoff = Date.now() - TOMBSTONE_TTL_MS;
    return (tombstones || []).filter(t => t && t.secret && t.deletedAt > cutoff);
}

function mergeTombstones(...lists) {
    const map = new Map();
    for (const list of lists) {
        for (const t of (list || [])) {
            if (!t || !t.secret || !t.deletedAt) continue;
            const existing = map.get(t.secret);
            if (!existing || t.deletedAt > existing.deletedAt) {
                map.set(t.secret, { secret: t.secret, deletedAt: t.deletedAt });
            }
        }
    }
    return Array.from(map.values());
}

// Remove accounts that are shadowed by a newer tombstone
function applyTombstones(accounts, tombstones) {
    const tombMap = new Map(tombstones.map(t => [t.secret, t.deletedAt]));
    return accounts.filter(acc => {
        const ts = tombMap.get(normalizeSecret(acc.secret));
        if (!ts) return true;
        return (acc.createdAt || 0) > ts;
    });
}

/**
 * Auto sync khi có thay đổi (nếu đã cấu hình URL + Password)
 * LƯU Ý: Tính năng này hiện tại bị tắt vì masterPassword không được lưu 
 * (vì lý do bảo mật). Ngườ dùng cần sync thủ công qua Sync Modal.
 */
async function autoSyncToCloud() {
    // Auto sync disabled - requires master password which is not stored
    // User must use manual sync via Sync Modal
    return;
    
    /* Code cũ - cần password mới chạy được:
    const stored = await chrome.storage.sync.get(['syncSettings']);
    const apiUrl = stored.syncSettings?.apiUrl;

    if (!apiUrl || !settings?.masterPassword) {
        console.log('Auto sync: Chưa cấu hình URL hoặc Password');
        return;
    }

    try {
        const accounts = await getAccounts();
        const dataStr = JSON.stringify(accounts);
        const encrypted = await CryptoModule.encrypt(dataStr, settings.masterPassword);

        await fetch(apiUrl, {
            method: 'POST',
            body: JSON.stringify({
                data: encrypted,
                timestamp: Date.now()
            })
        });
        console.log('Auto sync: Đã upload thành công');
    } catch (error) {
        console.error('Auto sync failed:', error);
    }
    */
}

// ============================================
// UI ELEMENTS
// ============================================

const addBtn = document.getElementById('addBtn');
const addForm = document.getElementById('addForm');
const cancelBtn = document.getElementById('cancelBtn');
const saveBtn = document.getElementById('saveBtn');
const serviceNameInput = document.getElementById('serviceName');
const secretKeyInput = document.getElementById('secretKey');
const accountsList = document.getElementById('accountsList');
const emptyState = document.getElementById('emptyState');
const addFirstBtn = document.getElementById('addFirstBtn');

// QR Scanner Elements
const scanBtn = document.getElementById('scanBtn');
const scanForm = document.getElementById('scanForm');
const cancelScanBtn = document.getElementById('cancelScanBtn');
const scanNowBtn = document.getElementById('scanNowBtn');
const addScannedBtn = document.getElementById('addScannedBtn');
const qrFileInput = document.getElementById('qrFileInput');
const uploadBtn = document.getElementById('uploadBtn');
const fileName = document.getElementById('fileName');
const qrUrl = document.getElementById('qrUrl');
const scanPreview = document.getElementById('scanPreview');
const previewName = document.getElementById('previewName');
const previewSecret = document.getElementById('previewSecret');
const scanScreenBtn = document.getElementById('scanScreenBtn');

// Camera Elements
const scanCameraBtn = document.getElementById('scanCameraBtn');
const cameraContainer = document.getElementById('cameraContainer');
const cameraVideo = document.getElementById('cameraVideo');
const stopCameraBtn = document.getElementById('stopCameraBtn');
let stopCameraFn = null;

// Search & Pagination Elements
const searchInput = document.getElementById('searchInput');
const clearSearchBtn = document.getElementById('clearSearchBtn');
const paginationControls = document.getElementById('paginationControls');
const prevPageBtn = document.getElementById('prevPageBtn');
const nextPageBtn = document.getElementById('nextPageBtn');
const pageInfo = document.getElementById('pageInfo');

// Pagination State
let currentPage = 1;
const ITEMS_PER_PAGE = 5;
let filteredAccounts = [];

// Scanned data storage
let scannedData = null;

// ============================================
// UI FUNCTIONS
// ============================================

function showAddForm() {
    hideScanForm();
    addForm.classList.remove('hidden');
    serviceNameInput.focus();
}

function hideAddForm() {
    addForm.classList.add('hidden');
    serviceNameInput.value = '';
    secretKeyInput.value = '';
}

function showScanForm() {
    hideAddForm();
    scanForm.classList.remove('hidden');
    resetScanForm();
}

function hideScanForm() {
    scanForm.classList.add('hidden');
    resetScanForm();
}

function resetScanForm() {
    qrFileInput.value = '';
    qrUrl.value = '';
    fileName.textContent = 'Chưa chọn file';
    scanPreview.classList.add('hidden');
    scanNowBtn.classList.remove('hidden');
    addScannedBtn.classList.add('hidden');

    // Reset camera if active
    if (stopCameraFn) {
        stopCameraFn();
        stopCameraFn = null;
    }
    cameraContainer.classList.add('hidden');

    scannedData = null;
}

function showScanPreview(data) {
    scannedData = data;
    previewName.textContent = data.name || 'Unknown';
    previewSecret.textContent = data.secret ? `${data.secret.slice(0, 8)}...` : '-';
    scanPreview.classList.remove('hidden');
    scanNowBtn.classList.add('hidden');
    addScannedBtn.classList.remove('hidden');
}

function updateEmptyState(accountsCount) {
    if (accountsCount === 0) {
        emptyState.classList.remove('hidden');
        accountsList.classList.add('hidden');
    } else {
        emptyState.classList.add('hidden');
        accountsList.classList.remove('hidden');
    }
}

function createTimerRing(remaining, total = 30) {
    const radius = 14;
    const circumference = 2 * Math.PI * radius;
    const progress = (remaining / total) * circumference;

    return `
    <div class="timer-ring" data-period="${total}">
      <svg width="36" height="36">
        <circle class="bg" cx="18" cy="18" r="${radius}"/>
        <circle class="progress" cx="18" cy="18" r="${radius}"
          stroke-dasharray="${circumference}"
          stroke-dashoffset="${circumference - progress}"/>
      </svg>
      <span class="time">${remaining}</span>
    </div>
  `;
}

// In-memory map of visible account id → secret (so secret is NOT in DOM attributes)
const secretMap = new Map();

// Current service filter (null = all, else lowercase service name)
let currentServiceFilter = null;

// Build chips from all accounts, render into #serviceFilter, attach click handler
function renderServiceFilter(accounts) {
    const container = document.getElementById('serviceFilter');
    if (!container) return;

    if (!accounts || accounts.length === 0) {
        container.classList.add('hidden');
        container.innerHTML = '';
        return;
    }

    // Group by lowercase name, keep first-seen display casing
    const groups = new Map(); // key=lowercase, val={display, count}
    for (const acc of accounts) {
        const name = (acc.name || '').trim();
        if (!name) continue;
        const key = name.toLowerCase();
        const existing = groups.get(key);
        if (existing) {
            existing.count++;
        } else {
            groups.set(key, { display: name, count: 1 });
        }
    }

    // If filter refers to a no-longer-existing service, reset
    if (currentServiceFilter && !groups.has(currentServiceFilter)) {
        currentServiceFilter = null;
    }

    // Sort: by count desc, then display name asc
    const sorted = Array.from(groups.entries()).sort((a, b) => {
        if (b[1].count !== a[1].count) return b[1].count - a[1].count;
        return a[1].display.localeCompare(b[1].display);
    });

    const total = accounts.length;
    const chips = [
        `<button type="button" class="filter-chip ${currentServiceFilter === null ? 'active' : ''}" data-service="">Tất cả<span class="chip-count">${total}</span></button>`
    ];
    for (const [key, { display, count }] of sorted) {
        const active = currentServiceFilter === key ? 'active' : '';
        chips.push(
            `<button type="button" class="filter-chip ${active}" data-service="${escapeHtml(key)}">${escapeHtml(display)}<span class="chip-count">${count}</span></button>`
        );
    }

    container.innerHTML = chips.join('');
    container.classList.remove('hidden');
}

// Delegate clicks on chip bar
(function attachServiceFilterHandler() {
    const container = document.getElementById('serviceFilter');
    if (!container) return;
    container.addEventListener('click', (e) => {
        const chip = e.target.closest('.filter-chip');
        if (!chip) return;
        const value = chip.dataset.service || '';
        const newFilter = value === '' ? null : value;
        if (newFilter === currentServiceFilter) return;
        currentServiceFilter = newFilter;
        currentPage = 1;
        renderAccounts();
    });
})();

async function renderAccounts() {
    const accounts = await getAccounts();
    const query = searchInput.value.trim().toLowerCase();

    // Render filter chips first (always based on ALL accounts, not search-filtered)
    renderServiceFilter(accounts);

    // Filter
    filteredAccounts = accounts.filter(acc => {
        // Service filter
        if (currentServiceFilter && (acc.name || '').toLowerCase() !== currentServiceFilter) {
            return false;
        }
        // Search filter
        if (!query) return true;
        return acc.name.toLowerCase().includes(query) ||
            (acc.email && acc.email.toLowerCase().includes(query)) ||
            (acc.issuer && acc.issuer.toLowerCase().includes(query));
    });

    // Reset to page 1 if current page is out of bounds
    const totalPages = Math.ceil(filteredAccounts.length / ITEMS_PER_PAGE) || 1;
    if (currentPage > totalPages) currentPage = 1;

    // Toggle Clear Search Button
    if (query) {
        clearSearchBtn.classList.remove('hidden');
    } else {
        clearSearchBtn.classList.add('hidden');
    }

    // Toggle Empty State / Pagination
    if (filteredAccounts.length === 0) {
        if (query) {
            // Search empty state
            accountsList.innerHTML = `<div class="empty-state"><p>Không tìm thấy kết quả cho "${escapeHtml(query)}"</p></div>`;
            accountsList.classList.remove('hidden');
            paginationControls.classList.add('hidden');
        } else {
            // No accounts empty state
            updateEmptyState(0);
            paginationControls.classList.add('hidden');
        }
        return;
    }

    updateEmptyState(filteredAccounts.length);

    // Paginate
    const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
    const endIndex = startIndex + ITEMS_PER_PAGE;
    const paginatedItems = filteredAccounts.slice(startIndex, endIndex);

    // Reset secret map to only what's visible
    secretMap.clear();

    const html = await Promise.all(paginatedItems.map(async (acc) => {
        secretMap.set(acc.id, acc.secret);

        const period = acc.period || 30;
        const digits = acc.digits || 6;
        const algorithm = acc.algorithm || 'SHA-1';
        const code = await generateTOTP(acc.secret, { algorithm, digits, period });
        const formattedCode = formatOtpCode(code);
        const accRemaining = getRemainingSeconds(period);

        return `
      <div class="account-item" data-id="${acc.id}">
        <div class="account-header">
          <div class="account-info">
            <span class="account-name">${escapeHtml(acc.name)}</span>
            ${acc.email ? `<span class="account-email">${escapeHtml(acc.email)}</span>` : ''}
          </div>
          <div class="account-actions">
            <button class="edit-btn" data-id="${acc.id}" title="Chỉnh sửa">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
              </svg>
            </button>
            <button class="reveal-btn" data-id="${acc.id}" title="Xem Secret Key">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                <circle cx="12" cy="12" r="3"/>
              </svg>
            </button>
            <button class="delete-btn" data-id="${acc.id}" title="Xóa">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M3 6h18"/>
                <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>
              </svg>
            </button>
          </div>
        </div>
        <div class="otp-container" data-period="${period}">
          <span class="otp-code" data-code="${code}" title="Click để copy">${formattedCode}</span>
          ${createTimerRing(accRemaining, period)}
        </div>
      </div>
    `;
    }));

    accountsList.innerHTML = html.join('');

    // Update Pagination UI
    if (filteredAccounts.length > ITEMS_PER_PAGE) {
        paginationControls.classList.remove('hidden');
        pageInfo.textContent = `Trang ${currentPage} / ${totalPages}`;
        prevPageBtn.disabled = currentPage === 1;
        nextPageBtn.disabled = currentPage === totalPages;
    } else {
        paginationControls.classList.add('hidden');
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ============================================
// TOAST NOTIFICATION SYSTEM
// ============================================

let toastTimeout = null;

function showToast(message, type = 'info') {
    // Remove existing toast
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }
    if (toastTimeout) {
        clearTimeout(toastTimeout);
    }

    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ'}</span>
        <span class="toast-message">${message}</span>
    `;
    document.body.appendChild(toast);

    // Show toast with animation
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });

    // Auto hide after 3s
    toastTimeout = setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

async function copyToClipboard(code) {
    try {
        await navigator.clipboard.writeText(code);
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        return false;
    }
}

// ============================================
// QR SCANNER FUNCTIONS
// ============================================

async function scanQR() {
    const file = qrFileInput.files[0];
    const url = qrUrl.value.trim();

    if (!file && !url) {
        showToast('Vui lòng chọn ảnh hoặc nhập URL!', 'error');
        return;
    }

    scanNowBtn.classList.add('loading');

    try {
        let result;
        if (file) {
            result = await window.QRScanner.scanQRFromFile(file);
        } else {
            result = await window.QRScanner.scanQRFromUrl(url);
        }

        if (result && result.secret) {
            showScanPreview(result);
        } else if (result && result.raw) {
            showToast('QR không chứa thông tin 2FA', 'error');
        } else {
            showToast('Không tìm thấy mã 2FA trong QR', 'error');
        }
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    } finally {
        scanNowBtn.classList.remove('loading');
    }
}

/**
 * Scan QR từ màn hình trình duyệt
 */
async function scanFromScreen() {
    scanScreenBtn.classList.add('loading');
    scanScreenBtn.disabled = true;

    try {
        const result = await window.QRScanner.scanQRFromScreen();

        if (result && result.secret) {
            showScanPreview(result);
        } else if (result && result.raw) {
            showToast('QR không chứa thông tin 2FA', 'error');
        } else {
            showToast('Không tìm thấy QR trên màn hình', 'error');
        }
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    } finally {
        scanScreenBtn.classList.remove('loading');
        scanScreenBtn.disabled = false;
    }
}

/**
 * Scan QR bằng cách chọn vùng (snipping)
 */
const snipScanBtn = document.getElementById('snipScanBtn');

async function startSnipScan() {
    if (!snipScanBtn) return;

    snipScanBtn.classList.add('loading');
    snipScanBtn.disabled = true;

    try {
        // Get current active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
            showToast('Không thể quét trên trang hệ thống', 'error');
            return;
        }

        // Inject the snip overlay script
        await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ['snip-overlay.js']
        });

        // Close popup to show the page
        window.close();

    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    } finally {
        snipScanBtn.classList.remove('loading');
        snipScanBtn.disabled = false;
    }
}

// Listen for snip results from background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SNIP_RESULT') {
        handleSnipResult(message);
    }
});

// handleSnipResult is now handled by checkSnipResults reading from storage
// Background.js stores result directly to chrome.storage.session

// Check for snip results when popup opens
async function checkSnipResults() {
    try {
        const { snipResult, snipError } = await chrome.storage.session.get(['snipResult', 'snipError']);

        if (snipResult) {
            showScanPreview(snipResult);
            showScanForm();
            chrome.storage.session.remove('snipResult');
        } else if (snipError) {
            showToast(snipError, 'error');
            chrome.storage.session.remove('snipError');
        }
    } catch (err) {
        // Session storage might not be available
    }
}

// ============================================
// EVENT HANDLERS
// ============================================

// Add Form Events
addBtn.addEventListener('click', showAddForm);
addFirstBtn.addEventListener('click', showAddForm);
cancelBtn.addEventListener('click', hideAddForm);

// Scan Form Events
scanBtn.addEventListener('click', showScanForm);
cancelScanBtn.addEventListener('click', hideScanForm);
scanNowBtn.addEventListener('click', scanQR);
scanScreenBtn.addEventListener('click', scanFromScreen);
if (snipScanBtn) {
    snipScanBtn.addEventListener('click', startSnipScan);
}

uploadBtn.addEventListener('click', () => {
    qrFileInput.click();
});

qrFileInput.addEventListener('change', () => {
    const file = qrFileInput.files[0];
    if (file) {
        fileName.textContent = file.name;
        qrUrl.value = ''; // Clear URL when file is selected
    }
});

qrUrl.addEventListener('input', () => {
    if (qrUrl.value.trim()) {
        qrFileInput.value = '';
        fileName.textContent = 'Chưa chọn file';
    }
});

addScannedBtn.addEventListener('click', async () => {
    if (!scannedData || !scannedData.secret) {
        showToast('Không có dữ liệu để thêm!', 'error');
        return;
    }

    try {
        // Truyền cả email + algorithm/digits/period từ QR code
        await addAccount(
            scannedData.name,
            scannedData.secret,
            scannedData.account || '',
            'other',
            {
                algorithm: normalizeAlgorithm(scannedData.algorithm),
                digits: scannedData.digits,
                period: scannedData.period
            }
        );
        hideScanForm();
        await renderAccounts();
        showToast('Đã thêm tài khoản thành công!', 'success');
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    }
});

saveBtn.addEventListener('click', async () => {
    const name = serviceNameInput.value.trim();
    const secret = secretKeyInput.value.trim();

    if (!name || !secret) {
        showToast('Vui lòng nhập đầy đủ thông tin!', 'error');
        return;
    }

    // Validate secret key
    const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
    if (!/^[A-Z2-7]+=*$/.test(cleanSecret)) {
        showToast('Secret key không hợp lệ! Định dạng Base32.', 'error');
        return;
    }

    try {
        await addAccount(name, secret);
        hideAddForm();
        await renderAccounts();
        showToast('Đã thêm tài khoản!', 'success');
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    }
});

// Camera Events
if (scanCameraBtn) {
    scanCameraBtn.addEventListener('click', async () => {
        cameraContainer.classList.remove('hidden');

        stopCameraFn = await window.QRScanner.scanQRFromCamera(
            cameraVideo,
            (result) => {
                // On success
                if (result && result.secret) {
                    showScanPreview(result);
                    cameraContainer.classList.add('hidden');
                    stopCameraFn = null;
                } else {
                    showToast('QR không hợp lệ', 'error');
                }
            },
            (error) => {
                // On error
                console.error(error);
                cameraContainer.classList.add('hidden');
                showToast('Không thể bật camera: ' + error.message, 'error');
            }
        );
    });
}

if (stopCameraBtn) {
    stopCameraBtn.addEventListener('click', () => {
        if (stopCameraFn) {
            stopCameraFn();
            stopCameraFn = null;
        }
        cameraContainer.classList.add('hidden');
    });
}

// ============================================
// CONFIRM MODAL SYSTEM
// ============================================

const confirmModal = document.getElementById('confirmModal');
const confirmTitle = document.getElementById('confirmTitle');
const confirmMessage = document.getElementById('confirmMessage');
const confirmCancelBtn = document.getElementById('confirmCancelBtn');
const confirmOkBtn = document.getElementById('confirmOkBtn');

function showConfirm(title, message, okText = 'OK', type = 'danger') {
    return new Promise((resolve) => {
        confirmTitle.textContent = title;
        confirmMessage.textContent = message;
        confirmOkBtn.textContent = okText;
        confirmOkBtn.className = `btn btn-${type}`;

        confirmModal.classList.remove('hidden');

        const handleOk = () => {
            cleanup();
            resolve(true);
        };

        const handleCancel = () => {
            cleanup();
            resolve(false);
        };

        const cleanup = () => {
            confirmOkBtn.removeEventListener('click', handleOk);
            confirmCancelBtn.removeEventListener('click', handleCancel);
            confirmModal.classList.add('hidden');
        };

        confirmOkBtn.addEventListener('click', handleOk);
        confirmCancelBtn.addEventListener('click', handleCancel);
    });
}

/**
 * Show Secret Key Modal
 */
function showSecretModal(accountName, secret) {
    // Create modal if not exists
    let secretModal = document.getElementById('secretModal');
    if (!secretModal) {
        secretModal = document.createElement('div');
        secretModal.id = 'secretModal';
        secretModal.className = 'modal hidden';
        secretModal.innerHTML = `
            <div class="modal-content secret-content">
                <div class="secret-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                </div>
                <h3 id="secretAccountName">Secret Key</h3>
                <div class="secret-display">
                    <code id="secretKeyDisplay"></code>
                    <button id="copySecretBtn" class="btn-copy" title="Copy Secret">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                        </svg>
                    </button>
                </div>
                <p class="secret-warning">⚠️ Giữ bí mật! Không chia sẻ mã này.</p>
                <div class="form-actions">
                    <button id="closeSecretBtn" class="btn btn-secondary">Đóng</button>
                </div>
            </div>
        `;
        document.body.appendChild(secretModal);

        // Event listeners
        document.getElementById('closeSecretBtn').addEventListener('click', () => {
            secretModal.classList.add('hidden');
        });

        document.getElementById('copySecretBtn').addEventListener('click', async () => {
            const secretKey = document.getElementById('secretKeyDisplay').textContent;
            const success = await copyToClipboard(secretKey);
            if (success) {
                showToast('Đã copy Secret Key!', 'success');
            }
        });

        secretModal.addEventListener('click', (e) => {
            if (e.target === secretModal) secretModal.classList.add('hidden');
        });
    }

    document.getElementById('secretAccountName').textContent = accountName;
    document.getElementById('secretKeyDisplay').textContent = secret;
    secretModal.classList.remove('hidden');
}

/**
 * Handle Accounts List Clicks
 */
accountsList.addEventListener('click', async (e) => {
    // Handle delete
    const deleteBtn = e.target.closest('.delete-btn');
    if (deleteBtn) {
        const id = deleteBtn.dataset.id;
        const confirmed = await showConfirm(
            'Xóa tài khoản?',
            'Bạn có chắc chắn muốn xóa mã 2FA này không? Hành động này không thể hoàn tác.',
            'Xóa',
            'danger'
        );

        if (confirmed) {
            await deleteAccount(id);
            await renderAccounts();
            showToast('Đã xóa tài khoản', 'success');
        }
        return;
    }

    // Handle reveal secret (read from in-memory map / storage, never from DOM attribute)
    const revealBtn = e.target.closest('.reveal-btn');
    if (revealBtn) {
        const id = revealBtn.dataset.id;
        const accounts = await getAccounts();
        const acc = accounts.find(a => a.id === id);
        if (acc) {
            showSecretModal(acc.name, acc.secret);
        }
        return;
    }

    // Handle copy
    const otpCode = e.target.closest('.otp-code');
    if (otpCode) {
        const code = otpCode.dataset.code;
        const success = await copyToClipboard(code);
        if (success) {
            otpCode.classList.add('copied');
            showToast('Đã copy mã vào bộ nhớ tạm', 'success');
            setTimeout(() => otpCode.classList.remove('copied'), 500);
        }
    }
});

// ============================================
// AUTO-REFRESH
// ============================================

let refreshInterval;

function startAutoRefresh() {
    renderAccounts();

    // Sync to next 30-second boundary for smooth countdown
    const remaining = getRemainingSeconds();

    // Update timer every second (per-account period)
    refreshInterval = setInterval(() => {
        let needRerender = false;

        document.querySelectorAll('.timer-ring').forEach((ring) => {
            const period = parseInt(ring.dataset.period, 10) || 30;
            const currentRemaining = getRemainingSeconds(period);

            const radius = 14;
            const circumference = 2 * Math.PI * radius;
            const progress = (currentRemaining / period) * circumference;

            const progressCircle = ring.querySelector('.progress');
            const timeSpan = ring.querySelector('.time');

            if (progressCircle) {
                progressCircle.style.strokeDashoffset = circumference - progress;
            }
            if (timeSpan) {
                timeSpan.textContent = currentRemaining;
            }

            // Regenerate when this account hits its period boundary
            if (currentRemaining === period) {
                needRerender = true;
            }
        });

        if (needRerender) {
            renderAccounts();
        }
    }, 1000);
}

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    startAutoRefresh();
    loadSettings();
    checkSnipResults(); // Check for snip scan results
});

// Cleanup on popup close
window.addEventListener('unload', () => {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
});

// ============================================
// SYNC & SETTINGS
// ============================================

// Settings Elements
const settingsBtn = document.getElementById('settingsBtn');
const settingsModal = document.getElementById('settingsModal');
const closeSettingsBtn = document.getElementById('closeSettingsBtn');
const saveSettingsBtn = document.getElementById('saveSettingsBtn');
const apiUrlInput = document.getElementById('apiUrl');
const masterPasswordInput = document.getElementById('masterPassword');

// Sync Elements  
const syncBtn = document.getElementById('syncBtn');
const syncModal = document.getElementById('syncModal');
const closeSyncBtn = document.getElementById('closeSyncBtn');
const downloadBtnSync = document.getElementById('downloadBtn');
const uploadBtnSync = document.getElementById('syncUploadBtn');
const syncStatus = document.getElementById('syncStatus');

// Default API URL — để trống, người dùng tự cấu hình trong Settings
const DEFAULT_API_URL = '';

// Settings Storage
let settings = {
    apiUrl: DEFAULT_API_URL,
    masterPassword: ''
};

async function loadSettings() {
    // Dùng chrome.storage.sync để URL tự động sync giữa các máy Chrome
    const stored = await chrome.storage.sync.get(['syncSettings']);
    if (stored.syncSettings && stored.syncSettings.apiUrl) {
        settings.apiUrl = stored.syncSettings.apiUrl;
    }
    apiUrlInput.value = settings.apiUrl;
}

async function saveSettings() {
    settings.apiUrl = apiUrlInput.value.trim();
    settings.masterPassword = masterPasswordInput.value;

    // Lưu vào sync storage - tự động đồng bộ giữa các Chrome accounts
    await chrome.storage.sync.set({ syncSettings: { apiUrl: settings.apiUrl } });
    // Password không lưu vì lý do bảo mật - phải nhập mỗi lần

    settingsModal.classList.add('hidden');
    showToast('Đã lưu cài đặt!', 'success');
}

function showSyncStatus(message, type) {
    syncStatus.textContent = message;
    syncStatus.className = 'sync-status ' + type;
}

// Sync Password Input
const syncPasswordInput = document.getElementById('syncPassword');

// Parse cloud payload supporting both legacy (array) and new ({version, accounts, tombstones}) format
function parseSyncPayload(plaintext) {
    const data = JSON.parse(plaintext);
    if (Array.isArray(data)) {
        return { accounts: data, tombstones: [] };
    }
    return {
        accounts: Array.isArray(data.accounts) ? data.accounts : [],
        tombstones: Array.isArray(data.tombstones) ? data.tombstones : []
    };
}

// Merge local + cloud (accounts + tombstones), apply tombstones, return final state
function mergeSyncState(local, cloud) {
    const tombstones = pruneTombstones(mergeTombstones(local.tombstones, cloud.tombstones));

    const seen = new Set();
    const combined = [];
    let addedFromCloud = 0;

    for (const acc of (local.accounts || [])) {
        const ns = normalizeSecret(acc.secret);
        if (!seen.has(ns)) {
            seen.add(ns);
            combined.push(acc);
        }
    }
    for (const acc of (cloud.accounts || [])) {
        const ns = normalizeSecret(acc.secret);
        if (!seen.has(ns)) {
            seen.add(ns);
            combined.push(acc);
            addedFromCloud++;
        }
    }

    const accounts = applyTombstones(combined, tombstones);
    return { accounts, tombstones, addedFromCloud, removedByTombstone: combined.length - accounts.length };
}

async function uploadToCloud() {
    const password = syncPasswordInput.value;

    if (!settings.apiUrl) {
        showToast('Vui lòng cấu hình API URL!', 'error');
        return;
    }

    if (!password) {
        showToast('Vui lòng nhập Master Password!', 'error');
        syncPasswordInput.focus();
        return;
    }

    showSyncStatus('Đang đồng bộ...', 'loading');
    downloadBtnSync.disabled = true;
    uploadBtnSync.disabled = true;

    try {
        // 1. Fetch existing cloud state first
        let cloudState = { accounts: [], tombstones: [] };
        try {
            const getResponse = await fetch(settings.apiUrl);
            const getResult = await getResponse.json();

            if (getResult.success && getResult.data) {
                const decrypted = await CryptoModule.decrypt(getResult.data, password);
                cloudState = parseSyncPayload(decrypted);
            }
        } catch (fetchErr) {
            console.log('Cloud data fetch failed (might be empty):', fetchErr);
        }

        // 2. Get local state
        const localState = {
            accounts: await getAccounts(),
            tombstones: pruneTombstones(await getTombstones())
        };

        // 3. Merge with tombstone propagation
        const merged = mergeSyncState(localState, cloudState);

        // 4. Encrypt + upload payload v2
        const payload = JSON.stringify({
            version: 2,
            accounts: merged.accounts,
            tombstones: merged.tombstones
        });
        const encrypted = await CryptoModule.encrypt(payload, password);

        const response = await fetch(settings.apiUrl, {
            method: 'POST',
            body: JSON.stringify({
                data: encrypted,
                timestamp: Date.now()
            })
        });

        const result = await response.json();
        if (result.success) {
            // 5. Save merged state locally
            await saveAccounts(merged.accounts);
            await saveTombstones(merged.tombstones);
            await renderAccounts();

            let msg = `✓ Đã đồng bộ ${merged.accounts.length} tài khoản!`;
            if (merged.addedFromCloud > 0) {
                msg += ` (Thêm ${merged.addedFromCloud} từ cloud)`;
            }
            if (merged.removedByTombstone > 0) {
                msg += ` (Xóa ${merged.removedByTombstone} qua tombstone)`;
            }
            showSyncStatus(msg, 'success');
        } else {
            showSyncStatus('✗ Lỗi: ' + result.error, 'error');
        }
    } catch (error) {
        showSyncStatus('✗ ' + error.message, 'error');
    } finally {
        downloadBtnSync.disabled = false;
        uploadBtnSync.disabled = false;
    }
}

async function downloadFromCloud() {
    const password = syncPasswordInput.value;

    if (!settings.apiUrl) {
        showToast('Vui lòng cấu hình API URL!', 'error');
        return;
    }

    if (!password) {
        showToast('Vui lòng nhập Master Password!', 'error');
        syncPasswordInput.focus();
        return;
    }

    showSyncStatus('Đang tải xuống và giải mã...', 'loading');
    downloadBtnSync.disabled = true;
    uploadBtnSync.disabled = true;

    try {
        const response = await fetch(settings.apiUrl);
        const result = await response.json();

        if (!result.success) {
            throw new Error(result.error || 'API Error');
        }

        if (!result.data) {
            showSyncStatus('Không có dữ liệu trên cloud', 'error');
            return;
        }

        // Decrypt cloud payload (supports legacy array format)
        const decrypted = await CryptoModule.decrypt(result.data, password);
        const cloudState = parseSyncPayload(decrypted);

        // Local state
        const localState = {
            accounts: await getAccounts(),
            tombstones: pruneTombstones(await getTombstones())
        };

        // Merge with tombstone propagation
        const merged = mergeSyncState(localState, cloudState);

        // Upload merged payload v2 back to cloud
        const payload = JSON.stringify({
            version: 2,
            accounts: merged.accounts,
            tombstones: merged.tombstones
        });
        const encrypted = await CryptoModule.encrypt(payload, password);

        const uploadResponse = await fetch(settings.apiUrl, {
            method: 'POST',
            body: JSON.stringify({
                data: encrypted,
                timestamp: Date.now()
            })
        });

        const uploadResult = await uploadResponse.json();
        if (!uploadResult.success) {
            throw new Error(uploadResult.error || 'Upload failed');
        }

        // Save merged state locally
        await saveAccounts(merged.accounts);
        await saveTombstones(merged.tombstones);
        await renderAccounts();
        updateEmptyState(merged.accounts.length);

        let msg = `✓ Đã đồng bộ ${merged.accounts.length} tài khoản!`;
        if (merged.addedFromCloud > 0) {
            msg += ` (Thêm ${merged.addedFromCloud} từ cloud)`;
        }
        if (merged.removedByTombstone > 0) {
            msg += ` (Xóa ${merged.removedByTombstone} qua tombstone)`;
        }
        showSyncStatus(msg, 'success');
    } catch (error) {
        showSyncStatus('✗ ' + error.message, 'error');
    } finally {
        downloadBtnSync.disabled = false;
        uploadBtnSync.disabled = false;
    }
}

// Settings Event Listeners
settingsBtn.addEventListener('click', () => {
    settingsModal.classList.remove('hidden');
    masterPasswordInput.value = settings.masterPassword || '';
});

closeSettingsBtn.addEventListener('click', () => {
    settingsModal.classList.add('hidden');
});

saveSettingsBtn.addEventListener('click', saveSettings);

// Sync Event Listeners
syncBtn.addEventListener('click', () => {
    if (!settings.apiUrl) {
        showToast('Vui lòng cấu hình API URL trước!', 'error');
        settingsModal.classList.remove('hidden');
        return;
    }
    syncStatus.textContent = '';
    syncModal.classList.remove('hidden');
});

closeSyncBtn.addEventListener('click', () => {
    syncModal.classList.add('hidden');
});

downloadBtnSync.addEventListener('click', downloadFromCloud);
uploadBtnSync.addEventListener('click', uploadToCloud);

// Search Events
searchInput.addEventListener('input', () => {
    currentPage = 1; // Reset to first page on search
    renderAccounts();
});

clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    currentPage = 1;
    renderAccounts();
    searchInput.focus();
});

// Pagination Events
prevPageBtn.addEventListener('click', () => {
    if (currentPage > 1) {
        currentPage--;
        renderAccounts();
    }
});

nextPageBtn.addEventListener('click', () => {
    const totalPages = Math.ceil(filteredAccounts.length / ITEMS_PER_PAGE);
    if (currentPage < totalPages) {
        currentPage++;
        renderAccounts();
    }
});

// Close modals on backdrop click
settingsModal.addEventListener('click', (e) => {
    if (e.target === settingsModal) settingsModal.classList.add('hidden');
});

syncModal.addEventListener('click', (e) => {
    if (e.target === syncModal) syncModal.classList.add('hidden');
});

// ============================================
// EXPORT / IMPORT FUNCTIONS
// ============================================

const exportBtn = document.getElementById('exportBtn');
const importBtn = document.getElementById('importBtn');
const importFileInput = document.getElementById('importFileInput');

async function exportAccounts() {
    const accounts = await getAccounts();
    if (accounts.length === 0) {
        showToast('Không có tài khoản để export!', 'error');
        return;
    }

    const data = {
        version: '1.0',
        exportDate: new Date().toISOString(),
        accounts: accounts
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `2fa-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);

    showToast(`Đã export ${accounts.length} tài khoản!`, 'success');
}

async function importAccounts(file) {
    try {
        const text = await file.text();
        const data = JSON.parse(text);

        let importedAccounts = [];
        if (Array.isArray(data)) {
            importedAccounts = data;
        } else if (data.accounts && Array.isArray(data.accounts)) {
            importedAccounts = data.accounts;
        } else {
            throw new Error('File không đúng định dạng!');
        }

        // Validate accounts
        for (const acc of importedAccounts) {
            if (!acc.name || !acc.secret) {
                throw new Error('Dữ liệu tài khoản không hợp lệ!');
            }
        }

        const confirmed = await showConfirm(
            'Import tài khoản?',
            `Tìm thấy ${importedAccounts.length} tài khoản. Thêm vào danh sách hiện tại?`,
            'Import',
            'primary'
        );

        if (confirmed) {
            const currentAccounts = await getAccounts();
            const seen = new Set(currentAccounts.map(a => normalizeSecret(a.secret)));
            const merged = [...currentAccounts];

            for (const acc of importedAccounts) {
                const ns = normalizeSecret(acc.secret);
                if (seen.has(ns)) continue;
                seen.add(ns);
                const newAcc = {
                    id: Date.now().toString(36) + Math.random().toString(36).substr(2),
                    name: acc.name,
                    secret: ns,
                    email: acc.email || '',
                    category: acc.category || 'other',
                    createdAt: acc.createdAt || Date.now()
                };
                if (acc.algorithm) newAcc.algorithm = acc.algorithm;
                if (acc.digits && acc.digits !== 6) newAcc.digits = acc.digits;
                if (acc.period && acc.period !== 30) newAcc.period = acc.period;
                merged.push(newAcc);
            }

            await saveAccounts(merged);
            await renderAccounts();
            showToast(`Đã import ${importedAccounts.length} tài khoản!`, 'success');
        }
    } catch (error) {
        showToast('Lỗi: ' + error.message, 'error');
    }
}

exportBtn.addEventListener('click', exportAccounts);
importBtn.addEventListener('click', () => importFileInput.click());
importFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        importAccounts(file);
        importFileInput.value = '';
    }
});

// ============================================
// EDIT ACCOUNT FUNCTIONS
// ============================================

const editModal = document.getElementById('editModal');
const editNameInput = document.getElementById('editName');
const editEmailInput = document.getElementById('editEmail');
const editAccountIdInput = document.getElementById('editAccountId');
const cancelEditBtn = document.getElementById('cancelEditBtn');
const saveEditBtn = document.getElementById('saveEditBtn');

async function updateAccount(id, newName, newEmail, newCategory) {
    const accounts = await getAccounts();
    const index = accounts.findIndex(acc => acc.id === id);
    if (index !== -1) {
        accounts[index].name = newName;
        accounts[index].email = newEmail;
        if (newCategory) accounts[index].category = newCategory;
        await saveAccounts(accounts);
    }
    return accounts;
}

async function showEditModal(accountId) {
    const accounts = await getAccounts();
    const acc = accounts.find(a => a.id === accountId);
    if (!acc) return;

    editAccountIdInput.value = accountId;
    editNameInput.value = acc.name;
    editEmailInput.value = acc.email || '';
    editModal.classList.remove('hidden');
    editNameInput.focus();
}

cancelEditBtn.addEventListener('click', () => {
    editModal.classList.add('hidden');
});

saveEditBtn.addEventListener('click', async () => {
    const id = editAccountIdInput.value;
    const name = editNameInput.value.trim();
    const email = editEmailInput.value.trim();
    const category = document.getElementById('editCategory')?.value || 'other';

    if (!name) {
        showToast('Vui lòng nhập tên dịch vụ!', 'error');
        return;
    }

    await updateAccount(id, name, email, category);
    editModal.classList.add('hidden');
    await renderAccounts();
    showToast('Đã cập nhật tài khoản!', 'success');
});

editModal.addEventListener('click', (e) => {
    if (e.target === editModal) editModal.classList.add('hidden');
});

// Handle Edit button click in accounts list
accountsList.addEventListener('click', async (e) => {
    const editBtn = e.target.closest('.edit-btn');
    if (editBtn) {
        await showEditModal(editBtn.dataset.id);
    }
});

// ============================================
// GENERATE QR FROM SECRET
// ============================================

function generateOtpauthUri(name, secret, issuer = '') {
    const encodedName = encodeURIComponent(issuer ? `${issuer}:${name}` : name);
    const encodedSecret = encodeURIComponent(secret);
    let uri = `otpauth://totp/${encodedName}?secret=${encodedSecret}`;
    if (issuer) {
        uri += `&issuer=${encodeURIComponent(issuer)}`;
    }
    return uri;
}

function showQRModal(accountName, secret) {
    let qrModal = document.getElementById('qrModal');
    if (!qrModal) {
        qrModal = document.createElement('div');
        qrModal.id = 'qrModal';
        qrModal.className = 'modal hidden';
        qrModal.innerHTML = `
            <div class="modal-content qr-content">
                <h3 id="qrAccountName">QR Code</h3>
                <div id="qrCodeDisplay" class="qr-display"></div>
                <p class="qr-hint">Quét mã này bằng ứng dụng Authenticator khác</p>
                <div class="form-actions">
                    <button id="closeQRBtn" class="btn btn-secondary">Đóng</button>
                </div>
            </div>
        `;
        document.body.appendChild(qrModal);

        document.getElementById('closeQRBtn').addEventListener('click', () => {
            qrModal.classList.add('hidden');
        });

        qrModal.addEventListener('click', (e) => {
            if (e.target === qrModal) qrModal.classList.add('hidden');
        });
    }

    const uri = generateOtpauthUri(accountName, secret, accountName);
    document.getElementById('qrAccountName').textContent = accountName;

    // Generate QR code using canvas
    const qrDisplay = document.getElementById('qrCodeDisplay');
    qrDisplay.innerHTML = '';

    // Create QR code using a simple approach (use external library in production)
    const qrApiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(uri)}`;
    const img = document.createElement('img');
    img.src = qrApiUrl;
    img.alt = 'QR Code';
    img.width = 200;
    img.height = 200;
    qrDisplay.appendChild(img);

    qrModal.classList.remove('hidden');
}

// Add QR button to secret modal (modify showSecretModal)
const originalShowSecretModal = showSecretModal;
window.showSecretModalWithQR = function (accountName, secret) {
    // First call original to create/show modal
    originalShowSecretModal(accountName, secret);
    
    // Then add QR button if not exists
    const secretModal = document.getElementById('secretModal');
    if (secretModal) {
        const formActions = secretModal.querySelector('.form-actions');
        if (formActions && !formActions.querySelector('#showQRBtn')) {
            const qrBtn = document.createElement('button');
            qrBtn.id = 'showQRBtn';
            qrBtn.className = 'btn btn-primary';
            qrBtn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px">
                    <rect x="3" y="3" width="7" height="7"/>
                    <rect x="14" y="3" width="7" height="7"/>
                    <rect x="3" y="14" width="7" height="7"/>
                    <rect x="14" y="14" width="7" height="7"/>
                </svg>
                Tạo QR
            `;
            qrBtn.addEventListener('click', () => {
                const name = document.getElementById('secretAccountName').textContent;
                const sec = document.getElementById('secretKeyDisplay').textContent;
                secretModal.classList.add('hidden');
                showQRModal(name, sec);
            });
            formActions.insertBefore(qrBtn, formActions.firstChild);
        }
    }
};

// Override the reveal button handler to use new function
// Replace showSecretModal with showSecretModalWithQR
showSecretModal = showSecretModalWithQR;

