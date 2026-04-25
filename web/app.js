/**
 * 2FA Authenticator - Web App Version
 * TOTP (Time-based One-Time Password) Generator
 */

// ============================================
// TOTP ALGORITHM (RFC 6238)
// ============================================

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

function normalizeAlgorithm(algo) {
    if (!algo) return 'SHA-1';
    const a = String(algo).toUpperCase().replace(/-/g, '');
    if (a === 'SHA1') return 'SHA-1';
    if (a === 'SHA256') return 'SHA-256';
    if (a === 'SHA512') return 'SHA-512';
    return 'SHA-1';
}

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

async function generateTOTP(secret, options = {}) {
    const period = options.period || 30;
    const digits = options.digits || 6;
    const algorithm = normalizeAlgorithm(options.algorithm);

    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 1000 / period);

    const timeBuffer = new ArrayBuffer(8);
    const view = new DataView(timeBuffer);
    view.setUint32(4, time, false);

    const hash = await hmac(key, new Uint8Array(timeBuffer), algorithm);

    const offset = hash[hash.length - 1] & 0x0f;
    const code = (
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff)
    ) % Math.pow(10, digits);

    return code.toString().padStart(digits, '0');
}

function getRemainingSeconds(timeStep = 30) {
    return timeStep - (Math.floor(Date.now() / 1000) % timeStep);
}

function formatOtpCode(code) {
    if (code.length <= 4) return code;
    const mid = Math.ceil(code.length / 2);
    return code.slice(0, mid) + ' ' + code.slice(mid);
}

function normalizeSecret(secret) {
    return String(secret).replace(/\s+/g, '').toUpperCase();
}

// ============================================
// STORAGE MANAGEMENT (localStorage)
// ============================================

function getAccounts() {
    try {
        const data = localStorage.getItem('2fa_accounts');
        return data ? JSON.parse(data) : [];
    } catch {
        return [];
    }
}

function saveAccounts(accounts) {
    localStorage.setItem('2fa_accounts', JSON.stringify(accounts));
}

function addAccount(name, secret, email = '', extra = {}) {
    const accounts = getAccounts();
    const id = Date.now().toString(36) + Math.random().toString(36).substr(2);
    const newAccount = {
        id,
        name,
        secret: normalizeSecret(secret),
        email: email || '',
        createdAt: Date.now()
    };
    if (extra.algorithm) newAccount.algorithm = extra.algorithm;
    if (extra.digits && extra.digits !== 6) newAccount.digits = extra.digits;
    if (extra.period && extra.period !== 30) newAccount.period = extra.period;
    accounts.push(newAccount);
    saveAccounts(accounts);
    return accounts;
}

function deleteAccount(id) {
    const accounts = getAccounts();
    const acc = accounts.find(a => a.id === id);
    if (acc) {
        const tombstones = pruneTombstones(getTombstones());
        const ns = normalizeSecret(acc.secret);
        const filtered = tombstones.filter(t => t.secret !== ns);
        filtered.push({ secret: ns, deletedAt: Date.now() });
        saveTombstones(filtered);
    }
    const remaining = accounts.filter(a => a.id !== id);
    saveAccounts(remaining);
    return remaining;
}

// ============================================
// TOMBSTONE MANAGEMENT (delete propagation)
// ============================================

const TOMBSTONE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function getTombstones() {
    try {
        const data = localStorage.getItem('2fa_tombstones');
        const parsed = data ? JSON.parse(data) : [];
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function saveTombstones(tombstones) {
    localStorage.setItem('2fa_tombstones', JSON.stringify(tombstones));
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

function applyTombstones(accounts, tombstones) {
    const tombMap = new Map(tombstones.map(t => [t.secret, t.deletedAt]));
    return accounts.filter(acc => {
        const ts = tombMap.get(normalizeSecret(acc.secret));
        if (!ts) return true;
        return (acc.createdAt || 0) > ts;
    });
}

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

function mergeSyncState(local, cloud) {
    const tombstones = pruneTombstones(mergeTombstones(local.tombstones, cloud.tombstones));
    const seen = new Set();
    const combined = [];
    let addedFromCloud = 0;

    for (const acc of (local.accounts || [])) {
        const ns = normalizeSecret(acc.secret);
        if (!seen.has(ns)) { seen.add(ns); combined.push(acc); }
    }
    for (const acc of (cloud.accounts || [])) {
        const ns = normalizeSecret(acc.secret);
        if (!seen.has(ns)) { seen.add(ns); combined.push(acc); addedFromCloud++; }
    }

    const accounts = applyTombstones(combined, tombstones);
    return { accounts, tombstones, addedFromCloud, removedByTombstone: combined.length - accounts.length };
}

// ============================================
// SETTINGS (localStorage)
// ============================================

// Default API URL — để trống, người dùng tự cấu hình trong Settings
const DEFAULT_API_URL = '';

let settings = {
    apiUrl: DEFAULT_API_URL,
    masterPassword: ''
};

function loadSettings() {
    try {
        const data = localStorage.getItem('2fa_settings');
        if (data) {
            const stored = JSON.parse(data);
            settings.apiUrl = stored.apiUrl || DEFAULT_API_URL;
        }
    } catch { }
    apiUrlInput.value = settings.apiUrl;
}

function saveSettings() {
    settings.apiUrl = apiUrlInput.value.trim();
    settings.masterPassword = masterPasswordInput.value;

    localStorage.setItem('2fa_settings', JSON.stringify({ apiUrl: settings.apiUrl }));

    settingsModal.classList.add('hidden');
    showToast('Đã lưu cài đặt!', 'success');
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

// Search & Pagination
const searchInput = document.getElementById('searchInput');
const clearSearchBtn = document.getElementById('clearSearchBtn');
const paginationControls = document.getElementById('paginationControls');
const prevPageBtn = document.getElementById('prevPageBtn');
const nextPageBtn = document.getElementById('nextPageBtn');
const pageInfo = document.getElementById('pageInfo');

// Settings & Sync
const settingsBtn = document.getElementById('settingsBtn');
const settingsModal = document.getElementById('settingsModal');
const closeSettingsBtn = document.getElementById('closeSettingsBtn');
const saveSettingsBtn = document.getElementById('saveSettingsBtn');
const apiUrlInput = document.getElementById('apiUrl');
const masterPasswordInput = document.getElementById('masterPassword');

const syncBtn = document.getElementById('syncBtn');
const syncModal = document.getElementById('syncModal');
const closeSyncBtn = document.getElementById('closeSyncBtn');
const downloadBtnSync = document.getElementById('downloadBtn');
const uploadBtnSync = document.getElementById('syncUploadBtn');
const syncStatus = document.getElementById('syncStatus');
const syncPasswordInput = document.getElementById('syncPassword');

// Confirm Modal
const confirmModal = document.getElementById('confirmModal');
const confirmTitle = document.getElementById('confirmTitle');
const confirmMessage = document.getElementById('confirmMessage');
const confirmCancelBtn = document.getElementById('confirmCancelBtn');
const confirmOkBtn = document.getElementById('confirmOkBtn');

// Pagination State
let currentPage = 1;
const ITEMS_PER_PAGE = 5;
let filteredAccounts = [];
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

function updateEmptyState(count) {
    if (count === 0) {
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

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Current service filter (null = all, else lowercase service name)
let currentServiceFilter = null;

function renderServiceFilter(accounts) {
    const container = document.getElementById('serviceFilter');
    if (!container) return;

    if (!accounts || accounts.length === 0) {
        container.classList.add('hidden');
        container.innerHTML = '';
        return;
    }

    const groups = new Map();
    for (const acc of accounts) {
        const name = (acc.name || '').trim();
        if (!name) continue;
        const key = name.toLowerCase();
        const existing = groups.get(key);
        if (existing) existing.count++;
        else groups.set(key, { display: name, count: 1 });
    }

    if (currentServiceFilter && !groups.has(currentServiceFilter)) {
        currentServiceFilter = null;
    }

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
    const accounts = getAccounts();
    const query = searchInput.value.trim().toLowerCase();

    renderServiceFilter(accounts);

    filteredAccounts = accounts.filter(acc => {
        if (currentServiceFilter && (acc.name || '').toLowerCase() !== currentServiceFilter) {
            return false;
        }
        if (!query) return true;
        return acc.name.toLowerCase().includes(query) ||
            (acc.email && acc.email.toLowerCase().includes(query));
    });

    const totalPages = Math.ceil(filteredAccounts.length / ITEMS_PER_PAGE) || 1;
    if (currentPage > totalPages) currentPage = 1;

    if (query) {
        clearSearchBtn.classList.remove('hidden');
    } else {
        clearSearchBtn.classList.add('hidden');
    }

    if (filteredAccounts.length === 0) {
        if (query) {
            accountsList.innerHTML = `<div class="empty-state"><p>Không tìm thấy kết quả cho "${escapeHtml(query)}"</p></div>`;
            accountsList.classList.remove('hidden');
            paginationControls.classList.add('hidden');
        } else {
            updateEmptyState(0);
            paginationControls.classList.add('hidden');
        }
        return;
    }

    updateEmptyState(filteredAccounts.length);

    const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
    const paginatedItems = filteredAccounts.slice(startIndex, startIndex + ITEMS_PER_PAGE);

    const html = await Promise.all(paginatedItems.map(async (acc) => {
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
                <path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
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

    if (filteredAccounts.length > ITEMS_PER_PAGE) {
        paginationControls.classList.remove('hidden');
        pageInfo.textContent = `Trang ${currentPage} / ${totalPages}`;
        prevPageBtn.disabled = currentPage === 1;
        nextPageBtn.disabled = currentPage === totalPages;
    } else {
        paginationControls.classList.add('hidden');
    }
}

// ============================================
// TOAST NOTIFICATION
// ============================================

let toastTimeout = null;

function showToast(message, type = 'info') {
    const existingToast = document.querySelector('.toast');
    if (existingToast) existingToast.remove();
    if (toastTimeout) clearTimeout(toastTimeout);

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ'}</span>
        <span class="toast-message">${message}</span>
    `;
    document.body.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add('show'));

    toastTimeout = setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

async function copyToClipboard(code) {
    try {
        await navigator.clipboard.writeText(code);
        return true;
    } catch {
        return false;
    }
}

// ============================================
// CONFIRM MODAL
// ============================================

function showConfirm(title, message, okText = 'OK', type = 'danger') {
    return new Promise((resolve) => {
        confirmTitle.textContent = title;
        confirmMessage.textContent = message;
        confirmOkBtn.textContent = okText;
        confirmOkBtn.className = `btn btn-${type}`;
        confirmModal.classList.remove('hidden');

        const handleOk = () => { cleanup(); resolve(true); };
        const handleCancel = () => { cleanup(); resolve(false); };
        const cleanup = () => {
            confirmOkBtn.removeEventListener('click', handleOk);
            confirmCancelBtn.removeEventListener('click', handleCancel);
            confirmModal.classList.add('hidden');
        };

        confirmOkBtn.addEventListener('click', handleOk);
        confirmCancelBtn.addEventListener('click', handleCancel);
    });
}

// ============================================
// QR SCANNER
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
        } else {
            showToast('Không tìm thấy mã 2FA trong QR', 'error');
        }
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    } finally {
        scanNowBtn.classList.remove('loading');
    }
}

// ============================================
// SYNC FUNCTIONS
// ============================================

function showSyncStatus(message, type) {
    syncStatus.textContent = message;
    syncStatus.className = 'sync-status ' + type;
}

async function syncWithCloud(password) {
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

    const localState = {
        accounts: getAccounts(),
        tombstones: pruneTombstones(getTombstones())
    };

    const merged = mergeSyncState(localState, cloudState);

    const payload = JSON.stringify({
        version: 2,
        accounts: merged.accounts,
        tombstones: merged.tombstones
    });
    const encrypted = await CryptoModule.encrypt(payload, password);

    const response = await fetch(settings.apiUrl, {
        method: 'POST',
        body: JSON.stringify({ data: encrypted, timestamp: Date.now() })
    });
    const result = await response.json();
    if (!result.success) {
        throw new Error(result.error || 'Upload failed');
    }

    saveAccounts(merged.accounts);
    saveTombstones(merged.tombstones);
    renderAccounts();

    return merged;
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
        const merged = await syncWithCloud(password);
        let msg = `✓ Đã đồng bộ ${merged.accounts.length} tài khoản!`;
        if (merged.addedFromCloud > 0) msg += ` (Thêm ${merged.addedFromCloud} từ cloud)`;
        if (merged.removedByTombstone > 0) msg += ` (Xóa ${merged.removedByTombstone} qua tombstone)`;
        showSyncStatus(msg, 'success');
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

    showSyncStatus('Đang tải xuống và đồng bộ...', 'loading');
    downloadBtnSync.disabled = true;
    uploadBtnSync.disabled = true;

    try {
        // First check if cloud has data
        const response = await fetch(settings.apiUrl);
        const result = await response.json();
        if (!result.success) throw new Error(result.error || 'API Error');
        if (!result.data) {
            showSyncStatus('Không có dữ liệu trên cloud', 'error');
            return;
        }

        const merged = await syncWithCloud(password);
        let msg = `✓ Đã đồng bộ ${merged.accounts.length} tài khoản!`;
        if (merged.addedFromCloud > 0) msg += ` (Thêm ${merged.addedFromCloud} từ cloud)`;
        if (merged.removedByTombstone > 0) msg += ` (Xóa ${merged.removedByTombstone} qua tombstone)`;
        showSyncStatus(msg, 'success');
    } catch (error) {
        showSyncStatus('✗ ' + error.message, 'error');
    } finally {
        downloadBtnSync.disabled = false;
        uploadBtnSync.disabled = false;
    }
}

// ============================================
// EVENT LISTENERS
// ============================================

addBtn.addEventListener('click', showAddForm);
addFirstBtn.addEventListener('click', showAddForm);
cancelBtn.addEventListener('click', hideAddForm);

scanBtn.addEventListener('click', showScanForm);
cancelScanBtn.addEventListener('click', hideScanForm);

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

scanNowBtn.addEventListener('click', scanQR);

// Hide scan from screen for web (requires extension permission)
if (scanScreenBtn) {
    scanScreenBtn.style.display = 'none';
}

uploadBtn.addEventListener('click', () => qrFileInput.click());

qrFileInput.addEventListener('change', () => {
    const file = qrFileInput.files[0];
    if (file) {
        fileName.textContent = file.name;
        qrUrl.value = '';
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
        addAccount(scannedData.name, scannedData.secret, scannedData.account || '', {
            algorithm: normalizeAlgorithm(scannedData.algorithm),
            digits: scannedData.digits,
            period: scannedData.period
        });
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

    const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
    if (!/^[A-Z2-7]+=*$/.test(cleanSecret)) {
        showToast('Secret key không hợp lệ! Định dạng Base32.', 'error');
        return;
    }

    try {
        addAccount(name, secret);
        hideAddForm();
        await renderAccounts();
        showToast('Đã thêm tài khoản!', 'success');
    } catch (err) {
        showToast('Lỗi: ' + err.message, 'error');
    }
});

accountsList.addEventListener('click', async (e) => {
    // Handle delete
    const deleteBtn = e.target.closest('.delete-btn');
    if (deleteBtn) {
        const id = deleteBtn.dataset.id;
        const confirmed = await showConfirm(
            'Xóa tài khoản?',
            'Bạn có chắc chắn muốn xóa mã 2FA này không?',
            'Xóa',
            'danger'
        );

        if (confirmed) {
            deleteAccount(id);
            await renderAccounts();
            showToast('Đã xóa tài khoản', 'success');
        }
        return;
    }

    // Handle reveal secret (look up by id from storage; no secret in DOM attribute)
    const revealBtn = e.target.closest('.reveal-btn');
    if (revealBtn) {
        const accounts = getAccounts();
        const acc = accounts.find(a => a.id === revealBtn.dataset.id);
        if (acc) {
            showSecretModal(acc.name, acc.secret);
        }
        return;
    }

    // Handle edit
    const editBtn = e.target.closest('.edit-btn');
    if (editBtn) {
        const accounts = getAccounts();
        const acc = accounts.find(a => a.id === editBtn.dataset.id);
        if (acc) {
            showEditModal(acc);
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

/**
 * Show Secret Key Modal
 */
function showSecretModal(accountName, secret) {
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
 * Show Edit Modal
 */
function showEditModal(account) {
    let editModal = document.getElementById('editModal');
    if (!editModal) {
        editModal = document.createElement('div');
        editModal.id = 'editModal';
        editModal.className = 'modal hidden';
        editModal.innerHTML = `
            <div class="modal-content">
                <h3>✏️ Chỉnh sửa tài khoản</h3>
                <div class="form-group">
                    <label for="editName">Tên dịch vụ</label>
                    <input type="text" id="editName" placeholder="Tên dịch vụ">
                </div>
                <div class="form-group">
                    <label for="editEmail">Email/Tài khoản</label>
                    <input type="text" id="editEmail" placeholder="Email hoặc username">
                </div>
                <input type="hidden" id="editAccountId">
                <div class="form-actions">
                    <button id="cancelEditBtn" class="btn btn-secondary">Hủy</button>
                    <button id="saveEditBtn" class="btn btn-primary">Lưu</button>
                </div>
            </div>
        `;
        document.body.appendChild(editModal);

        document.getElementById('cancelEditBtn').addEventListener('click', () => {
            editModal.classList.add('hidden');
        });

        document.getElementById('saveEditBtn').addEventListener('click', async () => {
            const id = document.getElementById('editAccountId').value;
            const newName = document.getElementById('editName').value.trim();
            const newEmail = document.getElementById('editEmail').value.trim();

            if (!newName) {
                showToast('Vui lòng nhập tên dịch vụ!', 'error');
                return;
            }

            const accounts = getAccounts();
            const accIndex = accounts.findIndex(a => a.id === id);
            if (accIndex !== -1) {
                accounts[accIndex].name = newName;
                accounts[accIndex].email = newEmail;
                saveAccounts(accounts);
                await renderAccounts();
                showToast('Đã cập nhật tài khoản!', 'success');
            }
            editModal.classList.add('hidden');
        });

        editModal.addEventListener('click', (e) => {
            if (e.target === editModal) editModal.classList.add('hidden');
        });
    }

    document.getElementById('editAccountId').value = account.id;
    document.getElementById('editName').value = account.name;
    document.getElementById('editEmail').value = account.email || '';
    editModal.classList.remove('hidden');
}

// Search & Pagination
searchInput.addEventListener('input', () => {
    currentPage = 1;
    renderAccounts();
});

clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    currentPage = 1;
    renderAccounts();
    searchInput.focus();
});

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

// Settings
settingsBtn.addEventListener('click', () => {
    settingsModal.classList.remove('hidden');
    masterPasswordInput.value = settings.masterPassword || '';
});

closeSettingsBtn.addEventListener('click', () => settingsModal.classList.add('hidden'));
saveSettingsBtn.addEventListener('click', saveSettings);

// Sync
syncBtn.addEventListener('click', () => {
    if (!settings.apiUrl) {
        showToast('Vui lòng cấu hình API URL trước!', 'error');
        settingsModal.classList.remove('hidden');
        return;
    }
    syncStatus.textContent = '';
    syncModal.classList.remove('hidden');
});

closeSyncBtn.addEventListener('click', () => syncModal.classList.add('hidden'));
downloadBtnSync.addEventListener('click', downloadFromCloud);
uploadBtnSync.addEventListener('click', uploadToCloud);

// Modal backdrop click
settingsModal.addEventListener('click', (e) => {
    if (e.target === settingsModal) settingsModal.classList.add('hidden');
});

syncModal.addEventListener('click', (e) => {
    if (e.target === syncModal) syncModal.classList.add('hidden');
});

confirmModal.addEventListener('click', (e) => {
    if (e.target === confirmModal) confirmModal.classList.add('hidden');
});

// ============================================
// AUTO-REFRESH
// ============================================

let refreshInterval;

function startAutoRefresh() {
    renderAccounts();

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

            if (progressCircle) progressCircle.style.strokeDashoffset = circumference - progress;
            if (timeSpan) timeSpan.textContent = currentRemaining;

            if (currentRemaining === period) needRerender = true;
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
});

window.addEventListener('unload', () => {
    if (refreshInterval) clearInterval(refreshInterval);
});
