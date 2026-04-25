/**
 * Background Service Worker for 2FA Authenticator
 * Handles snipping capture and QR decoding
 */

// Import jsQR for decoding
importScripts('lib/jsQR.min.js');

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SNIP_SELECTION') {
        handleSnipCapture(message.rect, message.devicePixelRatio, sender.tab.id);
    } else if (message.type === 'SNIP_CANCELLED') {
        chrome.storage.session.set({ snipError: 'Đã hủy chọn vùng' });
    }
    return true;
});

async function handleSnipCapture(rect, devicePixelRatio, tabId) {
    try {
        // Capture the visible tab
        const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: 'png' });

        // Load and crop image
        const result = await decodeQRFromRegion(dataUrl, {
            x: Math.round(rect.x * devicePixelRatio),
            y: Math.round(rect.y * devicePixelRatio),
            width: Math.round(rect.width * devicePixelRatio),
            height: Math.round(rect.height * devicePixelRatio)
        });

        if (result && result.secret) {
            chrome.storage.session.set({ snipResult: result });
        } else if (result && result.raw) {
            chrome.storage.session.set({ snipError: 'QR không chứa thông tin 2FA' });
        } else {
            chrome.storage.session.set({ snipError: 'Không tìm thấy QR trong vùng đã chọn' });
        }
    } catch (error) {
        chrome.storage.session.set({ snipError: error.message });
    }
}

async function decodeQRFromRegion(dataUrl, rect) {
    return new Promise((resolve, reject) => {
        // Create offscreen canvas
        const img = new Image();
        img.onload = () => {
            const canvas = new OffscreenCanvas(rect.width, rect.height);
            const ctx = canvas.getContext('2d');

            // Draw cropped region
            ctx.drawImage(
                img,
                rect.x, rect.y,
                rect.width, rect.height,
                0, 0,
                rect.width, rect.height
            );

            const imageData = ctx.getImageData(0, 0, rect.width, rect.height);

            // Try to decode
            const code = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: 'attemptBoth',
            });

            if (code && code.data.startsWith('otpauth://')) {
                const parsed = parseOtpAuthUri(code.data);
                resolve(parsed || { raw: code.data });
            } else {
                // Try scaling up for small QR codes
                const scaledCanvas = new OffscreenCanvas(rect.width * 2, rect.height * 2);
                const scaledCtx = scaledCanvas.getContext('2d');
                scaledCtx.imageSmoothingEnabled = false;
                scaledCtx.drawImage(canvas, 0, 0, rect.width * 2, rect.height * 2);

                const scaledData = scaledCtx.getImageData(0, 0, rect.width * 2, rect.height * 2);
                const scaledCode = jsQR(scaledData.data, scaledData.width, scaledData.height, {
                    inversionAttempts: 'attemptBoth',
                });

                if (scaledCode && scaledCode.data.startsWith('otpauth://')) {
                    const parsed = parseOtpAuthUri(scaledCode.data);
                    resolve(parsed || { raw: scaledCode.data });
                } else {
                    resolve(null);
                }
            }
        };

        img.onerror = () => reject(new Error('Không thể xử lý ảnh'));
        img.src = dataUrl;
    });
}

/**
 * Parse otpauth:// URI
 */
function parseOtpAuthUri(uri) {
    if (!uri.startsWith('otpauth://')) {
        return null;
    }

    try {
        const url = new URL(uri);
        const type = url.hostname;

        let label = decodeURIComponent(url.pathname.slice(1));
        let issuer = '';
        let account = label;

        if (label.includes(':')) {
            const parts = label.split(':');
            issuer = parts[0];
            account = parts.slice(1).join(':');
        }

        const secret = url.searchParams.get('secret');
        const issuerParam = url.searchParams.get('issuer');
        const digits = url.searchParams.get('digits') || '6';
        const period = url.searchParams.get('period') || '30';
        const algorithm = url.searchParams.get('algorithm') || 'SHA1';

        if (issuerParam) {
            issuer = issuerParam;
        }

        const name = issuer || account || 'Unknown';

        return {
            type,
            name: name.trim(),
            account: account.trim(),
            secret: secret ? secret.toUpperCase() : null,
            digits: parseInt(digits, 10),
            period: parseInt(period, 10),
            algorithm: algorithm.toUpperCase(),
        };
    } catch (err) {
        console.error('Failed to parse otpauth URI:', err);
        return null;
    }
}
