/**
 * QR Code Scanner Module
 * Sử dụng thư viện jsQR để decode QR code từ ảnh
 * jsQR được load từ lib/jsQR.min.js
 */

let jsQRLoaded = false;

async function loadJsQR() {
    if (typeof jsQR !== 'undefined') {
        jsQRLoaded = true;
        return true;
    }
    throw new Error('jsQR library not loaded');
}

/**
 * Decode QR code từ ImageData
 */
async function decodeQR(imageData) {
    await loadJsQR();

    const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'dontInvert',
    });

    return code ? code.data : null;
}

/**
 * Parse otpauth:// URI
 * Format: otpauth://totp/Service:user@email.com?secret=XXX&issuer=Service
 */
function parseOtpAuthUri(uri) {
    if (!uri.startsWith('otpauth://')) {
        return null;
    }

    try {
        const url = new URL(uri);
        const type = url.hostname; // 'totp' or 'hotp'

        if (type !== 'totp') {
            console.warn('Only TOTP is supported, got:', type);
        }

        // Get label (path without leading /)
        let label = decodeURIComponent(url.pathname.slice(1));

        // Extract issuer and account from label
        let issuer = '';
        let account = label;

        if (label.includes(':')) {
            const parts = label.split(':');
            issuer = parts[0];
            account = parts.slice(1).join(':');
        }

        // Get params
        const secret = url.searchParams.get('secret');
        const issuerParam = url.searchParams.get('issuer');
        const digits = url.searchParams.get('digits') || '6';
        const period = url.searchParams.get('period') || '30';
        const algorithm = url.searchParams.get('algorithm') || 'SHA1';

        // Prefer issuer from params if available
        if (issuerParam) {
            issuer = issuerParam;
        }

        // Use issuer as name, fallback to account
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

/**
 * Scan QR code từ File (image)
 */
async function scanQRFromFile(file) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');

        img.onload = async () => {
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0);

            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

            try {
                const result = await decodeQR(imageData);
                if (result) {
                    const parsed = parseOtpAuthUri(result);
                    resolve(parsed || { raw: result });
                } else {
                    reject(new Error('Không tìm thấy QR code trong ảnh'));
                }
            } catch (err) {
                reject(err);
            }
        };

        img.onerror = () => reject(new Error('Không thể đọc file ảnh'));
        img.src = URL.createObjectURL(file);
    });
}

/**
 * Scan QR code từ URL (image URL)
 */
async function scanQRFromUrl(imageUrl) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');

        img.onload = async () => {
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0);

            try {
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const result = await decodeQR(imageData);

                if (result) {
                    const parsed = parseOtpAuthUri(result);
                    resolve(parsed || { raw: result });
                } else {
                    reject(new Error('Không tìm thấy QR code trong ảnh'));
                }
            } catch (err) {
                reject(err);
            }
        };

        img.onerror = () => reject(new Error('Không thể tải ảnh từ URL'));
        img.src = imageUrl;
    });
}

/**
 * Scan QR code từ màn hình trình duyệt (capture visible tab)
 */
async function scanQRFromScreen() {
    await loadJsQR();

    return new Promise((resolve, reject) => {
        // Capture visible tab using Chrome API
        chrome.tabs.captureVisibleTab(null, { format: 'png' }, async (dataUrl) => {
            if (chrome.runtime.lastError) {
                reject(new Error('Không thể chụp màn hình: ' + chrome.runtime.lastError.message));
                return;
            }

            if (!dataUrl) {
                reject(new Error('Không thể chụp màn hình'));
                return;
            }

            // Load image from data URL
            const img = new Image();
            img.onload = async () => {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);

                try {
                    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    const result = await decodeQR(imageData);

                    if (result) {
                        const parsed = parseOtpAuthUri(result);
                        resolve(parsed || { raw: result });
                    } else {
                        // Try scanning smaller regions (QR might be small)
                        const smallerResult = await scanImageRegions(imageData);
                        if (smallerResult) {
                            const parsed = parseOtpAuthUri(smallerResult);
                            resolve(parsed || { raw: smallerResult });
                        } else {
                            reject(new Error('Không tìm thấy QR code trên màn hình'));
                        }
                    }
                } catch (err) {
                    reject(err);
                }
            };

            img.onerror = () => reject(new Error('Không thể xử lý ảnh chụp màn hình'));
            img.src = dataUrl;
        });
    });
}

/**
 * Scan image in smaller regions to find QR code
 */
async function scanImageRegions(fullImageData) {
    const { width, height, data } = fullImageData;

    // Try different region sizes
    const regionSizes = [
        { w: Math.floor(width / 2), h: Math.floor(height / 2) },
        { w: Math.floor(width / 3), h: Math.floor(height / 3) },
    ];

    for (const size of regionSizes) {
        // Scan 9 regions (3x3 grid)
        for (let row = 0; row < 3; row++) {
            for (let col = 0; col < 3; col++) {
                const startX = Math.floor(col * (width - size.w) / 2);
                const startY = Math.floor(row * (height - size.h) / 2);

                // Extract region
                const regionData = extractRegion(fullImageData, startX, startY, size.w, size.h);

                const result = jsQR(regionData.data, regionData.width, regionData.height, {
                    inversionAttempts: 'attemptBoth',
                });

                if (result) {
                    return result.data;
                }
            }
        }
    }

    return null;
}

/**
 * Extract a region from ImageData
 */
function extractRegion(imageData, startX, startY, regionWidth, regionHeight) {
    const { width, data } = imageData;
    const regionData = new Uint8ClampedArray(regionWidth * regionHeight * 4);

    for (let y = 0; y < regionHeight; y++) {
        for (let x = 0; x < regionWidth; x++) {
            const srcIdx = ((startY + y) * width + (startX + x)) * 4;
            const dstIdx = (y * regionWidth + x) * 4;
            regionData[dstIdx] = data[srcIdx];
            regionData[dstIdx + 1] = data[srcIdx + 1];
            regionData[dstIdx + 2] = data[srcIdx + 2];
            regionData[dstIdx + 3] = data[srcIdx + 3];
        }
    }

    return {
        data: regionData,
        width: regionWidth,
        height: regionHeight,
    };
}

/**
 * Scan QR code từ Camera
 * @param {HTMLVideoElement} videoElement
 * @param {Function} onResult Callback khi tìm thấy QR
 * @param {Function} onError Callback khi lỗi
 */
async function scanQRFromCamera(videoElement, onResult, onError) {
    await loadJsQR();

    // Check secure context
    if (window.isSecureContext === false) {
        onError(new Error('Camera chỉ hoạt động trên HTTPS hoặc Localhost (Secure Context).'));
        return () => { };
    }

    // Check API support
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        onError(new Error('Trình duyệt không hỗ trợ truy cập Camera.'));
        return () => { };
    }

    let stream = null;
    let scanning = true;

    try {
        stream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: 'environment' }
        });

        videoElement.srcObject = stream;
        videoElement.setAttribute('playsinline', true);

        await videoElement.play();

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');

        const scanLoop = () => {
            if (!scanning) return;

            if (videoElement.readyState === videoElement.HAVE_ENOUGH_DATA) {
                canvas.width = videoElement.videoWidth;
                canvas.height = videoElement.videoHeight;
                ctx.drawImage(videoElement, 0, 0, canvas.width, canvas.height);

                try {
                    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    const code = jsQR(imageData.data, imageData.width, imageData.height, {
                        inversionAttempts: 'dontInvert',
                    });

                    if (code) {
                        const parsed = parseOtpAuthUri(code.data);
                        scanning = false;
                        stopCamera(stream);
                        onResult(parsed || { raw: code.data });
                        return;
                    }
                } catch (e) {
                    console.error('Frame process error:', e);
                }
            }
            requestAnimationFrame(scanLoop);
        };

        requestAnimationFrame(scanLoop);

        return () => {
            scanning = false;
            stopCamera(stream);
        };

    } catch (err) {
        if (stream) stopCamera(stream);

        let msg = err.message;
        if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
            msg = 'Bạn đã từ chối quyền truy cập Camera.';
        } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
            msg = 'Không tìm thấy Camera trên thiết bị.';
        }

        onError(new Error(msg));
        return () => { };
    }
}

function stopCamera(stream) {
    if (stream) {
        stream.getTracks().forEach(track => track.stop());
    }
}

// Export functions
window.QRScanner = {
    loadJsQR,
    decodeQR,
    parseOtpAuthUri,
    scanQRFromFile,
    scanQRFromUrl,
    scanQRFromScreen,
    scanQRFromCamera
};

