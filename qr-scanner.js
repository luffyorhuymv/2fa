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

    // Try with attemptBoth to handle both normal and inverted QR codes
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'attemptBoth',
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
 * Enhance image for better QR detection
 * Applies grayscale conversion and contrast enhancement
 */
function enhanceImageForQR(imageData) {
    const data = imageData.data;
    const enhanced = new Uint8ClampedArray(data.length);

    for (let i = 0; i < data.length; i += 4) {
        // Convert to grayscale
        const gray = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];

        // Enhance contrast (stretch to 0-255)
        const contrast = gray < 128 ? 0 : 255;

        enhanced[i] = contrast;
        enhanced[i + 1] = contrast;
        enhanced[i + 2] = contrast;
        enhanced[i + 3] = 255;
    }

    return new ImageData(enhanced, imageData.width, imageData.height);
}

/**
 * Scale up image for detecting small QR codes
 */
function scaleImageData(imageData, scale) {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    // Create temporary canvas with original image
    const tempCanvas = document.createElement('canvas');
    const tempCtx = tempCanvas.getContext('2d');
    tempCanvas.width = imageData.width;
    tempCanvas.height = imageData.height;
    tempCtx.putImageData(imageData, 0, 0);

    // Scale up
    canvas.width = imageData.width * scale;
    canvas.height = imageData.height * scale;
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(tempCanvas, 0, 0, canvas.width, canvas.height);

    return ctx.getImageData(0, 0, canvas.width, canvas.height);
}

/**
 * Scan QR code từ màn hình trình duyệt (capture visible tab)
 * Enhanced with multiple detection techniques
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

                    // Pass 1: Try original image
                    let result = await decodeQR(imageData);
                    if (result && result.startsWith('otpauth://')) {
                        const parsed = parseOtpAuthUri(result);
                        resolve(parsed || { raw: result });
                        return;
                    }

                    // Pass 2: Try enhanced (high contrast) image
                    const enhancedData = enhanceImageForQR(imageData);
                    result = await decodeQR(enhancedData);
                    if (result && result.startsWith('otpauth://')) {
                        const parsed = parseOtpAuthUri(result);
                        resolve(parsed || { raw: result });
                        return;
                    }

                    // Pass 3: Try scaled up image (2x) for small QR codes
                    const scaledData = scaleImageData(imageData, 2);
                    result = await decodeQR(scaledData);
                    if (result && result.startsWith('otpauth://')) {
                        const parsed = parseOtpAuthUri(result);
                        resolve(parsed || { raw: result });
                        return;
                    }

                    // Pass 4: Scan regions on original image
                    result = await scanImageRegions(imageData);
                    if (result && result.startsWith('otpauth://')) {
                        const parsed = parseOtpAuthUri(result);
                        resolve(parsed || { raw: result });
                        return;
                    }

                    // Pass 5: Scan regions on enhanced image
                    result = await scanImageRegions(enhancedData);
                    if (result && result.startsWith('otpauth://')) {
                        const parsed = parseOtpAuthUri(result);
                        resolve(parsed || { raw: result });
                        return;
                    }

                    // Pass 6: Scan regions on scaled image
                    result = await scanImageRegions(scaledData);
                    if (result && result.startsWith('otpauth://')) {
                        const parsed = parseOtpAuthUri(result);
                        resolve(parsed || { raw: result });
                        return;
                    }

                    reject(new Error('Không tìm thấy QR code trên màn hình'));
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
 * Enhanced with more region sizes and overlapping grid for better detection
 */
async function scanImageRegions(fullImageData) {
    const { width, height } = fullImageData;

    // Try different region sizes - from large to small
    const regionSizes = [
        { w: Math.floor(width * 0.75), h: Math.floor(height * 0.75) },
        { w: Math.floor(width / 2), h: Math.floor(height / 2) },
        { w: Math.floor(width / 3), h: Math.floor(height / 3) },
        { w: Math.floor(width / 4), h: Math.floor(height / 4) },
    ];

    for (const size of regionSizes) {
        // Calculate step for overlapping regions (50% overlap)
        const stepX = Math.max(1, Math.floor(size.w / 2));
        const stepY = Math.max(1, Math.floor(size.h / 2));

        // Scan with overlapping grid
        for (let startY = 0; startY <= height - size.h; startY += stepY) {
            for (let startX = 0; startX <= width - size.w; startX += stepX) {
                // Extract region
                const regionData = extractRegion(fullImageData, startX, startY, size.w, size.h);

                const result = jsQR(regionData.data, regionData.width, regionData.height, {
                    inversionAttempts: 'attemptBoth',
                });

                if (result && result.data.startsWith('otpauth://')) {
                    return result.data;
                }
            }
        }
    }

    // Final pass: try entire image with attemptBoth again
    const finalResult = jsQR(fullImageData.data, width, height, {
        inversionAttempts: 'attemptBoth',
    });

    return finalResult ? finalResult.data : null;
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
                        inversionAttempts: 'attemptBoth',
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

