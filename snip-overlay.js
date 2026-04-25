/**
 * Snip Overlay - Content Script
 * Cho phép người dùng chọn vùng trên màn hình để quét QR code
 */

(function () {
    // Prevent multiple injections
    if (window.__2faSnipOverlayInjected) {
        window.postMessage({ type: '2FA_SNIP_READY' }, '*');
        return;
    }
    window.__2faSnipOverlayInjected = true;

    let overlay = null;
    let selection = null;
    let startX = 0;
    let startY = 0;
    let isSelecting = false;

    function createOverlay() {
        // Create dark overlay
        overlay = document.createElement('div');
        overlay.id = '2fa-snip-overlay';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.5);
            z-index: 2147483647;
            cursor: crosshair;
        `;

        // Create selection box
        selection = document.createElement('div');
        selection.id = '2fa-snip-selection';
        selection.style.cssText = `
            position: fixed;
            border: 2px dashed #00d4ff;
            background: rgba(0, 212, 255, 0.1);
            z-index: 2147483647;
            display: none;
            pointer-events: none;
        `;

        // Create instruction text
        const instruction = document.createElement('div');
        instruction.style.cssText = `
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0, 0, 0, 0.8);
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            z-index: 2147483647;
            pointer-events: none;
        `;
        instruction.textContent = 'Kéo chuột để chọn vùng QR code. Nhấn ESC để hủy.';

        document.body.appendChild(overlay);
        document.body.appendChild(selection);
        overlay.appendChild(instruction);

        // Event listeners
        overlay.addEventListener('mousedown', handleMouseDown);
        overlay.addEventListener('mousemove', handleMouseMove);
        overlay.addEventListener('mouseup', handleMouseUp);
        document.addEventListener('keydown', handleKeyDown);
    }

    function handleMouseDown(e) {
        isSelecting = true;
        startX = e.clientX;
        startY = e.clientY;
        selection.style.left = startX + 'px';
        selection.style.top = startY + 'px';
        selection.style.width = '0';
        selection.style.height = '0';
        selection.style.display = 'block';
    }

    function handleMouseMove(e) {
        if (!isSelecting) return;

        const currentX = e.clientX;
        const currentY = e.clientY;

        const left = Math.min(startX, currentX);
        const top = Math.min(startY, currentY);
        const width = Math.abs(currentX - startX);
        const height = Math.abs(currentY - startY);

        selection.style.left = left + 'px';
        selection.style.top = top + 'px';
        selection.style.width = width + 'px';
        selection.style.height = height + 'px';
    }

    function handleMouseUp(e) {
        if (!isSelecting) return;
        isSelecting = false;

        const currentX = e.clientX;
        const currentY = e.clientY;

        const rect = {
            x: Math.min(startX, currentX),
            y: Math.min(startY, currentY),
            width: Math.abs(currentX - startX),
            height: Math.abs(currentY - startY)
        };

        // Minimum size check
        if (rect.width < 20 || rect.height < 20) {
            cleanup();
            return;
        }

        // Hide overlay before capture
        overlay.style.display = 'none';
        selection.style.display = 'none';

        // Small delay to ensure overlay is hidden
        setTimeout(() => {
            // Send selection to extension
            chrome.runtime.sendMessage({
                type: 'SNIP_SELECTION',
                rect: rect,
                devicePixelRatio: window.devicePixelRatio || 1
            });
            cleanup();
        }, 50);
    }

    function handleKeyDown(e) {
        if (e.key === 'Escape') {
            cleanup();
            chrome.runtime.sendMessage({ type: 'SNIP_CANCELLED' });
        }
    }

    function cleanup() {
        if (overlay) {
            overlay.remove();
            overlay = null;
        }
        if (selection) {
            selection.remove();
            selection = null;
        }
        document.removeEventListener('keydown', handleKeyDown);
        window.__2faSnipOverlayInjected = false;
    }

    // Initialize
    createOverlay();
    window.postMessage({ type: '2FA_SNIP_READY' }, '*');
})();
