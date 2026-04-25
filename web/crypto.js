/**
 * Crypto Module - AES-256-GCM Encryption
 * Sử dụng Web Crypto API (browser native)
 *
 * Format v2 (current): [version=0x02:1B][salt:16B][iv:12B][ciphertext+tag]
 *   PBKDF2-SHA256 600.000 iterations (OWASP 2023+)
 * Format v1 (legacy, decrypt-only): [salt:16B][iv:12B][ciphertext+tag]
 *   PBKDF2-SHA256 100.000 iterations
 */

const PBKDF2_ITERATIONS_V1 = 100000;
const PBKDF2_ITERATIONS_V2 = 600000;
const VERSION_V2 = 0x02;
const SALT_LEN = 16;
const IV_LEN = 12;
const GCM_TAG_LEN = 16;

const CryptoModule = {
    async deriveKey(password, salt, iterations) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    async encrypt(plaintext, password) {
        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
        const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
        const key = await this.deriveKey(password, salt, PBKDF2_ITERATIONS_V2);

        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encoder.encode(plaintext)
        );

        const combined = new Uint8Array(1 + SALT_LEN + IV_LEN + encrypted.byteLength);
        combined[0] = VERSION_V2;
        combined.set(salt, 1);
        combined.set(iv, 1 + SALT_LEN);
        combined.set(new Uint8Array(encrypted), 1 + SALT_LEN + IV_LEN);

        return btoa(String.fromCharCode(...combined));
    },

    async _decryptWithLayout(combined, password, headerLen, iterations) {
        const salt = combined.slice(headerLen, headerLen + SALT_LEN);
        const iv = combined.slice(headerLen + SALT_LEN, headerLen + SALT_LEN + IV_LEN);
        const encrypted = combined.slice(headerLen + SALT_LEN + IV_LEN);

        const key = await this.deriveKey(password, salt, iterations);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );
        return new TextDecoder().decode(decrypted);
    },

    async decrypt(encryptedBase64, password) {
        let combined;
        try {
            combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        } catch (e) {
            throw new Error('Dữ liệu mã hóa không hợp lệ.');
        }

        const minV2 = 1 + SALT_LEN + IV_LEN + GCM_TAG_LEN;
        const minV1 = SALT_LEN + IV_LEN + GCM_TAG_LEN;

        if (combined[0] === VERSION_V2 && combined.length >= minV2) {
            try {
                return await this._decryptWithLayout(combined, password, 1, PBKDF2_ITERATIONS_V2);
            } catch (_) { /* fallback v1 */ }
        }

        if (combined.length >= minV1) {
            try {
                return await this._decryptWithLayout(combined, password, 0, PBKDF2_ITERATIONS_V1);
            } catch (_) { /* fall through */ }
        }

        throw new Error('Giải mã thất bại. Sai mật khẩu?');
    }
};

// Export
window.CryptoModule = CryptoModule;
