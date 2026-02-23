/* =========================================
   CipherVault — Encryption Engine
   Uses Web Crypto API (AES-256-GCM + PBKDF2)
   + Per-Device Session Management
   ========================================= */

(() => {
    'use strict';

    // ———————————————————————————————————
    //  SESSION MANAGER — Per-Device Logic
    // ———————————————————————————————————

    const SessionManager = (() => {
        const STORAGE_PREFIX = 'ciphervault_';
        const SESSION_KEY = STORAGE_PREFIX + 'session';
        const HISTORY_KEY = STORAGE_PREFIX + 'history';
        const MAX_HISTORY = 20;

        /**
         * Generate a unique device session ID.
         * Combines crypto randomness with a basic device fingerprint
         * so different devices always get different sessions.
         */
        function generateSessionId() {
            // Collect browser/device signals for fingerprint component
            const signals = [
                navigator.userAgent,
                navigator.language,
                screen.width + 'x' + screen.height,
                screen.colorDepth,
                new Date().getTimezoneOffset(),
                navigator.hardwareConcurrency || 0,
                navigator.maxTouchPoints || 0,
                (navigator.platform || ''),
            ].join('|');

            // Simple hash of the signals string
            let hash = 0;
            for (let i = 0; i < signals.length; i++) {
                const ch = signals.charCodeAt(i);
                hash = ((hash << 5) - hash) + ch;
                hash |= 0;
            }
            const fingerprint = Math.abs(hash).toString(36).slice(0, 6);

            // Random component (per new session)
            const random = Array.from(crypto.getRandomValues(new Uint8Array(4)))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');

            return `${fingerprint}-${random}`;
        }

        /**
         * Get or create the current session object.
         */
        function getSession() {
            try {
                const raw = localStorage.getItem(SESSION_KEY);
                if (raw) {
                    const session = JSON.parse(raw);
                    // Validate structure
                    if (session && session.id && session.createdAt && session.deviceId) {
                        session.lastUsed = Date.now();
                        localStorage.setItem(SESSION_KEY, JSON.stringify(session));
                        return session;
                    }
                }
            } catch { /* corrupted data — create fresh */ }

            return createSession();
        }

        /**
         * Create a brand-new session, resetting all state.
         */
        function createSession() {
            const id = generateSessionId();

            const session = {
                id,
                deviceId: id.split('-')[0],  // fingerprint part
                createdAt: Date.now(),
                lastUsed: Date.now(),
                operationCount: 0,
            };

            try {
                localStorage.setItem(SESSION_KEY, JSON.stringify(session));
                // Fresh session → clear history so each "new session" starts clean
                localStorage.removeItem(HISTORY_KEY);
            } catch { /* storage full or blocked */ }

            return session;
        }

        /**
         * Increment operation counter for this session.
         */
        function trackOperation() {
            const session = getSession();
            session.operationCount++;
            session.lastUsed = Date.now();
            try {
                localStorage.setItem(SESSION_KEY, JSON.stringify(session));
            } catch { /* ignore */ }
        }

        /**
         * Add an entry to the session history.
         */
        function addHistoryEntry(type, preview) {
            let history = getHistory();
            const entry = {
                type, // 'encrypt' or 'decrypt'
                preview: preview.slice(0, 60),
                timestamp: Date.now(),
            };

            history.unshift(entry);
            if (history.length > MAX_HISTORY) {
                history = history.slice(0, MAX_HISTORY);
            }

            try {
                localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
            } catch { /* ignore */ }

            return history;
        }

        /**
         * Get session history.
         */
        function getHistory() {
            try {
                const raw = localStorage.getItem(HISTORY_KEY);
                if (raw) {
                    const history = JSON.parse(raw);
                    if (Array.isArray(history)) return history;
                }
            } catch { /* corrupted */ }
            return [];
        }

        /**
         * Clear session history.
         */
        function clearHistory() {
            try { localStorage.removeItem(HISTORY_KEY); } catch { /* ignore */ }
        }

        /**
         * Destroy the current session and start fresh.
         */
        function resetSession() {
            try {
                localStorage.removeItem(SESSION_KEY);
                localStorage.removeItem(HISTORY_KEY);
            } catch { /* ignore */ }
            return createSession();
        }

        return {
            getSession,
            createSession,
            resetSession,
            trackOperation,
            addHistoryEntry,
            getHistory,
            clearHistory,
        };
    })();


    // ———————————————————————————————————
    //  DOM REFERENCES
    // ———————————————————————————————————

    const $ = (sel) => document.querySelector(sel);

    const btnEncrypt = $('#btn-encrypt');
    const btnDecrypt = $('#btn-decrypt');
    const modeSlider = $('#mode-slider');
    const secretKey = $('#secret-key');
    const toggleKey = $('#toggle-key');
    const inputText = $('#input-text');
    const inputLabel = $('#input-label-text');
    const charCount = $('#char-count');
    const actionBtn = $('#action-btn');
    const actionText = $('#action-btn-text');
    const outputField = $('#output-field');
    const outputText = $('#output-text');
    const outputLabel = $('#output-label-text');
    const copyBtn = $('#copy-btn');
    const copyBtnText = $('#copy-btn-text');
    const clearBtn = $('#clear-btn');
    const toast = $('#toast');
    const encryptIcon = $('.action-btn__icon--encrypt');
    const decryptIcon = $('.action-btn__icon--decrypt');
    const sessionDisplay = $('#session-id-display');
    const newSessionBtn = $('#new-session-btn');
    const historySection = $('#history-section');
    const historyList = $('#history-list');
    const clearHistoryBtn = $('#clear-history-btn');

    let currentMode = 'encrypt';
    let toastTimer = null;


    // ———————————————————————————————————
    //  CRYPTO CONSTANTS
    // ———————————————————————————————————

    const SALT_LEN = 16;
    const IV_LEN = 12;
    const ITER = 310_000;


    // ———————————————————————————————————
    //  UTILITY — ArrayBuffer ↔ Base64
    // ———————————————————————————————————

    function bufToBase64(buf) {
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToBuf(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }


    // ———————————————————————————————————
    //  KEY DERIVATION — PBKDF2 → AES-256
    // ———————————————————————————————————

    async function deriveKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            enc.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }


    // ———————————————————————————————————
    //  ENCRYPT / DECRYPT
    // ———————————————————————————————————

    async function encryptMessage(plaintext, password) {
        const enc = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
        const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
        const key = await deriveKey(password, salt);

        const cipherBuf = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            enc.encode(plaintext)
        );

        const combined = new Uint8Array(salt.byteLength + iv.byteLength + cipherBuf.byteLength);
        combined.set(salt, 0);
        combined.set(iv, salt.byteLength);
        combined.set(new Uint8Array(cipherBuf), salt.byteLength + iv.byteLength);

        return bufToBase64(combined.buffer);
    }

    /**
     * Sanitize a Base64 string — strip all whitespace/newlines
     * and validate that only valid Base64 chars remain.
     */
    function sanitizeBase64(str) {
        // Remove every whitespace character (spaces, newlines, tabs, etc.)
        const cleaned = str.replace(/\s+/g, '');
        // Validate Base64 alphabet
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleaned)) {
            throw new Error('Invalid Base64 characters detected');
        }
        if (cleaned.length === 0) {
            throw new Error('Empty cipher text');
        }
        return cleaned;
    }

    async function decryptMessage(cipherB64, password) {
        // Clean up the pasted input first
        const cleanB64 = sanitizeBase64(cipherB64);
        const combined = new Uint8Array(base64ToBuf(cleanB64));

        // Minimum length: 16 (salt) + 12 (iv) + at least 1 byte of ciphertext
        if (combined.byteLength < SALT_LEN + IV_LEN + 1) {
            throw new Error('Cipher text is too short — data may be truncated');
        }

        const salt = combined.slice(0, SALT_LEN);
        const iv = combined.slice(SALT_LEN, SALT_LEN + IV_LEN);
        const data = combined.slice(SALT_LEN + IV_LEN);

        const key = await deriveKey(password, salt);

        const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );

        return new TextDecoder().decode(plainBuf);
    }


    // ———————————————————————————————————
    //  TOAST NOTIFICATIONS
    // ———————————————————————————————————

    function showToast(message, type = 'info') {
        clearTimeout(toastTimer);
        toast.textContent = message;
        toast.className = `toast toast--${type}`;
        void toast.offsetWidth;
        toast.classList.add('toast--visible');

        toastTimer = setTimeout(() => {
            toast.classList.remove('toast--visible');
        }, 3000);
    }


    // ———————————————————————————————————
    //  MODE SWITCHING
    // ———————————————————————————————————

    function setMode(mode) {
        currentMode = mode;

        btnEncrypt.classList.toggle('mode-btn--active', mode === 'encrypt');
        btnDecrypt.classList.toggle('mode-btn--active', mode === 'decrypt');
        btnEncrypt.setAttribute('aria-selected', mode === 'encrypt');
        btnDecrypt.setAttribute('aria-selected', mode === 'decrypt');
        modeSlider.classList.toggle('mode-slider--decrypt', mode === 'decrypt');

        if (mode === 'encrypt') {
            inputLabel.textContent = 'Plain Text Message';
            inputText.placeholder = 'Type your secret message here…';
            actionText.textContent = 'Encrypt Message';
            outputLabel.textContent = 'Encrypted Output';
            encryptIcon.style.display = '';
            decryptIcon.style.display = 'none';
        } else {
            inputLabel.textContent = 'Encrypted Message';
            inputText.placeholder = 'Paste the encrypted message here…';
            actionText.textContent = 'Decrypt Message';
            outputLabel.textContent = 'Decrypted Output';
            encryptIcon.style.display = 'none';
            decryptIcon.style.display = '';
        }

        inputText.value = '';
        outputText.value = '';
        charCount.textContent = '0';
        outputField.style.display = 'none';
    }

    btnEncrypt.addEventListener('click', () => setMode('encrypt'));
    btnDecrypt.addEventListener('click', () => setMode('decrypt'));


    // ———————————————————————————————————
    //  TOGGLE SECRET KEY VISIBILITY
    // ———————————————————————————————————

    toggleKey.addEventListener('click', () => {
        const isPassword = secretKey.type === 'password';
        secretKey.type = isPassword ? 'text' : 'password';
        toggleKey.querySelector('.eye-open').style.display = isPassword ? 'none' : '';
        toggleKey.querySelector('.eye-closed').style.display = isPassword ? '' : 'none';
    });


    // ———————————————————————————————————
    //  CHARACTER COUNTER
    // ———————————————————————————————————

    inputText.addEventListener('input', () => {
        charCount.textContent = inputText.value.length;
    });


    // ———————————————————————————————————
    //  SESSION UI
    // ———————————————————————————————————

    function displaySession() {
        const session = SessionManager.getSession();
        sessionDisplay.textContent = `Session: ${session.id}`;
    }

    function formatTime(ts) {
        const d = new Date(ts);
        const now = new Date();
        const isToday = d.toDateString() === now.toDateString();
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        if (isToday) return `${hh}:${mm}`;
        return `${d.getMonth() + 1}/${d.getDate()} ${hh}:${mm}`;
    }

    function renderHistory() {
        const history = SessionManager.getHistory();

        if (history.length === 0) {
            historySection.style.display = 'none';
            return;
        }

        historySection.style.display = 'block';
        historyList.innerHTML = '';

        history.forEach((entry) => {
            const li = document.createElement('li');
            li.className = 'history__item';
            li.innerHTML = `
                <span class="history__item-type history__item-type--${entry.type}">
                    ${entry.type === 'encrypt' ? 'ENC' : 'DEC'}
                </span>
                <span class="history__item-preview">${escapeHtml(entry.preview)}</span>
                <span class="history__item-time">${formatTime(entry.timestamp)}</span>
            `;
            historyList.appendChild(li);
        });
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // New session button
    newSessionBtn.addEventListener('click', () => {
        SessionManager.resetSession();
        displaySession();
        renderHistory();

        // Clear all fields
        secretKey.value = '';
        inputText.value = '';
        outputText.value = '';
        charCount.textContent = '0';
        outputField.style.display = 'none';

        showToast('🔄  New session started', 'info');
    });

    // Clear history button
    clearHistoryBtn.addEventListener('click', () => {
        SessionManager.clearHistory();
        renderHistory();
        showToast('🗑  History cleared', 'info');
    });


    // ———————————————————————————————————
    //  MAIN ACTION — Encrypt / Decrypt
    // ———————————————————————————————————

    actionBtn.addEventListener('click', async () => {
        const key = secretKey.value.trim();
        const text = inputText.value.trim();

        if (!key) {
            showToast('⚠  Please enter a secret key', 'error');
            secretKey.focus();
            return;
        }
        if (!text) {
            showToast('⚠  Please enter a message', 'error');
            inputText.focus();
            return;
        }

        actionBtn.disabled = true;
        actionBtn.classList.add('action-btn--loading');

        try {
            let result;
            if (currentMode === 'encrypt') {
                result = await encryptMessage(text, key);
                showToast('✓  Message encrypted successfully!', 'success');
                SessionManager.addHistoryEntry('encrypt', text);
            } else {
                result = await decryptMessage(text, key);
                showToast('✓  Message decrypted successfully!', 'success');
                SessionManager.addHistoryEntry('decrypt', result);
            }

            SessionManager.trackOperation();

            outputText.value = result;
            outputField.style.display = 'block';
            outputField.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

            // Re-render history
            renderHistory();

        } catch (err) {
            console.error('Crypto error:', err);
            if (currentMode === 'decrypt') {
                const msg = err.message || '';
                if (msg.includes('Invalid Base64')) {
                    showToast('✗  Invalid encrypted text — contains bad characters', 'error');
                } else if (msg.includes('too short')) {
                    showToast('✗  Encrypted text looks incomplete or truncated', 'error');
                } else {
                    showToast('✗  Decryption failed — wrong key or corrupted data', 'error');
                }
            } else {
                showToast('✗  Encryption failed — please try again', 'error');
            }
        } finally {
            actionBtn.disabled = false;
            actionBtn.classList.remove('action-btn--loading');
        }
    });


    // ———————————————————————————————————
    //  COPY TO CLIPBOARD
    // ———————————————————————————————————

    copyBtn.addEventListener('click', async () => {
        const text = outputText.value;
        if (!text) return;

        try {
            await navigator.clipboard.writeText(text);
            copyBtnText.textContent = 'Copied!';
            showToast('📋  Copied to clipboard', 'success');
            setTimeout(() => { copyBtnText.textContent = 'Copy to Clipboard'; }, 2000);
        } catch {
            outputText.select();
            document.execCommand('copy');
            copyBtnText.textContent = 'Copied!';
            showToast('📋  Copied to clipboard', 'info');
            setTimeout(() => { copyBtnText.textContent = 'Copy to Clipboard'; }, 2000);
        }
    });


    // ———————————————————————————————————
    //  CLEAR ALL
    // ———————————————————————————————————

    clearBtn.addEventListener('click', () => {
        inputText.value = '';
        outputText.value = '';
        secretKey.value = '';
        charCount.textContent = '0';
        outputField.style.display = 'none';
        showToast('🗑  All fields cleared', 'info');
    });


    // ———————————————————————————————————
    //  KEYBOARD SHORTCUT: Ctrl+Enter
    // ———————————————————————————————————

    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            actionBtn.click();
        }
    });


    // ———————————————————————————————————
    //  VISIBILITY CHANGE — Auto-save state
    // ———————————————————————————————————

    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            // Touch the session so lastUsed is updated
            SessionManager.getSession();
        }
    });


    // ———————————————————————————————————
    //  INIT — Kick off session on load
    // ———————————————————————————————————

    displaySession();
    renderHistory();

})();
