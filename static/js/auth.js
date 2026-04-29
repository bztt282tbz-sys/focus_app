// --- UI Helpers ---

/**
 * Update the status feedback area with a decaying message.
 */
const setStatus = (msg, isError = false) => {
    const container = document.getElementById('flash-container');
    if (container) {
        const category = isError ? 'danger' : 'info';
        const alertHtml = `
            <div class="alert alert-${category} alert-dismissible fade show" role="alert">
                ${msg}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>`;
        const div = document.createElement('div');
        div.innerHTML = alertHtml;
        const alertElement = div.firstElementChild;
        container.appendChild(alertElement);

        setTimeout(() => {
            if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
                new bootstrap.Alert(alertElement).close();
            } else {
                alertElement.remove();
            }
        }, 3500);
    }
};

const logDebug = (msg, isError = false) => {
    const debugBox = document.getElementById('debug-info');
    const debugText = document.getElementById('debug-text');
    if (debugBox && debugText) {
        debugBox.style.display = 'block';
        debugText.innerText = msg;
        debugText.style.color = isError ? 'red' : 'black';
    }
};

// --- WebAuthn Helpers ---

function bufferDecode(value) {
    return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// --- Crypto Core ---

async function getCryptoKey() {
    const hexKey = sessionStorage.getItem("e2e_key");
    if (!hexKey) return null;
    const keyBytes = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    return await window.crypto.subtle.importKey(
        "raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
}

async function encryptWithSessionKey(plainText) {
    try {
        if (!plainText) return "";
        const cryptoKey = await getCryptoKey();
        if (!cryptoKey) return null;
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedText = new TextEncoder().encode(plainText);
        const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cryptoKey, encodedText);
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(ciphertext), iv.length);
        return btoa(String.fromCharCode(...combined));
    } catch (err) { return null; }
}

async function decryptWithSessionKey(base64Data) {
    try {
        const cryptoKey = await getCryptoKey();
        if (!cryptoKey) return null;
        const combined = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);
        const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, cryptoKey, ciphertext);
        return new TextDecoder().decode(decrypted);
    } catch (err) { return null; }
}

// --- Batch Decryption ---

async function decryptPageContent() {
    const elements = document.querySelectorAll('.decrypt-me');
    const cryptoKey = await getCryptoKey();
    
    if (!cryptoKey) {
        elements.forEach(el => {
            if (el.innerText.trim().length > 20) {
                el.innerText = "🔒 Locked";
            }
            el.classList.remove('is-decrypting');
        });
        return;
    }

    for (const el of elements) {
        const ciphertext = el.innerText.trim();
        if (ciphertext && ciphertext.length > 20 && !ciphertext.includes(" ")) {
            const decrypted = await decryptWithSessionKey(ciphertext);
            if (decrypted) {
                el.innerText = decrypted;
            }
        }
        el.classList.remove('is-decrypting');
        el.style.opacity = "1";
    }
}

// --- Registration/Auth Logic ---

async function registerDevice() {
    const regBtn = document.getElementById('reg-btn');
    if (regBtn) regBtn.disabled = true;
    try {
        const resp = await fetch('/generate-register', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        const options = await resp.json();
        options.challenge = bufferDecode(options.challenge);
        options.user.id = bufferDecode(options.user.id);
        
        const cred = await navigator.credentials.create({ publicKey: options });
        const verifyResp = await fetch('/verify-register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: cred.id,
                rawId: bufferEncode(cred.rawId),
                type: cred.type,
                response: {
                    clientDataJSON: bufferEncode(cred.response.clientDataJSON),
                    attestationObject: bufferEncode(cred.response.attestationObject)
                }
            })
        });
        if(verifyResp.ok) window.location.href = "/login";
    } catch (err) {
        setStatus(err.message, true);
        if (regBtn) regBtn.disabled = false;
    }
}

async function authenticateDevice() {
    const authBtn = document.getElementById('auth-btn');
    if (authBtn) authBtn.disabled = true;
    try {
        const resp = await fetch('/generate-auth', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        const data = await resp.json();
        const options = JSON.parse(data.options);
        
        options.challenge = bufferDecode(options.challenge);
        if(options.allowCredentials) options.allowCredentials.forEach(c => c.id = bufferDecode(c.id));

        const firstCredId = data.options.allowCredentials?.[0]?.id;
        const specificSalt = data.salts[firstCredId] || Object.values(data.salts)[0];

        options.extensions = { prf: { eval: { first: bufferDecode(specificSalt) } } };

        const assertion = await navigator.credentials.get({ publicKey: options });
        const extensions = assertion.getClientExtensionResults();

        if (extensions.prf?.results?.first) {
            const keyBytes = new Uint8Array(extensions.prf.results.first);
            const hexKey = Array.from(keyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            sessionStorage.setItem("e2e_key", hexKey);
        }

        const verifyResp = await fetch('/verify-auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: assertion.id,
                rawId: bufferEncode(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
                    authenticatorData: bufferEncode(assertion.response.authenticatorData),
                    signature: bufferEncode(assertion.response.signature)
                }
            })
        });
        const result = await verifyResp.json();
        if(verifyResp.ok) window.location.href = result.redirect;
    } catch (err) {
        setStatus(err.message, true);
        if (authBtn) authBtn.disabled = false;
    }
}

// --- Global Initialization ---

document.addEventListener("DOMContentLoaded", () => {
    // 1. Decrypt existing page content
    decryptPageContent();

    // 2. Auto-dismiss existing flash messages after 7 seconds
    document.querySelectorAll('#flash-container .alert').forEach(alert => {
        setTimeout(() => {
            if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
                const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
                bsAlert.close();
            } else {
                const closeBtn = alert.querySelector('.btn-close');
                if (closeBtn) closeBtn.click();
                else alert.remove();
            }
        }, 3500);
    });

    // 3. Register/Auth button listeners
    const regBtn = document.getElementById('reg-btn');
    const authBtn = document.getElementById('auth-btn');
    if (regBtn) regBtn.addEventListener('click', registerDevice);
    if (authBtn) authBtn.addEventListener('click', authenticateDevice);

    // 4. Delete Confirmation Handler
    const deleteBtn = document.getElementById('delete-btn-trigger');
    const deleteForm = document.getElementById('delete-task-form');
    if (deleteBtn && deleteForm) {
        deleteBtn.addEventListener('click', () => {
            if (confirm('Are you sure you want to delete this task?')) {
                deleteForm.submit();
            }
        });
    }

    // 5. Points Counter Logic
    const pointsInput = document.getElementById('points-input');
    const btnMinus = document.getElementById('btn-minus');
    const btnPlus = document.getElementById('btn-plus');
    if (pointsInput) {
        const maxPoints = parseInt(pointsInput.getAttribute('max'));
        btnMinus.addEventListener('click', () => {
            let val = parseInt(pointsInput.value);
            if (val > 1) pointsInput.value = val - 1;
        });
        btnPlus.addEventListener('click', () => {
            let val = parseInt(pointsInput.value);
            if (val < maxPoints) pointsInput.value = val + 1;
        });
    }

    // 6. Intercept Create Task Form (E2E Encryption)
    const taskForm = document.getElementById('task-form');
    if (taskForm) {
        let isProcessing = false;
        taskForm.addEventListener('submit', async (e) => {
            if (isProcessing) return; 
            e.preventDefault(); 
            
            const labelInput = document.getElementById('label');
            const commentInput = document.getElementById('comment');
            const submitBtn = taskForm.querySelector('button[type="submit"]');

            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerText = "Encrypting...";
            }

            const encryptedLabel = await encryptWithSessionKey(labelInput.value);
            const encryptedComment = await encryptWithSessionKey(commentInput.value || "");

            if (encryptedLabel) {
                labelInput.value = encryptedLabel;
                commentInput.value = encryptedComment;
                isProcessing = true; 
                taskForm.submit(); 
            } else {
                isProcessing = false;
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerText = "Create Task";
                }
                setStatus("E2E Key missing. Please log in with your Passkey first.", true);
            }
        });
    }

    // 7. Intercept Progress Update Form
    const progressForm = document.getElementById('progress-form');
    if (progressForm) {
        progressForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const noteInput = document.getElementById('update_comment');
            const submitBtn = document.getElementById('submit-btn');

            if (noteInput && noteInput.value.trim() !== "") {
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.innerText = "Encrypting...";
                }
                const encrypted = await encryptWithSessionKey(noteInput.value.trim());
                if (encrypted) {
                    noteInput.value = encrypted;
                }
            }
            progressForm.submit();
        });
    }

    // 8. Toolbox Decryption (Helper)
    const decryptBtn = document.getElementById('decrypt-btn');
    if (decryptBtn) {
        decryptBtn.addEventListener('click', async () => {
            const input = document.getElementById('decrypt-input');
            const output = document.getElementById('decrypt-output');
            const area = document.getElementById('decryption-result-area');
            const decrypted = await decryptWithSessionKey(input.value.trim());
            if (decrypted) {
                output.innerText = decrypted;
                area.style.display = 'block';
            } else {
                setStatus("Decryption failed. Ensure the input is valid Base64.", true);
            }
        });
    }

    // 9. Check for missing E2E key to show Re-auth button
    const e2eKey = sessionStorage.getItem("e2e_key");
    const reauthBtn = document.getElementById('reauth-btn');

    if (!e2eKey && reauthBtn) {
        reauthBtn.style.display = 'inline-block';
    }
});