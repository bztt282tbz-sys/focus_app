/**
 * Update the status feedback area with a decaying message.
 * Targets 'flash-container' from base.html
 */
const setStatus = (msg, isError = false) => {
    const container = document.getElementById('flash-container');
    if (container) {
        const category = isError ? 'danger' : 'info';
        // Build Bootstrap-compatible HTML
        const alertHtml = `
            <div class="alert alert-${category} alert-dismissible fade show" role="alert">
                ${msg}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>`;
        
        // Append to container
        const div = document.createElement('div');
        div.innerHTML = alertHtml;
        const alertElement = div.firstElementChild;
        container.appendChild(alertElement);

        // Decay logic: Start removal after 7 seconds
        setTimeout(() => {
            if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
                const bsAlert = new bootstrap.Alert(alertElement);
                bsAlert.close();
            } else {
                // Fallback if Bootstrap JS isn't loaded
                alertElement.classList.remove('show');
                setTimeout(() => alertElement.remove(), 150);
            }
        }, 7000);
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

// --- Registration Logic ---

async function registerDevice() {
    const regBtn = document.getElementById('reg-btn');
    logDebug("Generating registration options...");
    setStatus("Contacting server...");
    if (regBtn) regBtn.disabled = true;

    try {
        const resp = await fetch('/generate-register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const options = await resp.json();
        options.challenge = bufferDecode(options.challenge);
        options.user.id = bufferDecode(options.user.id);
        
        const cred = await navigator.credentials.create({ publicKey: options });
        setStatus("Verifying with server...");

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

        if(verifyResp.ok) {
            window.location.href = "/login";
        } else {
            const errorData = await verifyResp.json();
            throw new Error(errorData.error || "Server rejected credential");
        }
    } catch (err) {
        logDebug(err.message, true);
        setStatus(err.message, true);
        if (regBtn) regBtn.disabled = false;
    }
}

// --- Authentication Logic ---

async function authenticateDevice() {
    const authBtn = document.getElementById('auth-btn');
    logDebug("Requesting options...");
    if (authBtn) authBtn.disabled = true;

    try {
        const resp = await fetch('/generate-auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        if(!resp.ok) {
            const err = await resp.json();
            throw new Error(err.error || "Server Error");
        }

        const data = await resp.json();
        const options = JSON.parse(data.options);
        const allSalts = data.salts;

        options.challenge = bufferDecode(options.challenge);
        
        if(options.allowCredentials) {
            options.allowCredentials.forEach(c => c.id = bufferDecode(c.id));
        }

        const firstCredId = data.options.allowCredentials?.[0]?.id;
        const specificSalt = allSalts[firstCredId] || Object.values(allSalts)[0];

        options.extensions = {
            prf: {
                eval: {
                    first: bufferDecode(specificSalt) 
                }
            }
        };

        const assertion = await navigator.credentials.get({ publicKey: options });
        
        const extensions = assertion.getClientExtensionResults();
        if (extensions.prf?.results?.first) {
            const keyBytes = new Uint8Array(extensions.prf.results.first);
            const e2eKeyHex = Array.from(keyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            sessionStorage.setItem("e2e_key", e2eKeyHex);
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
                    signature: bufferEncode(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferEncode(assertion.response.userHandle) : null
                }
            })
        });
        const result = await verifyResp.json();
        if(verifyResp.ok) {
            window.location.href = result.redirect;
        } else {
            throw new Error(result.error || "Verification failed");
        } 
    } catch (err) {
        console.error("Login Error:", err);
        logDebug(err.message, true);
        if (authBtn) authBtn.disabled = false;
    }
}


// --- Initialization ---

document.addEventListener("DOMContentLoaded", () => {
    const regBtn = document.getElementById('reg-btn');
    const authBtn = document.getElementById('auth-btn');
    const adminKeyDisplay = document.getElementById("e2e-key-display");
    
    if (regBtn) regBtn.addEventListener('click', registerDevice);
    if (authBtn) authBtn.addEventListener('click', authenticateDevice);
    
    if (adminKeyDisplay) {
        const storedKey = sessionStorage.getItem("e2e_key");
        adminKeyDisplay.innerText = storedKey || "Key will appear here after a successful passkey login.";
    }
    
    // Auto-decay for existing Flask flash messages on page load
    const existingAlerts = document.querySelectorAll('#flash-container .alert');
    existingAlerts.forEach(alert => {
        setTimeout(() => {
            if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            } else {
                alert.remove();
            }
        }, 7000);
    });
});

