// ============================================================
// AES Encryption / Decryption System
// Uses CryptoJS for AES with ECB, CBC, CFB modes + 128/192/256 keys
// ============================================================

// ---------- Helpers ----------

// Convert user password to a key of exactly `bits` bits (16/24/32 bytes)
function deriveKey(password, bits) {
    const byteLen = bits / 8; // 16, 24, or 32
    // Use SHA-256 hash (always 32 bytes) then slice/repeat to needed length
    const hashHex = CryptoJS.SHA256(password).toString(CryptoJS.enc.Hex);
    let keyHex = hashHex;
    // If we need fewer bytes than 32, slice; if need more (unlikely since max 32), pad
    while (keyHex.length < byteLen * 2) keyHex += hashHex;
    keyHex = keyHex.substring(0, byteLen * 2);
    return CryptoJS.enc.Hex.parse(keyHex);
}

// Generate random 16-byte IV
function generateIV() {
    return CryptoJS.lib.WordArray.random(16);
}

// Get mode object from CryptoJS
function getMode(mode) {
    switch (mode) {
        case 'ECB': return CryptoJS.mode.ECB;
        case 'CBC': return CryptoJS.mode.CBC;
        case 'CFB': return CryptoJS.mode.CFB;
        default:    return CryptoJS.mode.CBC;
    }
}

// Show toast notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ---------- DOM references ----------
const processBtn = document.getElementById('processBtn');
const saveBtn    = document.getElementById('saveBtn');
const loadBtn    = document.getElementById('loadBtn');
const clearBtn   = document.getElementById('clearBtn');
const fileInput  = document.getElementById('fileInput');
const inputText  = document.getElementById('inputText');
const outputText = document.getElementById('outputText');
const secretKey  = document.getElementById('secretKey');
const ivInput    = document.getElementById('ivInput');
const ivGroup    = document.getElementById('ivGroup');
const modeSelect = document.getElementById('mode');
const keyLength  = document.getElementById('keyLength');
const metaInfo   = document.getElementById('metaInfo');

// Hide IV field if ECB selected
function updateIVVisibility() {
    ivGroup.style.display = (modeSelect.value === 'ECB') ? 'none' : 'block';
}
modeSelect.addEventListener('change', updateIVVisibility);
updateIVVisibility();

// ---------- Process (encrypt / decrypt) ----------
processBtn.addEventListener('click', () => {
    const text = inputText.value.trim();
    const password = secretKey.value;
    const operation = document.querySelector('input[name="operation"]:checked').value;
    const mode = modeSelect.value;
    const bits = parseInt(keyLength.value, 10);

    // Validation
    if (!password) {
        showToast('Secret key cannot be empty!', 'error');
        secretKey.focus();
        return;
    }
    if (!text) {
        showToast('Please enter text to process!', 'error');
        inputText.focus();
        return;
    }

    try {
        const key = deriveKey(password, bits);
        const cryptoMode = getMode(mode);

        if (operation === 'encrypt') {
            // IV handling
            let iv = null;
            if (mode !== 'ECB') {
                if (ivInput.value.trim()) {
                    iv = CryptoJS.enc.Hex.parse(ivInput.value.trim());
                } else {
                    iv = generateIV();
                    ivInput.value = iv.toString(CryptoJS.enc.Hex);
                }
            }

            const options = { mode: cryptoMode };
            if (iv) options.iv = iv;
            if (mode === 'ECB') options.padding = CryptoJS.pad.Pkcs7;

            const encrypted = CryptoJS.AES.encrypt(text, key, options);
            const cipherText = encrypted.ciphertext.toString(CryptoJS.enc.Base64);

            outputText.value = cipherText;
            metaInfo.value = `Mode: ${mode} | Key: AES-${bits} | IV: ${iv ? iv.toString(CryptoJS.enc.Hex) : 'N/A (ECB)'}`;
            showToast('Encryption successful!', 'success');

        } else {
            // DECRYPT
            let iv = null;
            if (mode !== 'ECB') {
                if (!ivInput.value.trim()) {
                    showToast('IV is required for decryption in CBC/CFB mode!', 'error');
                    ivInput.focus();
                    return;
                }
                iv = CryptoJS.enc.Hex.parse(ivInput.value.trim());
            }

            const cipherParams = CryptoJS.lib.CipherParams.create({
                ciphertext: CryptoJS.enc.Base64.parse(text)
            });

            const options = { mode: cryptoMode };
            if (iv) options.iv = iv;
            if (mode === 'ECB') options.padding = CryptoJS.pad.Pkcs7;

            const decrypted = CryptoJS.AES.decrypt(cipherParams, key, options);
            const plaintext = decrypted.toString(CryptoJS.enc.Utf8);

            if (!plaintext) {
                throw new Error('Decryption failed. Wrong key/IV/mode or corrupted data.');
            }

            outputText.value = plaintext;
            metaInfo.value = `Mode: ${mode} | Key: AES-${bits} | Decrypted successfully`;
            showToast('Decryption successful!', 'success');
        }

    } catch (err) {
        console.error(err);
        showToast(err.message || 'Operation failed!', 'error');
        outputText.value = '';
    }
});

// ---------- Save to .txt file ----------
saveBtn.addEventListener('click', () => {
    const data = outputText.value.trim();
    if (!data) {
        showToast('Nothing to save! Process first.', 'error');
        return;
    }

    const mode = modeSelect.value;
    const bits = keyLength.value;
    const iv = ivInput.value.trim() || 'N/A';
    const timestamp = new Date().toISOString();

    const fileContent =
`=== AES Encrypted File ===
Timestamp: ${timestamp}
Mode: ${mode}
Key Length: AES-${bits}
IV: ${iv}

--- DATA ---
${data}
`;

    const blob = new Blob([fileContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aes_${mode}_${bits}_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('File saved successfully!', 'success');
});

// ---------- Load from .txt file ----------
loadBtn.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
        const content = event.target.result;
        try {
            // Try parse our formatted file
            const dataMatch = content.match(/--- DATA ---\s*([\s\S]*)/);
            const metaMode = content.match(/Mode:\s*(\w+)/);
            const metaBits = content.match(/Key Length:\s*AES-(\d+)/);
            const metaIV   = content.match(/IV:\s*(\S+)/);

            if (dataMatch) {
                outputText.value = dataMatch[1].trim();
                inputText.value = dataMatch[1].trim(); // also put in input for decryption
                if (metaMode) modeSelect.value = metaMode[1];
                if (metaBits) keyLength.value = metaBits[1];
                if (metaIV && metaIV[1] !== 'N/A') ivInput.value = metaIV[1];
                updateIVVisibility();
                showToast('File loaded! Copy the data & switch to Decrypt mode.', 'info');
            } else {
                // Raw ciphertext file
                inputText.value = content.trim();
                showToast('Raw ciphertext loaded into input.', 'info');
            }
        } catch (err) {
            showToast('Could not parse file.', 'error');
        }
    };
    reader.readAsText(file);
    fileInput.value = ''; // reset
});

// ---------- Clear ----------
clearBtn.addEventListener('click', () => {
    inputText.value = '';
    outputText.value = '';
    ivInput.value = '';
    secretKey.value = '';
    metaInfo.value = '';
    showToast('All fields cleared.', 'info');
});