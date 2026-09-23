/**
 * OPENCIPHER - ZERO-KNOWLEDGE CLIENT-SIDE CRYPTOGRAPHIC ENGINE
 * Implemented using the native W3C Web Cryptography API (crypto.subtle)
 * Zero external libraries. 100% Client-Side. No telemetry.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  /* ==========================================================================
     1. UTILITY HELPERS (Hex, Base64, ArrayBuffer)
     ========================================================================== */
  const buf2hex = (buffer) => {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  };

  const hex2buf = (hexString) => {
    const bytes = new Uint8Array(Math.ceil(hexString.length / 2));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return bytes.buffer;
  };

  const buf2b64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  const b642buf = (b64) => {
    const binary = window.atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  };

  const b64url2b64 = (str) => {
    return str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  };

  const b642b64url = (str) => {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  // Toast Notification
  const toast = document.getElementById('toastNotice');
  const showToast = (message) => {
    if (!toast) return;
    toast.querySelector('.toast-msg').textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 2800);
  };

  // Copy to clipboard helper
  window.copyText = (elementId, label = 'Content') => {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.value || el.textContent;
    if (!text.trim()) {
      showToast('Nothing to copy');
      return;
    }
    navigator.clipboard.writeText(text).then(() => {
      showToast(`${label} copied to clipboard!`);
    }).catch(() => {
      showToast('Failed to copy to clipboard');
    });
  };

  /* ==========================================================================
     2. NAVIGATION & TABS
     ========================================================================== */
  const tabBtns = document.querySelectorAll('.tab-btn');
  const toolPanes = document.querySelectorAll('.tool-pane');

  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      toolPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');
    });
  });

  /* ==========================================================================
     3. PANIC / MEMORY ZEROIZE BUTTON
     ========================================================================== */
  const panicBtn = document.getElementById('panicBtn');
  if (panicBtn) {
    panicBtn.addEventListener('click', () => {
      if (confirm('Zeroize all memory? This will purge all inputs, outputs, and keys in this session.')) {
        document.querySelectorAll('textarea, input[type="text"], input[type="password"]').forEach((input) => {
          input.value = '';
        });
        currentRsaKeyPair = null;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText('');
        }
        showToast('All session data safely zeroized.');
      }
    });
  }

  /* ==========================================================================
     4. AES-GCM 256-BIT ENCRYPTION & DECRYPTION (PBKDF2)
     ========================================================================== */
  const deriveKeyFromPassword = async (password, salt, usage) => {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      usage
    );
  };

  // Encrypt Text
  const aesEncryptBtn = document.getElementById('aesEncryptBtn');
  if (aesEncryptBtn) {
    aesEncryptBtn.addEventListener('click', async () => {
      const plaintext = document.getElementById('aesPlainInput').value;
      const password = document.getElementById('aesPasswordInput').value;
      const output = document.getElementById('aesOutput');

      if (!plaintext) {
        showToast('Please enter plaintext to encrypt.');
        return;
      }
      if (!password) {
        showToast('Please specify an encryption password.');
        return;
      }

      try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKeyFromPassword(password, salt, ['encrypt']);

        const ciphertext = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: iv },
          key,
          enc.encode(plaintext)
        );

        const payload = {
          alg: 'AES-GCM-256',
          kdf: 'PBKDF2-SHA256-100K',
          salt: buf2b64(salt),
          iv: buf2b64(iv),
          ciphertext: buf2b64(ciphertext)
        };

        output.value = JSON.stringify(payload, null, 2);
        showToast('Encrypted successfully with AES-GCM-256!');
      } catch (err) {
        output.value = `Encryption Error: ${err.message}`;
      }
    });
  }

  // Decrypt Text
  const aesDecryptBtn = document.getElementById('aesDecryptBtn');
  if (aesDecryptBtn) {
    aesDecryptBtn.addEventListener('click', async () => {
      const rawPayload = document.getElementById('aesDecryptInput').value.trim();
      const password = document.getElementById('aesDecryptPassword').value;
      const output = document.getElementById('aesDecryptOutput');

      if (!rawPayload) {
        showToast('Please paste the encrypted JSON payload.');
        return;
      }
      if (!password) {
        showToast('Please enter the decryption password.');
        return;
      }

      try {
        const payload = JSON.parse(rawPayload);
        if (!payload.salt || !payload.iv || !payload.ciphertext) {
          throw new Error('Invalid payload structure. Missing salt, iv, or ciphertext.');
        }

        const salt = new Uint8Array(b642buf(payload.salt));
        const iv = new Uint8Array(b642buf(payload.iv));
        const ciphertext = b642buf(payload.ciphertext);

        const key = await deriveKeyFromPassword(password, salt, ['decrypt']);

        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          key,
          ciphertext
        );

        output.value = dec.decode(decrypted);
        showToast('Payload verified and decrypted successfully!');
      } catch (err) {
        output.value = `[DECRYPTION FAILED]: Invalid password or corrupted authentication tag. (OperationError)`;
        showToast('Decryption failed: check password.');
      }
    });
  }

  // File Encryption Drag & Drop
  const fileEncDrop = document.getElementById('fileEncDrop');
  const fileEncInput = document.getElementById('fileEncInput');
  const fileEncPass = document.getElementById('fileEncPass');
  const fileEncBtn = document.getElementById('fileEncBtn');
  let selectedEncFile = null;

  if (fileEncDrop && fileEncInput) {
    fileEncDrop.addEventListener('click', () => fileEncInput.click());
    fileEncDrop.addEventListener('dragover', (e) => {
      e.preventDefault();
      fileEncDrop.classList.add('drag-over');
    });
    fileEncDrop.addEventListener('dragleave', () => fileEncDrop.classList.remove('drag-over'));
    fileEncDrop.addEventListener('drop', (e) => {
      e.preventDefault();
      fileEncDrop.classList.remove('drag-over');
      if (e.dataTransfer.files.length > 0) {
        selectedEncFile = e.dataTransfer.files[0];
        fileEncDrop.querySelector('.dropzone-title').textContent = selectedEncFile.name;
        fileEncDrop.querySelector('.dropzone-sub').textContent = `${(selectedEncFile.size / 1024).toFixed(1)} KB ready`;
      }
    });

    fileEncInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        selectedEncFile = e.target.files[0];
        fileEncDrop.querySelector('.dropzone-title').textContent = selectedEncFile.name;
        fileEncDrop.querySelector('.dropzone-sub').textContent = `${(selectedEncFile.size / 1024).toFixed(1)} KB ready`;
      }
    });

    if (fileEncBtn) {
      fileEncBtn.addEventListener('click', async () => {
        if (!selectedEncFile) {
          showToast('Please select a file to encrypt.');
          return;
        }
        const password = fileEncPass.value;
        if (!password) {
          showToast('Please provide an encryption key.');
          return;
        }

        try {
          const fileBuffer = await selectedEncFile.arrayBuffer();
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const key = await deriveKeyFromPassword(password, salt, ['encrypt']);

          const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            fileBuffer
          );

          // Package: [16B salt][12B iv][ciphertext]
          const combined = new Uint8Array(salt.byteLength + iv.byteLength + ciphertext.byteLength);
          combined.set(salt, 0);
          combined.set(iv, salt.byteLength);
          combined.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);

          const blob = new Blob([combined], { type: 'application/octet-stream' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `${selectedEncFile.name}.opencipher`;
          a.click();
          URL.revokeObjectURL(url);
          showToast('Encrypted file downloaded!');
        } catch (err) {
          showToast(`File error: ${err.message}`);
        }
      });
    }
  }

  /* ==========================================================================
     5. RSA KEY STUDIO (2048 / 4096-BIT)
     ========================================================================== */
  let currentRsaKeyPair = null;
  const rsaGenBtn = document.getElementById('rsaGenBtn');
  const rsaBitsSelect = document.getElementById('rsaBitsSelect');
  const rsaPublicKeyArea = document.getElementById('rsaPublicKeyArea');
  const rsaPrivateKeyArea = document.getElementById('rsaPrivateKeyArea');

  const exportPem = (buffer, type) => {
    const b64 = buf2b64(buffer);
    const lines = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
  };

  if (rsaGenBtn) {
    rsaGenBtn.addEventListener('click', async () => {
      const bits = parseInt(rsaBitsSelect.value, 10);
      rsaGenBtn.disabled = true;
      rsaGenBtn.innerHTML = `Generating ${bits}-bit RSA Keypair...`;

      try {
        const keyPair = await crypto.subtle.generateKey(
          {
            name: 'RSA-OAEP',
            modulusLength: bits,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
          },
          true,
          ['encrypt', 'decrypt']
        );

        currentRsaKeyPair = keyPair;

        const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        rsaPublicKeyArea.value = exportPem(spki, 'PUBLIC KEY');
        rsaPrivateKeyArea.value = exportPem(pkcs8, 'PRIVATE KEY');

        showToast(`${bits}-bit RSA keypair generated successfully!`);
      } catch (err) {
        showToast(`RSA Generation failed: ${err.message}`);
      } finally {
        rsaGenBtn.disabled = false;
        rsaGenBtn.innerHTML = `Generate Fresh RSA Keypair`;
      }
    });
  }

  // RSA Live Sandbox
  const rsaTestEncryptBtn = document.getElementById('rsaTestEncryptBtn');
  const rsaTestDecryptBtn = document.getElementById('rsaTestDecryptBtn');
  const rsaTestInput = document.getElementById('rsaTestInput');
  const rsaTestOutput = document.getElementById('rsaTestOutput');

  if (rsaTestEncryptBtn) {
    rsaTestEncryptBtn.addEventListener('click', async () => {
      if (!currentRsaKeyPair) {
        showToast('Please generate an RSA keypair above first.');
        return;
      }
      const text = rsaTestInput.value;
      if (!text) {
        showToast('Please enter text to test RSA encryption.');
        return;
      }

      try {
        const encrypted = await crypto.subtle.encrypt(
          { name: 'RSA-OAEP' },
          currentRsaKeyPair.publicKey,
          enc.encode(text)
        );
        rsaTestOutput.value = buf2b64(encrypted);
        showToast('Encrypted with current RSA Public Key!');
      } catch (err) {
        rsaTestOutput.value = `RSA Encrypt Error: ${err.message}`;
      }
    });
  }

  if (rsaTestDecryptBtn) {
    rsaTestDecryptBtn.addEventListener('click', async () => {
      if (!currentRsaKeyPair) {
        showToast('Please generate an RSA keypair above first.');
        return;
      }
      const b64 = rsaTestOutput.value.trim();
      if (!b64) {
        showToast('No ciphertext available to decrypt.');
        return;
      }

      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: 'RSA-OAEP' },
          currentRsaKeyPair.privateKey,
          b642buf(b64)
        );
        rsaTestInput.value = dec.decode(decrypted);
        showToast('Decrypted with RSA Private Key!');
      } catch (err) {
        showToast(`RSA Decrypt Error: ${err.message}`);
      }
    });
  }

  /* ==========================================================================
     6. REAL-TIME MULTI-HASH & CHECKSUM ENGINE
     ========================================================================== */
  const hashInputText = document.getElementById('hashInputText');
  const hashSha256 = document.getElementById('hashSha256');
  const hashSha512 = document.getElementById('hashSha512');
  const hashSha384 = document.getElementById('hashSha384');
  const hashSha1 = document.getElementById('hashSha1');

  const updateHashes = async (text) => {
    if (!text) {
      if (hashSha256) hashSha256.textContent = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      if (hashSha512) hashSha512.textContent = 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
      if (hashSha384) hashSha384.textContent = '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b';
      if (hashSha1) hashSha1.textContent = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
      return;
    }

    const data = enc.encode(text);
    const [h256, h512, h384, h1] = await Promise.all([
      crypto.subtle.digest('SHA-256', data),
      crypto.subtle.digest('SHA-512', data),
      crypto.subtle.digest('SHA-384', data),
      crypto.subtle.digest('SHA-1', data)
    ]);

    if (hashSha256) hashSha256.textContent = buf2hex(h256);
    if (hashSha512) hashSha512.textContent = buf2hex(h512);
    if (hashSha384) hashSha384.textContent = buf2hex(h384);
    if (hashSha1) hashSha1.textContent = buf2hex(h1);

    verifyChecksumMatch();
  };

  if (hashInputText) {
    hashInputText.addEventListener('input', (e) => updateHashes(e.target.value));
    updateHashes(''); // Init with empty string standard hash
  }

  // Checksum Comparator
  const verifyCompareInput = document.getElementById('verifyCompareInput');
  const verifyResultBadge = document.getElementById('verifyResultBadge');

  const verifyChecksumMatch = () => {
    if (!verifyCompareInput || !verifyResultBadge) return;
    const target = verifyCompareInput.value.trim().toLowerCase();
    if (!target) {
      verifyResultBadge.textContent = 'Awaiting Checksum';
      verifyResultBadge.style.color = 'var(--text-muted)';
      return;
    }

    const current256 = hashSha256.textContent.toLowerCase();
    const current512 = hashSha512.textContent.toLowerCase();

    if (target === current256 || target === current512) {
      verifyResultBadge.textContent = 'âœ“ CHECKSUM MATCH (VALID)';
      verifyResultBadge.style.color = 'var(--accent-emerald)';
    } else {
      verifyResultBadge.textContent = 'âœ— MISMATCH (INVALID)';
      verifyResultBadge.style.color = 'var(--accent-rose)';
    }
  };

  if (verifyCompareInput) {
    verifyCompareInput.addEventListener('input', verifyChecksumMatch);
  }

  /* ==========================================================================
     7. JWT (JSON WEB TOKEN) OFFLINE INSPECTOR & VERIFIER
     ========================================================================== */
  const jwtInput = document.getElementById('jwtInput');
  const jwtHeaderView = document.getElementById('jwtHeaderView');
  const jwtPayloadView = document.getElementById('jwtPayloadView');
  const jwtSignatureView = document.getElementById('jwtSignatureView');
  const jwtSecretInput = document.getElementById('jwtSecretInput');
  const jwtVerifyStatus = document.getElementById('jwtVerifyStatus');

  const parseJwt = (token) => {
    const parts = token.trim().split('.');
    if (parts.length !== 3) {
      jwtHeaderView.textContent = '// Invalid JWT: Expected 3 parts (header.payload.signature)';
      jwtPayloadView.textContent = '// Awaiting valid token';
      jwtSignatureView.textContent = '// Empty';
      return null;
    }

    try {
      const header = JSON.parse(dec.decode(b642buf(b64url2b64(parts[0]))));
      const payload = JSON.parse(dec.decode(b642buf(b64url2b64(parts[1]))));

      jwtHeaderView.textContent = JSON.stringify(header, null, 2);

      // Add expiry human readable hint
      let expNote = '';
      if (payload.exp) {
        const expDate = new Date(payload.exp * 1000);
        const isExpired = Date.now() > expDate.getTime();
        expNote = `\n// Token status: ${isExpired ? 'EXPIRED' : 'ACTIVE'} (${expDate.toUTCString()})`;
      }

      jwtPayloadView.textContent = JSON.stringify(payload, null, 2) + expNote;
      jwtSignatureView.textContent = parts[2];

      return { header, payload, rawHeader: parts[0], rawPayload: parts[1], signature: parts[2] };
    } catch (err) {
      jwtHeaderView.textContent = `// Parse error: ${err.message}`;
      return null;
    }
  };

  if (jwtInput) {
    jwtInput.addEventListener('input', (e) => {
      parseJwt(e.target.value);
    });
  }

  // Offline HMAC-SHA256 Signature Verification
  const verifyJwtBtn = document.getElementById('verifyJwtBtn');
  if (verifyJwtBtn) {
    verifyJwtBtn.addEventListener('click', async () => {
      const token = jwtInput.value.trim();
      const secret = jwtSecretInput.value;
      const parsed = parseJwt(token);

      if (!parsed) {
        showToast('Please provide a valid JWT.');
        return;
      }
      if (!secret) {
        showToast('Please enter the HMAC secret key.');
        return;
      }

      try {
        const key = await crypto.subtle.importKey(
          'raw',
          enc.encode(secret),
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign']
        );

        const dataToSign = enc.encode(`${parsed.rawHeader}.${parsed.rawPayload}`);
        const expectedSig = await crypto.subtle.sign('HMAC', key, dataToSign);
        const expectedB64Url = b642b64url(buf2b64(expectedSig));

        if (expectedB64Url === parsed.signature) {
          jwtVerifyStatus.textContent = 'âœ“ SIGNATURE VALID (Authentic token)';
          jwtVerifyStatus.style.color = 'var(--accent-emerald)';
          showToast('HMAC signature verified!');
        } else {
          jwtVerifyStatus.textContent = 'âœ— INVALID SIGNATURE (Key mismatch or tampered token)';
          jwtVerifyStatus.style.color = 'var(--accent-rose)';
          showToast('Signature mismatch!');
        }
      } catch (err) {
        jwtVerifyStatus.textContent = `Verification Error: ${err.message}`;
      }
    });
  }

  /* ==========================================================================
     8. PASSPHRASE GENERATOR & ENTROPY AUDITOR
     ========================================================================== */
  const wordlist = [
    'acumen', 'aerospace', 'alchemy', 'algorithm', 'altitude', 'amplitude', 'anchor',
    'archon', 'astral', 'atomic', 'avalanche', 'beacon', 'bison', 'blackhole',
    'boulder', 'cadence', 'cascade', 'catalyst', 'celestial', 'cipher', 'citadel',
    'comet', 'compass', 'cortex', 'cosmos', 'canyon', 'crescent', 'crystal',
    'cybernetic', 'delta', 'dynamo', 'echo', 'eclipse', 'element', 'enigma',
    'equinox', 'falcon', 'flare', 'flux', 'fractal', 'fusion', 'galaxy',
    'gamma', 'glacier', 'gravity', 'horizon', 'hydra', 'hyperion', 'infinity',
    'ion', 'isotope', 'jaguar', 'jupiter', 'kinetic', 'labyrinth', 'laser',
    'matrix', 'meteor', 'monolith', 'nebula', 'neutron', 'nexus', 'nova',
    'obsidian', 'omega', 'orbit', 'origin', 'orion', 'parallax', 'phantom',
    'photon', 'plasma', 'polaris', 'prism', 'proton', 'pulsar', 'quantum',
    'quasar', 'radar', 'radiance', 'reactor', 'rift', 'satellite', 'shadow',
    'sigma', 'singularity', 'solaris', 'specter', 'spectrum', 'stellar', 'subzero',
    'supernova', 'synapse', 'tachyon', 'titan', 'trajectory', 'vanguard', 'vector',
    'velocity', 'vertex', 'vortex', 'zenith', 'zero'
  ];

  const genPassphraseBtn = document.getElementById('genPassphraseBtn');
  const passLengthSelect = document.getElementById('passLengthSelect');
  const passSeparatorSelect = document.getElementById('passSeparatorSelect');
  const genPassResult = document.getElementById('genPassResult');
  const entropyBitsDisplay = document.getElementById('entropyBitsDisplay');
  const entropyBarFill = document.getElementById('entropyBarFill');
  const entropyCrackTime = document.getElementById('entropyCrackTime');

  const calculateEntropy = (str) => {
    if (!str) return 0;
    const len = str.length;
    const freq = {};
    for (let i = 0; i < len; i++) {
      freq[str[i]] = (freq[str[i]] || 0) + 1;
    }
    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * len);
  };

  const updateEntropyUI = (str) => {
    const bits = calculateEntropy(str);
    if (entropyBitsDisplay) entropyBitsDisplay.textContent = `${bits} bits`;

    // 0 - 128+ scale
    const pct = Math.min(Math.round((bits / 128) * 100), 100);
    if (entropyBarFill) {
      entropyBarFill.style.width = `${pct}%`;
      if (bits < 45) {
        entropyBarFill.style.background = 'var(--accent-rose)';
        if (entropyCrackTime) entropyCrackTime.textContent = '< 1 millisecond';
      } else if (bits < 75) {
        entropyBarFill.style.background = 'var(--accent-amber)';
        if (entropyCrackTime) entropyCrackTime.textContent = '~ a few weeks';
      } else {
        entropyBarFill.style.background = 'var(--accent-emerald)';
        if (entropyCrackTime) entropyCrackTime.textContent = '> 1,000,000 years (Uncrackable)';
      }
    }
  };

  const generatePassphrase = () => {
    const count = parseInt(passLengthSelect ? passLengthSelect.value : '4', 10);
    const sep = passSeparatorSelect ? passSeparatorSelect.value : '-';
    const words = [];
    const randVals = new Uint32Array(count);
    crypto.getRandomValues(randVals);

    for (let i = 0; i < count; i++) {
      const idx = randVals[i] % wordlist.length;
      words.push(wordlist[idx]);
    }

    const passphrase = words.join(sep);
    if (genPassResult) genPassResult.value = passphrase;
    updateEntropyUI(passphrase);
  };

  if (genPassphraseBtn) {
    genPassphraseBtn.addEventListener('click', generatePassphrase);
  }

  // Live entropy on manual typing
  if (genPassResult) {
    genPassResult.addEventListener('input', (e) => updateEntropyUI(e.target.value));
  }

  generatePassphrase(); // Initial run

  /* ==========================================================================
     9. FORMAT ENCODER / DECODER (Base64, Hex, Binary, URL)
     ========================================================================== */
  const fmtInput = document.getElementById('fmtInput');
  const fmtMode = document.getElementById('fmtMode');
  const fmtOutput = document.getElementById('fmtOutput');
  const fmtConvertBtn = document.getElementById('fmtConvertBtn');

  if (fmtConvertBtn) {
    fmtConvertBtn.addEventListener('click', () => {
      const text = fmtInput.value;
      const mode = fmtMode.value;

      try {
        switch (mode) {
          case 'b64-enc':
            fmtOutput.value = window.btoa(text);
            break;
          case 'b64-dec':
            fmtOutput.value = window.atob(text);
            break;
          case 'hex-enc':
            fmtOutput.value = buf2hex(enc.encode(text));
            break;
          case 'hex-dec':
            fmtOutput.value = dec.decode(hex2buf(text.replace(/\s+/g, '')));
            break;
          case 'url-enc':
            fmtOutput.value = encodeURIComponent(text);
            break;
          case 'url-dec':
            fmtOutput.value = decodeURIComponent(text);
            break;
          default:
            fmtOutput.value = text;
        }
        showToast('Converted!');
      } catch (err) {
        fmtOutput.value = `Conversion Error: ${err.message}`;
      }
    });
  }
});
