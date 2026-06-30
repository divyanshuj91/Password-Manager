// Popup controller for Vaultme Obsidian Extension

let currentCredentials = [];
let activeTabUrl = '';
let activeTabId = null;
let encryptionKey = null;
const API_BASE_URL = 'https://vault-me.onrender.com/api';

const views = {
  loading: document.getElementById('view-loading'),
  login: document.getElementById('view-login'),
  lock: document.getElementById('view-lock'),
  main: document.getElementById('view-main')
};

const forms = {
  login: document.getElementById('form-login'),
  unlock: document.getElementById('form-unlock'),
  credential: document.getElementById('form-credential')
};

// UI references
const btnLockHeader = document.getElementById('btn-lock-header');
const lockUserEmail = document.getElementById('lock-user-email');
const settingsUserEmail = document.getElementById('settings-user-email');
const btnSwitchAccount = document.getElementById('btn-switch-account');
const btnLogout = document.getElementById('btn-logout');
const selectAutoLock = document.getElementById('select-auto-lock');

const matchingSection = document.getElementById('matching-logins-section');
const matchingList = document.getElementById('matching-logins-list');
const allLoginsList = document.getElementById('all-logins-list');
const vaultSearch = document.getElementById('vault-search');

const pendingBanner = document.getElementById('pending-banner');

document.addEventListener('DOMContentLoaded', async () => {
  // Activity listeners to reset lock timer
  document.body.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'update_activity' });
  });
  document.body.addEventListener('keypress', () => {
    chrome.runtime.sendMessage({ action: 'update_activity' });
  });

  initNavigation();
  initSettings();
  await detectActiveTab();
  await checkSessionStatus();
});

// Detect tab
async function detectActiveTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]) {
      activeTabId = tabs[0].id;
      activeTabUrl = tabs[0].url || '';
    }
  } catch (err) {
    console.error('Failed to query active tab:', err);
  }
}

// Navigation Tabs
function initNavigation() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const targetPaneId = tab.getAttribute('data-tab');
      const panes = document.querySelectorAll('.tab-pane');
      panes.forEach(pane => {
        pane.classList.remove('active');
        if (pane.id === targetPaneId) {
          pane.classList.add('active');
        }
      });

      if (targetPaneId === 'tab-add') {
        // Reset only if we don't have a pending prefill
        if (pendingBanner.style.display !== 'block') {
          resetCredentialForm();
        }
      } else {
        pendingBanner.style.display = 'none';
      }
    });
  });
}

// Switch UI View
function showView(viewId) {
  Object.keys(views).forEach(key => {
    if (key === viewId) {
      views[key].classList.add('active');
    } else {
      views[key].classList.remove('active');
    }
  });

  if (viewId === 'main') {
    btnLockHeader.style.display = 'block';
  } else {
    btnLockHeader.style.display = 'none';
  }
}

// Check session
async function checkSessionStatus() {
  showView('loading');
  chrome.runtime.sendMessage({ action: 'get_session_status' }, (response) => {
    if (response && response.success) {
      const { isLoggedIn, isLocked, user, autoLockTime } = response;
      selectAutoLock.value = autoLockTime;

      if (!isLoggedIn) {
        showView('login');
      } else if (isLocked) {
        lockUserEmail.textContent = user.email;
        showView('lock');
      } else {
        settingsUserEmail.textContent = user.email;
        btnLockHeader.style.display = 'block';
        loadVault();
      }
    } else {
      showView('login');
    }
  });
}

// ---------------- CRYPTO UTILITIES ----------------

function deriveKeyAndHash(masterPassword, salt) {
  const derivedKey = CryptoJS.PBKDF2(masterPassword, salt, {
    keySize: 256 / 32,
    iterations: 10000,
    hasher: CryptoJS.algo.SHA256
  });

  const encryptionKeyHex = derivedKey.toString(CryptoJS.enc.Hex);
  const authHash = CryptoJS.SHA256(encryptionKeyHex + masterPassword).toString(CryptoJS.enc.Hex);

  return {
    encryptionKey: encryptionKeyHex,
    authHash
  };
}

function encryptData(plaintext, key) {
  if (!plaintext) return '';
  return CryptoJS.AES.encrypt(plaintext, key).toString();
}

function decryptData(ciphertext, key) {
  if (!ciphertext) return '';
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    console.error('Decryption error:', error);
    return '';
  }
}

async function encryptPassword(plaintext, hexKey, kdfSalt) {
  if (!plaintext) {
    return { ciphertext: '', iv: '', kdf_salt: '', enc_algo: 'AES-GCM', enc_version: '1' };
  }
  
  const keyBuffer = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw', keyBuffer, { name: 'AES-GCM' }, false, ['encrypt']
  );

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    cryptoKey,
    encoder.encode(plaintext)
  );

  const ciphertextBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
  const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');

  return {
    ciphertext: ciphertextBase64,
    iv: ivHex,
    kdf_salt: kdfSalt || '',
    enc_algo: 'AES-GCM',
    enc_version: '1'
  };
}

async function decryptPassword(ciphertext, hexKey, ivHex) {
  if (!ciphertext || !ivHex) return '';
  try {
    const keyBuffer = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw', keyBuffer, { name: 'AES-GCM' }, false, ['decrypt']
    );

    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const encryptedBuffer = new Uint8Array(
      atob(ciphertext).split('').map(char => char.charCodeAt(0))
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      encryptedBuffer
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch (error) {
    console.error('Password GCM decryption failed:', error);
    return '';
  }
}

// ---------------- SESSIONS ----------------

forms.login.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  const masterPassword = document.getElementById('login-password').value;
  const loginError = document.getElementById('login-error');
  loginError.textContent = '';

  const submitBtn = forms.login.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'DECRYPTING...';

  chrome.runtime.sendMessage({ action: 'get_salt', email }, (saltRes) => {
    if (!saltRes || !saltRes.success) {
      loginError.textContent = saltRes ? saltRes.error : 'Failed to retrieve salt.';
      submitBtn.disabled = false;
      submitBtn.textContent = 'DECRYPT';
      return;
    }
    
    try {
      const { salt } = saltRes;
      const { encryptionKey: derivedKey, authHash } = deriveKeyAndHash(masterPassword, salt);

      chrome.runtime.sendMessage({
        action: 'login',
        email,
        authHash,
        encryptionKey: derivedKey,
        autoLockTime: Number(selectAutoLock.value)
      }, (response) => {
        submitBtn.disabled = false;
        submitBtn.textContent = 'DECRYPT';

        if (response && response.success) {
          forms.login.reset();
          settingsUserEmail.textContent = email;
          loadVault();
        } else {
          loginError.textContent = response ? response.error : 'Login failed.';
        }
      });
    } catch (err) {
      loginError.textContent = err.message;
      submitBtn.disabled = false;
      submitBtn.textContent = 'DECRYPT';
    }
  });
});

forms.unlock.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = lockUserEmail.textContent;
  const masterPassword = document.getElementById('unlock-password').value;
  const unlockError = document.getElementById('unlock-error');
  unlockError.textContent = '';

  const submitBtn = forms.unlock.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'UNLOCKING...';

  chrome.runtime.sendMessage({ action: 'get_salt', email }, (saltRes) => {
    if (!saltRes || !saltRes.success) {
      unlockError.textContent = saltRes ? saltRes.error : 'Failed to retrieve salt.';
      submitBtn.disabled = false;
      submitBtn.textContent = 'UNLOCK';
      return;
    }

    try {
      const { salt } = saltRes;
      const { encryptionKey: derivedKey, authHash } = deriveKeyAndHash(masterPassword, salt);

      chrome.runtime.sendMessage({
        action: 'login',
        email,
        authHash,
        encryptionKey: derivedKey,
        autoLockTime: Number(selectAutoLock.value)
      }, (response) => {
        submitBtn.disabled = false;
        submitBtn.textContent = 'UNLOCK';

        if (response && response.success) {
          forms.unlock.reset();
          loadVault();
        } else {
          unlockError.textContent = response ? response.error : 'Incorrect master password.';
        }
      });
    } catch (err) {
      unlockError.textContent = err.message;
      submitBtn.disabled = false;
      submitBtn.textContent = 'UNLOCK';
    }
  });
});

btnLockHeader.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'lock' }, () => {
    checkSessionStatus();
  });
});

btnLogout.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'logout' }, () => {
    checkSessionStatus();
  });
});

btnSwitchAccount.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'logout' }, () => {
    showView('login');
  });
});

// ---------------- VAULT SYNCING & RENDER ----------------

async function loadVault() {
  showView('loading');
  chrome.runtime.sendMessage({ action: 'fetch_passwords' }, async (response) => {
    if (response && response.success) {
      const encryptedList = response.passwords;
      encryptionKey = response.encryptionKey;

      try {
        currentCredentials = await Promise.all(encryptedList.map(async (item) => {
          const password = await decryptPassword(item.ciphertext, encryptionKey, item.iv);
          return {
            id: item.id,
            siteName: decryptData(item.site_name, encryptionKey),
            url: decryptData(item.url, encryptionKey),
            username: decryptData(item.username, encryptionKey),
            category: decryptData(item.category, encryptionKey),
            notes: decryptData(item.notes, encryptionKey),
            kdfSalt: item.kdf_salt,
            password
          };
        }));

        showView('main');
        renderCredentials();
        checkForPendingCredential();
      } catch (err) {
        console.error('Vault decryption error:', err);
        showView('lock');
      }
    } else {
      checkSessionStatus();
    }
  });
}

function getDomainName(urlStr) {
  if (!urlStr) return '';
  try {
    const url = new URL(urlStr);
    let host = url.hostname;
    if (host.startsWith('www.')) host = host.substring(4);
    return host.toLowerCase();
  } catch (e) {
    return urlStr.replace(/(^\w+:|^)\/\//, '').split('/')[0].split(':')[0].toLowerCase();
  }
}

function renderCredentials() {
  const query = vaultSearch.value.toLowerCase().trim();
  const activeDomain = getDomainName(activeTabUrl);

  let matching = [];
  let others = [];

  currentCredentials.forEach(cred => {
    const matchesQuery = !query || 
      cred.siteName.toLowerCase().includes(query) ||
      cred.username.toLowerCase().includes(query) ||
      cred.url.toLowerCase().includes(query);

    if (matchesQuery) {
      const credDomain = getDomainName(cred.url);
      if (activeDomain && credDomain && (credDomain.includes(activeDomain) || activeDomain.includes(credDomain))) {
        matching.push(cred);
      } else {
        others.push(cred);
      }
    }
  });

  // Dynamic Matching Tab Banner
  if (matching.length > 0 && !query) {
    matchingSection.style.display = 'block';
    matchingList.innerHTML = '';
    matching.forEach(cred => {
      matchingList.appendChild(createCredentialCardDOM(cred, true));
    });
  } else {
    matchingSection.style.display = 'none';
  }

  // All other entries
  allLoginsList.innerHTML = '';
  const displayList = query ? [...matching, ...others] : others;
  
  if (displayList.length === 0 && matching.length === 0) {
    allLoginsList.innerHTML = '<div class="view-subtitle" style="text-align:center; padding: 24px 0;">No matching credentials.</div>';
  } else {
    displayList.forEach(cred => {
      allLoginsList.appendChild(createCredentialCardDOM(cred, false));
    });
  }
}

function createCredentialCardDOM(cred, isMatching) {
  const card = document.createElement('div');
  card.className = 'credential-card';

  const info = document.createElement('div');
  info.className = 'credential-info';

  const site = document.createElement('div');
  site.className = 'credential-site';
  site.textContent = cred.siteName;

  const user = document.createElement('div');
  user.className = 'credential-user';
  user.textContent = cred.username;

  info.appendChild(site);
  info.appendChild(user);
  card.appendChild(info);

  const actions = document.createElement('div');
  actions.className = 'credential-actions';

  // Fill option
  if (activeTabId && activeTabUrl && activeTabUrl.startsWith('http')) {
    const btnFill = document.createElement('button');
    btnFill.className = 'btn btn-secondary';
    btnFill.style.padding = '4px 8px';
    btnFill.style.fontSize = '10px';
    btnFill.textContent = 'FILL';
    btnFill.addEventListener('click', () => {
      chrome.tabs.sendMessage(activeTabId, {
        action: 'fill_inputs',
        username: cred.username,
        password: cred.password
      });
    });
    actions.appendChild(btnFill);
  }

  // Copy Username
  const btnCopyUser = document.createElement('button');
  btnCopyUser.className = 'icon-btn';
  btnCopyUser.title = 'Copy Username';
  btnCopyUser.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>`;
  btnCopyUser.addEventListener('click', () => {
    navigator.clipboard.writeText(cred.username).then(() => {
      btnCopyUser.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" stroke="#10b981" stroke-width="2" fill="none"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
      setTimeout(() => {
        btnCopyUser.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>`;
      }, 1000);
    });
  });
  actions.appendChild(btnCopyUser);

  // Copy Password
  const btnCopyPass = document.createElement('button');
  btnCopyPass.className = 'icon-btn';
  btnCopyPass.title = 'Copy Password';
  btnCopyPass.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
  btnCopyPass.addEventListener('click', () => {
    navigator.clipboard.writeText(cred.password).then(() => {
      btnCopyPass.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" stroke="#10b981" stroke-width="2" fill="none"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
      setTimeout(() => {
        btnCopyPass.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
      }, 1000);
    });
  });
  actions.appendChild(btnCopyPass);

  // Edit Option
  const btnEdit = document.createElement('button');
  btnEdit.className = 'icon-btn';
  btnEdit.title = 'Edit';
  btnEdit.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>`;
  btnEdit.addEventListener('click', () => {
    prepareEditForm(cred);
  });
  actions.appendChild(btnEdit);

  // Delete option
  const btnDelete = document.createElement('button');
  btnDelete.className = 'icon-btn';
  btnDelete.title = 'Delete';
  btnDelete.innerHTML = `<svg viewBox="0 0 24 24" width="13" height="13" stroke="#ff8b80" stroke-width="2" fill="none"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`;
  btnDelete.addEventListener('click', () => {
    if (confirm(`Remove ${cred.siteName}?`)) {
      chrome.runtime.sendMessage({ action: 'delete_password', id: cred.id }, (res) => {
        if (res && res.success) {
          loadVault();
        } else {
          alert(res.error || 'Deletion failed.');
        }
      });
    }
  });
  actions.appendChild(btnDelete);

  card.appendChild(actions);
  return card;
}

vaultSearch.addEventListener('input', renderCredentials);

// ---------------- ADD / EDIT LOGINS ----------------

function resetCredentialForm() {
  forms.credential.reset();
  document.getElementById('cred-id').value = '';
  document.getElementById('form-credential-title').textContent = 'ADD CREDENTIAL';
  document.getElementById('btn-cred-submit').textContent = 'SAVE';
  document.getElementById('btn-cred-cancel').style.display = 'none';
  document.getElementById('cred-error').textContent = '';
  pendingBanner.style.display = 'none';
  
  if (activeTabUrl && activeTabUrl.startsWith('http')) {
    document.getElementById('cred-url').value = activeTabUrl;
    const rawDom = getDomainName(activeTabUrl).split('.')[0];
    if (rawDom) {
      document.getElementById('cred-name').value = rawDom.charAt(0).toUpperCase() + rawDom.slice(1);
    }
  }
}

function prepareEditForm(cred) {
  document.querySelector('.tab-btn[data-tab="tab-add"]').click();
  document.getElementById('cred-id').value = cred.id;
  document.getElementById('cred-name').value = cred.siteName;
  document.getElementById('cred-url').value = cred.url;
  document.getElementById('cred-username').value = cred.username;
  document.getElementById('cred-password').value = cred.password;
  document.getElementById('cred-category').value = cred.category || 'Logins';
  document.getElementById('cred-notes').value = cred.notes;

  document.getElementById('form-credential-title').textContent = 'EDIT CREDENTIAL';
  document.getElementById('btn-cred-submit').textContent = 'UPDATE';
  document.getElementById('btn-cred-cancel').style.display = 'block';
}

document.getElementById('btn-cred-cancel').addEventListener('click', () => {
  resetCredentialForm();
  document.querySelector('.tab-btn[data-tab="tab-vault"]').click();
});

// Toggle password text/password fields
const btnCredTogglePassword = document.getElementById('btn-cred-toggle-password');
const credPasswordInput = document.getElementById('cred-password');
const svgEyeCred = document.getElementById('svg-eye-cred');

let credPasswordVisible = false;
btnCredTogglePassword.addEventListener('click', () => {
  credPasswordVisible = !credPasswordVisible;
  if (credPasswordVisible) {
    credPasswordInput.type = 'text';
    svgEyeCred.innerHTML = `<line x1="1" y1="1" x2="23" y2="23"></line><path d="M9 9a3 3 0 1 1 4.24 4.24"></path><path d="M17.29 17.29a9 9 0 0 1-12.55-12.55"></path><path d="M1 12a18 18 0 0 1 6.36-6.36m10.74 0A18 18 0 0 1 23 12a18 18 0 0 1-6.36 6.36"></path>`;
  } else {
    credPasswordInput.type = 'password';
    svgEyeCred.innerHTML = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>`;
  }
});

// Submit Form
forms.credential.addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = document.getElementById('cred-id').value;
  const siteName = document.getElementById('cred-name').value.trim();
  const url = document.getElementById('cred-url').value.trim();
  const username = document.getElementById('cred-username').value.trim();
  const password = document.getElementById('cred-password').value;
  const category = document.getElementById('cred-category').value;
  const notes = document.getElementById('cred-notes').value.trim();
  const credError = document.getElementById('cred-error');

  credError.textContent = '';
  const submitBtn = document.getElementById('btn-cred-submit');
  submitBtn.disabled = true;

  try {
    if (!encryptionKey) throw new Error('Encryption key not loaded.');

    const encryptedSiteName = encryptData(siteName, encryptionKey);
    const encryptedUrl = encryptData(url, encryptionKey);
    const encryptedUsername = encryptData(username, encryptionKey);
    const encryptedCategory = encryptData(category, encryptionKey);
    const encryptedNotes = encryptData(notes, encryptionKey);

    chrome.runtime.sendMessage({ action: 'get_session_status' }, (statusRes) => {
      if (!statusRes || !statusRes.success || !statusRes.user) {
        credError.textContent = 'Session not loaded.';
        submitBtn.disabled = false;
        return;
      }
      
      const userEmail = statusRes.user.email;
      chrome.runtime.sendMessage({ action: 'get_salt', email: userEmail }, async (saltRes) => {
        if (!saltRes || !saltRes.success) {
          credError.textContent = saltRes ? saltRes.error : 'Failed to retrieve salt.';
          submitBtn.disabled = false;
          return;
        }

        try {
          const { salt } = saltRes;
          const encryptedPassObj = await encryptPassword(password, encryptionKey, salt);

          const payload = {
            siteName: encryptedSiteName,
            url: encryptedUrl,
            username: encryptedUsername,
            ciphertext: encryptedPassObj.ciphertext,
            iv: encryptedPassObj.iv,
            kdfSalt: salt,
            encAlgo: 'AES-GCM',
            encVersion: '1',
            category: encryptedCategory,
            notes: encryptedNotes,
            lastChangedAt: new Date().toISOString()
          };

        if (id) {
          chrome.runtime.sendMessage({ action: 'update_password', id, payload }, (res) => {
            submitBtn.disabled = false;
            if (res && res.success) {
              loadVault();
              document.querySelector('.tab-btn[data-tab="tab-vault"]').click();
            } else {
              credError.textContent = res ? res.error : 'Failed to update.';
            }
          });
        } else {
          chrome.runtime.sendMessage({ action: 'save_password', payload }, (res) => {
            submitBtn.disabled = false;
            if (res && res.success) {
              loadVault();
              document.querySelector('.tab-btn[data-tab="tab-vault"]').click();
            } else {
              credError.textContent = res ? res.error : 'Failed to save.';
            }
          });
        }
      } catch (err) {
        submitBtn.disabled = false;
        credError.textContent = err.message;
      }
    });
  });
} catch (err) {
  submitBtn.disabled = false;
  credError.textContent = err.message;
}
});

// ---------------- PENDING GENERATED PASSWORD CHECKS ----------------

function checkForPendingCredential() {
  chrome.runtime.sendMessage({ action: 'get_pending_credential' }, (response) => {
    if (response && response.success && response.pending) {
      const { url, username, password } = response.pending;
      
      // Auto switch to add pane
      document.querySelector('.tab-btn[data-tab="tab-add"]').click();
      
      // Prefill fields
      document.getElementById('cred-id').value = '';
      document.getElementById('cred-url').value = url;
      document.getElementById('cred-username').value = username || '';
      document.getElementById('cred-password').value = password;
      
      const rawDom = getDomainName(url).split('.')[0];
      if (rawDom) {
        document.getElementById('cred-name').value = rawDom.charAt(0).toUpperCase() + rawDom.slice(1);
      }
      
      // Display info banner
      pendingBanner.style.display = 'block';
    }
  });
}

// ---------------- SETTINGS ----------------

function initSettings() {
  selectAutoLock.addEventListener('change', () => {
    const minutes = Number(selectAutoLock.value);
    chrome.runtime.sendMessage({ action: 'set_auto_lock', minutes });
  });
}
