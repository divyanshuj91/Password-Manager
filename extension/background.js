// Background Service Worker for Vaultme Obsidian Extension

const DEFAULT_AUTO_LOCK_MINUTES = 5;
const API_BASE_URL = 'https://vault-me.onrender.com/api';

// CryptoJS in-memory library placeholder
let CryptoJSInstance = null;

async function getSessionData() {
  if (chrome.storage.session) {
    return await chrome.storage.session.get(['encryptionKey', 'token', 'user', 'lastActive', 'autoLockTime', 'isLocked', 'pendingCredential']);
  }
  return globalSessionData || {};
}

let globalSessionData = {};
async function setSessionData(data) {
  if (chrome.storage.session) {
    await chrome.storage.session.set(data);
  } else {
    globalSessionData = { ...globalSessionData, ...data };
  }
}

async function clearSessionData() {
  if (chrome.storage.session) {
    await chrome.storage.session.remove(['encryptionKey', 'token', 'user', 'isLocked', 'pendingCredential']);
  } else {
    globalSessionData = {};
  }
}

async function updateActivity() {
  await setSessionData({ lastActive: Date.now() });
}

async function checkAutoLock() {
  const session = await getSessionData();
  if (!session.token || !session.encryptionKey || session.isLocked) {
    return true;
  }

  const autoLockTime = session.autoLockTime || DEFAULT_AUTO_LOCK_MINUTES;
  const lastActive = session.lastActive || Date.now();
  const elapsedMinutes = (Date.now() - lastActive) / 1000 / 60;

  if (elapsedMinutes >= autoLockTime) {
    console.log(`Auto-locking vault due to inactivity (${elapsedMinutes.toFixed(1)} mins elapsed).`);
    await lockVault();
    return true;
  }

  await updateActivity();
  return false;
}

async function lockVault() {
  await setSessionData({
    isLocked: true,
    encryptionKey: null,
    token: null
  });
}

// ---------------- CRYPTO IN SERVICE WORKER ----------------
// Since Service Worker doesn't load HTML scripts, we import crypto-js.js dynamically or parse it.
// We can use importScripts to load local files in Manifest V3 Service Workers!
try {
  importScripts('lib/crypto-js.js');
} catch (e) {
  console.error("Failed to importScripts crypto-js.js:", e);
}

// Helper to decrypt fields in background
function decryptField(ciphertext, key) {
  if (!ciphertext) return '';
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    console.error('Field decryption failed in background:', error);
    return '';
  }
}

// Helper to decrypt Web Crypto passwords in background
async function decryptPassword(ciphertext, hexKey, ivHex) {
  if (!ciphertext || !ivHex) return '';
  try {
    const keyBuffer = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const cryptoKey = await crypto.subtle.importKey(
      'raw', keyBuffer, { name: 'AES-GCM' }, false, ['decrypt']
    );

    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const encryptedBuffer = new Uint8Array(
      atob(ciphertext).split('').map(char => char.charCodeAt(0))
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      encryptedBuffer
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch (error) {
    console.error('Password GCM decryption failed in background:', error);
    return '';
  }
}

// Extract clean domain
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

// Fetch and decrypt matching logins for a domain
async function findMatchingLogins(domain) {
  const session = await getSessionData();
  if (!session.token || !session.encryptionKey || session.isLocked) {
    return [];
  }

  const res = await fetch(`${API_BASE_URL}/passwords`, {
    headers: { 'Authorization': `Bearer ${session.token}` }
  });

  if (!res.ok) return [];
  const encryptedList = await res.json();
  const activeDomain = getDomainName(domain);

  const matches = [];
  for (const item of encryptedList) {
    const credUrl = decryptField(item.url, session.encryptionKey);
    const credDomain = getDomainName(credUrl);

    if (activeDomain && credDomain && (credDomain.includes(activeDomain) || activeDomain.includes(credDomain))) {
      const username = decryptField(item.username, session.encryptionKey);
      const siteName = decryptField(item.site_name, session.encryptionKey);
      matches.push({
        id: item.id,
        siteName,
        username
      });
    }
  }

  return matches;
}

// Message Router
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const originalSendResponse = sendResponse;
  sendResponse = (response) => {
    if (typeof originalSendResponse === 'function') {
      try {
        originalSendResponse(response);
      } catch (e) {
        console.warn("sendResponse failed (probably message port disconnected):", e);
      }
    }
  };

  (async () => {
    try {
      if (request.action !== 'login' && request.action !== 'set_auto_lock' && request.action !== 'get_salt') {
        const locked = await checkAutoLock();
        if (locked && request.action !== 'get_session_status') {
          sendResponse({ success: false, error: 'Vault is locked.' });
          return;
        }
      }

      switch (request.action) {
        case 'get_salt': {
          const saltRes = await fetch(`${API_BASE_URL}/auth/salt?email=${encodeURIComponent(request.email)}`);
          if (!saltRes.ok) throw new Error('Failed to fetch salt.');
          const { salt } = await saltRes.json();
          sendResponse({ success: true, salt });
          break;
        }

        case 'login': {
          const { email, authHash, encryptionKey } = request;
          const saltRes = await fetch(`${API_BASE_URL}/auth/salt?email=${encodeURIComponent(email)}`);
          if (!saltRes.ok) throw new Error('Failed to fetch salt.');
          const { salt } = await saltRes.json();

          const loginRes = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, authHash })
          });

          if (!loginRes.ok) {
            const err = await loginRes.json();
            throw new Error(err.error || 'Invalid credentials.');
          }

          const { token, user } = await loginRes.json();

          await setSessionData({
            encryptionKey,
            token,
            user,
            isLocked: false,
            lastActive: Date.now(),
            autoLockTime: request.autoLockTime || DEFAULT_AUTO_LOCK_MINUTES
          });

          sendResponse({ success: true, user });
          break;
        }

        case 'logout': {
          await clearSessionData();
          sendResponse({ success: true });
          break;
        }

        case 'lock': {
          await lockVault();
          sendResponse({ success: true });
          break;
        }

        case 'get_session_status': {
          const session = await getSessionData();
          sendResponse({
            success: true,
            isLoggedIn: !!session.user,
            isLocked: session.isLocked !== false,
            user: session.user || null,
            autoLockTime: session.autoLockTime || DEFAULT_AUTO_LOCK_MINUTES
          });
          break;
        }

        case 'set_auto_lock': {
          await setSessionData({ autoLockTime: request.minutes });
          sendResponse({ success: true });
          break;
        }

        case 'update_activity': {
          await updateActivity();
          sendResponse({ success: true });
          break;
        }

        case 'fetch_passwords': {
          const session = await getSessionData();
          if (!session.token) {
            sendResponse({ success: false, error: 'Not authenticated.' });
            return;
          }

          const res = await fetch(`${API_BASE_URL}/passwords`, {
            headers: { 'Authorization': `Bearer ${session.token}` }
          });

          if (!res.ok) {
            if (res.status === 401) {
              await lockVault();
              sendResponse({ success: false, error: 'Session expired.' });
              return;
            }
            throw new Error('Failed to fetch credentials.');
          }

          const passwords = await res.json();
          sendResponse({ success: true, passwords, encryptionKey: session.encryptionKey });
          break;
        }

        case 'save_password': {
          const session = await getSessionData();
          if (!session.token) throw new Error('Not authenticated.');

          const res = await fetch(`${API_BASE_URL}/passwords`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${session.token}`
            },
            body: JSON.stringify(request.payload)
          });

          if (!res.ok) throw new Error('Failed to save credential.');
          const data = await res.json();
          sendResponse({ success: true, data });
          break;
        }

        case 'update_password': {
          const session = await getSessionData();
          if (!session.token) throw new Error('Not authenticated.');

          const res = await fetch(`${API_BASE_URL}/passwords/${request.id}`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${session.token}`
            },
            body: JSON.stringify(request.payload)
          });

          if (!res.ok) throw new Error('Failed to update credential.');
          const data = await res.json();
          sendResponse({ success: true, data });
          break;
        }

        case 'delete_password': {
          const session = await getSessionData();
          if (!session.token) throw new Error('Not authenticated.');

          const res = await fetch(`${API_BASE_URL}/passwords/${request.id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${session.token}` }
          });

          if (!res.ok) throw new Error('Failed to delete credential.');
          sendResponse({ success: true });
          break;
        }

        // --- NEW CONTENT SUGGESTION API ACTION ---
        case 'get_matching_usernames': {
          const matches = await findMatchingLogins(request.domain);
          sendResponse({ success: true, matches });
          break;
        }

        // --- NEW SPECIFIC DECRYPTED DELEGATION ACTION ---
        case 'get_autofill_data': {
          const session = await getSessionData();
          if (!session.token || !session.encryptionKey || session.isLocked) {
            sendResponse({ success: false, error: 'Vault is locked.' });
            return;
          }

          const res = await fetch(`${API_BASE_URL}/passwords`, {
            headers: { 'Authorization': `Bearer ${session.token}` }
          });

          if (!res.ok) throw new Error('Failed to fetch passwords.');
          const list = await res.json();
          const target = list.find(item => item.id == request.id);

          if (!target) {
            sendResponse({ success: false, error: 'Credential not found.' });
            return;
          }

          const username = decryptField(target.username, session.encryptionKey);
          const password = await decryptPassword(target.ciphertext, session.encryptionKey, target.iv);

          sendResponse({ success: true, username, password });
          break;
        }

        // --- NEW PENDING SIGNUP GENERATOR SAVE ACTION ---
        case 'set_pending_credential': {
          await setSessionData({
            pendingCredential: {
              url: request.url,
              username: request.username,
              password: request.password
            }
          });
          sendResponse({ success: true });
          break;
        }

        case 'get_pending_credential': {
          const session = await getSessionData();
          const pending = session.pendingCredential || null;
          // Clear it after retrieving
          if (pending) {
            if (chrome.storage.session) {
              await chrome.storage.session.remove('pendingCredential');
            } else {
              delete globalSessionData.pendingCredential;
            }
          }
          sendResponse({ success: true, pending });
          break;
        }

        default:
          sendResponse({ success: false, error: `Unknown background action: ${request.action}` });
      }
    } catch (err) {
      console.error('Background process error:', err);
      sendResponse({ success: false, error: err.message });
    }
  })();
  return true;
});

chrome.runtime.onStartup.addListener(async () => {
  await clearSessionData();
});
