import React, { createContext, useState, useEffect, useContext } from 'react';
import api from '../utils/api.js';
import { deriveKeyAndHash, generateRandomSalt, encryptPassword, decryptPassword } from '../utils/encryption.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null); // In-memory ONLY
  const [encryptionKey, setEncryptionKey] = useState(null); // In-memory ONLY
  const [salt, setSalt] = useState(null); // In-memory ONLY
  const [isLocked, setIsLocked] = useState(true);
  const [isLoading, setIsLoading] = useState(true);
  
  // Settings
  const [themeColor, setThemeColor] = useState(localStorage.getItem('themeColor') || 'purple');
  const [autoLockTime, setAutoLockTime] = useState(Number(localStorage.getItem('autoLockTime')) || 5); // minutes

  // Handle unauthorized event from api.js interceptor
  useEffect(() => {
    const handleUnauthorized = () => {
      logout();
    };

    window.addEventListener('auth-unauthorized', handleUnauthorized);
    return () => {
      window.removeEventListener('auth-unauthorized', handleUnauthorized);
    };
  }, []);

  // Update root HTML class for dynamic theme accent color
  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('theme-purple', 'theme-cyan', 'theme-rose', 'theme-amber');
    root.classList.add(`theme-${themeColor}`);
    localStorage.setItem('themeColor', themeColor);
  }, [themeColor]);

  // Save auto-lock time
  useEffect(() => {
    localStorage.setItem('autoLockTime', autoLockTime);
  }, [autoLockTime]);

  // Initial user recovery from cookie on mount
  useEffect(() => {
    async function restoreSession() {
      try {
        const response = await api.get('/auth/me');
        const userData = response.data.user;
        if (userData) {
          setUser(userData);
          setToken('logged_in'); // Dummy token to keep routing checks working
        }
      } catch (error) {
        console.log('No active session.');
      } finally {
        setIsLoading(false);
      }
    }
    restoreSession();
  }, []);

  /**
   * Registers a user by generating salt, deriving key/hash, and uploading to server
   */
  const register = async (email, masterPassword) => {
    const salt = generateRandomSalt();
    const { encryptionKey, authHash } = deriveKeyAndHash(masterPassword, salt);
    setSalt(salt);

    // 1. Generate a random 32-character recovery key (formatted as VM-XXXX-XXXX-XXXX-XXXX)
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let recoveryKey = 'VM';
    for (let i = 0; i < 4; i++) {
      let segment = '';
      for (let j = 0; j < 4; j++) {
        segment += characters.charAt(Math.floor(Math.random() * characters.length));
      }
      recoveryKey += '-' + segment;
    }

    // 2. Derive key from recoveryKey using PBKDF2 (5000 iterations)
    const CryptoJS = await import('crypto-js');
    const derivedKey = CryptoJS.default.PBKDF2(recoveryKey, salt, {
      keySize: 256 / 32,
      iterations: 5000,
      hasher: CryptoJS.default.algo.SHA256
    });
    const recoveryEncryptionKeyHex = derivedKey.toString(CryptoJS.default.enc.Hex);

    // 3. Derive recoveryAuthHash
    const recoveryAuthHash = CryptoJS.default.SHA256(recoveryEncryptionKeyHex + recoveryKey).toString(CryptoJS.default.enc.Hex);

    // 4. Encrypt the master encryptionKey using recoveryEncryptionKey
    const encryptedMasterKey = CryptoJS.default.AES.encrypt(encryptionKey, recoveryEncryptionKeyHex).toString();

    // 5. Register with backend
    await api.post('/auth/register', {
      email,
      authHash,
      salt,
      recoveryHash: recoveryAuthHash,
      encryptedMasterKey
    });

    return { recoveryKey };
  };

  /**
   * Logs in a user, derives the vault encryption key, and saves JWT
   */
  const login = async (email, masterPassword) => {
    // 1. Fetch the user's salt
    const saltRes = await api.get(`/auth/salt?email=${encodeURIComponent(email)}`);
    const { salt } = saltRes.data;

    // 2. Derive key and authHash
    const { encryptionKey: derivedKey, authHash } = deriveKeyAndHash(masterPassword, salt);

    // 3. Login with authHash
    const response = await api.post('/auth/login', {
      email,
      authHash
    });

    const { token: jwtToken, user: userData } = response.data;
    
    // 4. Save credentials
    setToken(jwtToken || 'logged_in');
    setUser(userData);
    setEncryptionKey(derivedKey);
    setSalt(salt);
    setIsLocked(false);

    return { userData };
  };

  /**
   * Unlocks the vault by deriving the key again (for locked screen)
   */
  const unlock = async (masterPassword) => {
    if (!user) return false;

    try {
      const saltRes = await api.get(`/auth/salt?email=${encodeURIComponent(user.email)}`);
      const { salt } = saltRes.data;

      const { encryptionKey: derivedKey, authHash } = deriveKeyAndHash(masterPassword, salt);

      // Verify the authHash by calling login (or we can just verify it by checking if it decrypts successfully)
      // Query server login endpoint with the derived authHash to ensure it's correct
      await api.post('/auth/login', {
        email: user.email,
        authHash
      });

      setEncryptionKey(derivedKey);
      setSalt(salt);
      setIsLocked(false);
      return true;
    } catch (error) {
      console.error('Vault unlock failed:', error);
      return false;
    }
  };

  /**
   * Locks the vault by wiping the in-memory key (user session remains active)
   */
  const lock = () => {
    setEncryptionKey(null);
    setSalt(null);
    setIsLocked(true);
  };

  /**
   * Full logout (wipes token and key)
   */
  const logout = async () => {
    setToken(null);
    setUser(null);
    setEncryptionKey(null);
    setSalt(null);
    setIsLocked(true);
    try {
      await api.post('/auth/logout');
    } catch (e) {
      console.error('Failed to clear session on logout:', e);
    }
  };

  /**
   * Updates master password, re-encrypting all current vault items
   */
  const changeMasterPassword = async (currentMasterPassword, newMasterPassword, decryptedCredentials) => {
    if (!user || !encryptionKey) throw new Error('Session is locked or inactive.');

    // 1. Fetch current salt
    const saltRes = await api.get(`/auth/salt?email=${encodeURIComponent(user.email)}`);
    const { salt: currentSalt } = saltRes.data;

    // 2. Derive current hashes
    const { authHash: currentAuthHash } = deriveKeyAndHash(currentMasterPassword, currentSalt);

    // 3. Generate new salt and derive new hashes
    const newSalt = generateRandomSalt();
    const { encryptionKey: newKey, authHash: newAuthHash } = deriveKeyAndHash(newMasterPassword, newSalt);

    // 4. Update password on server
    await api.post('/auth/change-master-password', {
      currentAuthHash,
      newAuthHash,
      newSalt
    });

    // 5. Re-encrypt all items using the new key and prepare sync request
    // Note: decryptedCredentials must be passed in as argument (or retrieved from VaultContext)
    const CryptoJS = await import('crypto-js');
    const reEncrypted = await Promise.all(decryptedCredentials.map(async (item) => {
      const encPass = await encryptPassword(item.password, newKey, newSalt);
      return {
        siteName: CryptoJS.default.AES.encrypt(item.siteName, newKey).toString(),
        url: item.url ? CryptoJS.default.AES.encrypt(item.url, newKey).toString() : '',
        username: CryptoJS.default.AES.encrypt(item.username, newKey).toString(),
        ciphertext: encPass.ciphertext,
        iv: encPass.iv,
        kdf_salt: encPass.kdf_salt,
        enc_algo: encPass.enc_algo,
        enc_version: encPass.enc_version,
        category: item.category ? CryptoJS.default.AES.encrypt(item.category, newKey).toString() : '',
        notes: item.notes ? CryptoJS.default.AES.encrypt(item.notes, newKey).toString() : '',
        lastChangedAt: new Date().toISOString()
      };
    }));

    // 6. Bulk sync the newly encrypted credentials
    await api.post('/passwords/sync', { credentials: reEncrypted });

    // 7. Update active key and salt
    setEncryptionKey(newKey);
    setSalt(newSalt);
    
    return true;
  };

  /**
   * Deletes the user account permanently
   */
  const deleteAccount = async (masterPassword) => {
    if (!user) throw new Error('Not logged in.');

    const saltRes = await api.get(`/auth/salt?email=${encodeURIComponent(user.email)}`);
    const { salt } = saltRes.data;
    const { authHash } = deriveKeyAndHash(masterPassword, salt);

    await api.delete('/auth/delete-account', {
      data: { authHash }
    });

    logout();
  };

  /**
   * Triggers a password reset request.
   */
  const requestReset = async (email) => {
    const res = await api.post('/auth/reset-request', { email });
    return res.data;
  };

  /**
   * Verifies the 6-digit password reset code.
   */
  const verifyResetCode = async (email, code) => {
    const res = await api.post('/auth/reset-verify', { email, code });
    return res.data.resetToken;
  };

  /**
   * Resets the master password and wipes all vault credentials.
   */
  const completeDestructiveReset = async (email, resetToken, newMasterPassword) => {
    const salt = generateRandomSalt();
    const { authHash } = deriveKeyAndHash(newMasterPassword, salt);
    const res = await api.post('/auth/reset-complete-destructive', {
      email,
      resetToken,
      newAuthHash: authHash,
      newSalt: salt
    });
    return res.data;
  };

  /**
   * Resets the master password and recovers the vault using the Recovery Key.
   */
  const completeRecoveryReset = async (email, resetToken, recoveryKey, newMasterPassword) => {
    // 1. Fetch user salt
    const saltRes = await api.get(`/auth/salt?email=${encodeURIComponent(email)}`);
    const { salt } = saltRes.data;

    // 2. Fetch encrypted master key and credentials list
    const recoveryKeyRes = await api.get(
      `/auth/recovery-key?email=${encodeURIComponent(email)}&resetToken=${encodeURIComponent(resetToken)}`
    );
    const { encryptedMasterKey, credentials } = recoveryKeyRes.data;

    if (!encryptedMasterKey) {
      throw new Error('This account does not have a recovery key configured.');
    }

    // 3. Derive recovery encryption key
    const CryptoJS = await import('crypto-js');
    const derivedKey = CryptoJS.default.PBKDF2(recoveryKey, salt, {
      keySize: 256 / 32,
      iterations: 5000,
      hasher: CryptoJS.default.algo.SHA256
    });
    const recoveryEncryptionKeyHex = derivedKey.toString(CryptoJS.default.enc.Hex);

    // 4. Validate recovery key by checking if we can decrypt the master key
    let originalEncryptionKey;
    try {
      const bytes = CryptoJS.default.AES.decrypt(encryptedMasterKey, recoveryEncryptionKeyHex);
      originalEncryptionKey = bytes.toString(CryptoJS.default.enc.Utf8);
      if (!originalEncryptionKey) {
        throw new Error('Decryption empty');
      }
    } catch (e) {
      throw new Error('Invalid recovery key.');
    }

    // 5. Decrypt all credentials using the original master key
    const { decryptData, encryptData, decryptPassword, encryptPassword } = await import('../utils/encryption.js');
    const decryptedCredentials = await Promise.all(credentials.map(async (item) => {
      const decryptedPass = await decryptPassword(item.ciphertext, originalEncryptionKey, item.iv);
      return {
        siteName: decryptData(item.site_name, originalEncryptionKey),
        url: decryptData(item.url, originalEncryptionKey),
        username: decryptData(item.username, originalEncryptionKey),
        password: decryptedPass,
        category: decryptData(item.category, originalEncryptionKey),
        notes: decryptData(item.notes, originalEncryptionKey),
        last_changed_at: item.last_changed_at || item.created_at
      };
    }));

    // 6. Derive new keys and authHash from new master password
    const newSalt = generateRandomSalt();
    const { authHash: newAuthHash, encryptionKey: newEncryptionKey } = deriveKeyAndHash(newMasterPassword, newSalt);

    // 7. Re-encrypt all credentials using the new master key
    const reEncryptedCredentials = await Promise.all(decryptedCredentials.map(async (item) => {
      const encPass = await encryptPassword(item.password, newEncryptionKey, newSalt);
      return {
        siteName: encryptData(item.siteName, newEncryptionKey),
        url: item.url ? encryptData(item.url, newEncryptionKey) : '',
        username: encryptData(item.username, newEncryptionKey),
        ciphertext: encPass.ciphertext,
        iv: encPass.iv,
        kdf_salt: encPass.kdf_salt,
        enc_algo: encPass.enc_algo,
        enc_version: encPass.enc_version,
        category: item.category ? encryptData(item.category, newEncryptionKey) : 'Other',
        notes: item.notes ? encryptData(item.notes, newEncryptionKey) : '',
        last_changed_at: item.last_changed_at
      };
    }));

    // 8. Re-encrypt the new master encryption key using recovery key (so recovery continues to work)
    const newEncryptedMasterKey = CryptoJS.default.AES.encrypt(newEncryptionKey, recoveryEncryptionKeyHex).toString();

    // 9. Derive recoveryAuthHash to send for verification
    const recoveryAuthHash = CryptoJS.default.SHA256(recoveryEncryptionKeyHex + recoveryKey).toString(CryptoJS.default.enc.Hex);

    // 10. Complete recovery reset on server
    const res = await api.post('/auth/reset-complete-recover', {
      email,
      resetToken,
      recoveryAuthHash,
      newAuthHash,
      newSalt,
      newEncryptedMasterKey,
      credentials: reEncryptedCredentials
    });

    return res.data;
  };

  return (
    <AuthContext.Provider value={{
      user,
      token,
      encryptionKey,
      salt,
      isLocked,
      isLoading,
      themeColor,
      autoLockTime,
      setThemeColor,
      setAutoLockTime,
      register,
      login,
      unlock,
      lock,
      logout,
      changeMasterPassword,
      deleteAccount,
      requestReset,
      verifyResetCode,
      completeDestructiveReset,
      completeRecoveryReset
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
