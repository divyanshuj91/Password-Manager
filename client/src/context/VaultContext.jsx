import React, { createContext, useState, useEffect, useContext, useRef } from 'react';
import api from '../utils/api.js';
import { useAuth } from './AuthContext.jsx';
import { encryptData, decryptData, encryptPassword, decryptPassword } from '../utils/encryption.js';
import { analyzePassword } from '../utils/passwordStrength.js';
import CryptoJS from 'crypto-js';

const VaultContext = createContext(null);

export function VaultProvider({ children }) {
  const { user, encryptionKey, salt, isLocked } = useAuth();
  const [credentials, setCredentials] = useState([]);
  const [isVaultLoading, setIsVaultLoading] = useState(false);
  const [activities, setActivities] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Audited lists
  const [breachedList, setBreachedList] = useState({}); // passwordHex -> boolean (is breached)
  const [isAuditing, setIsAuditing] = useState(false);

  // Load activities from localStorage
  useEffect(() => {
    if (user) {
      const stored = localStorage.getItem(`activities_${user.email}`);
      setActivities(stored ? JSON.parse(stored) : []);
    } else {
      setActivities([]);
      setCredentials([]);
      setBreachedList({});
    }
  }, [user]);

  // Load vault when user logs in and unlocks
  useEffect(() => {
    if (user && encryptionKey && !isLocked) {
      fetchVault();
    } else {
      setCredentials([]);
      setBreachedList({});
    }
  }, [user, encryptionKey, isLocked]);

  // Trigger background breach auditing when credentials change
  useEffect(() => {
    if (credentials.length > 0 && encryptionKey) {
      auditBreachedPasswords();
    }
  }, [credentials, encryptionKey]);

  // Helper to log activities
  const logActivity = (action, details) => {
    if (!user) return;
    const newActivity = {
      id: Date.now(),
      action,
      details,
      timestamp: new Date().toISOString()
    };
    const updated = [newActivity, ...activities].slice(0, 50); // Keep last 50 activities
    setActivities(updated);
    localStorage.setItem(`activities_${user.email}`, JSON.stringify(updated));
  };

  /**
   * Fetches credentials from backend and decrypts them in-memory
   */
  const fetchVault = async () => {
    if (!encryptionKey) return;
    setIsVaultLoading(true);

    try {
      const res = await api.get('/passwords');
      const encryptedDataList = res.data;

      // Decrypt credentials
      const decrypted = await Promise.all(encryptedDataList.map(async (item) => {
        const decryptedPass = await decryptPassword(item.ciphertext, encryptionKey, item.iv);
        return {
          id: item.id,
          siteName: decryptData(item.site_name, encryptionKey),
          url: decryptData(item.url, encryptionKey),
          username: decryptData(item.username, encryptionKey),
          password: decryptedPass,
          category: decryptData(item.category, encryptionKey),
          notes: decryptData(item.notes, encryptionKey),
          lastChangedAt: item.last_changed_at || item.created_at,
          createdAt: item.created_at,
          updatedAt: item.updated_at
        };
      }));

      setCredentials(decrypted);
    } catch (error) {
      console.error('Fetch vault error:', error);
    } finally {
      setIsVaultLoading(false);
    }
  };

  /**
   * Adds a new credential, encrypting it client-side
   */
  const addCredential = async (item) => {
    if (!encryptionKey) throw new Error('Vault is locked.');

    const encPass = await encryptPassword(item.password, encryptionKey, salt);

    const encrypted = {
      siteName: encryptData(item.siteName, encryptionKey),
      url: item.url ? encryptData(item.url, encryptionKey) : '',
      username: encryptData(item.username, encryptionKey),
      ciphertext: encPass.ciphertext,
      iv: encPass.iv,
      kdfSalt: encPass.kdf_salt,
      encAlgo: encPass.enc_algo,
      encVersion: encPass.enc_version,
      category: item.category ? encryptData(item.category, encryptionKey) : 'Other',
      notes: item.notes ? encryptData(item.notes, encryptionKey) : '',
      lastChangedAt: new Date().toISOString()
    };

    const res = await api.post('/passwords', encrypted);
    
    // Optimistic UI or simple re-fetch
    await fetchVault();

    logActivity('Add', `Created entry for ${item.siteName}`);
    return res.data;
  };

  /**
   * Updates an existing credential
   */
  const updateCredential = async (id, item) => {
    if (!encryptionKey) throw new Error('Vault is locked.');

    const encPass = await encryptPassword(item.password, encryptionKey, salt);

    const encrypted = {
      siteName: encryptData(item.siteName, encryptionKey),
      url: item.url ? encryptData(item.url, encryptionKey) : '',
      username: encryptData(item.username, encryptionKey),
      ciphertext: encPass.ciphertext,
      iv: encPass.iv,
      kdfSalt: encPass.kdf_salt,
      encAlgo: encPass.enc_algo,
      encVersion: encPass.enc_version,
      category: item.category ? encryptData(item.category, encryptionKey) : 'Other',
      notes: item.notes ? encryptData(item.notes, encryptionKey) : '',
      lastChangedAt: new Date().toISOString()
    };

    await api.put(`/passwords/${id}`, encrypted);
    await fetchVault();

    logActivity('Update', `Modified entry for ${item.siteName}`);
  };

  /**
   * Deletes a credential
   */
  const deleteCredential = async (id, siteName) => {
    await api.delete(`/passwords/${id}`);
    
    // Remove from local state
    setCredentials(prev => prev.filter(c => c.id !== id));

    logActivity('Delete', `Deleted entry for ${siteName}`);
  };

  /**
   * Imports items from a CSV structure (performs encryption and bulk sync)
   */
  const importCredentials = async (items) => {
    if (!encryptionKey) throw new Error('Vault is locked.');

    const encryptedItems = await Promise.all(items.map(async (item) => {
      const encPass = await encryptPassword(item.password, encryptionKey, salt);
      return {
        siteName: encryptData(item.siteName || item.site_name, encryptionKey),
        url: item.url ? encryptData(item.url, encryptionKey) : '',
        username: encryptData(item.username, encryptionKey),
        ciphertext: encPass.ciphertext,
        iv: encPass.iv,
        kdf_salt: encPass.kdf_salt,
        enc_algo: encPass.enc_algo,
        enc_version: encPass.enc_version,
        category: encryptData(item.category || 'Other', encryptionKey),
        notes: item.notes ? encryptData(item.notes, encryptionKey) : '',
        lastChangedAt: new Date().toISOString()
      };
    }));

    await api.post('/passwords/sync', { credentials: encryptedItems });
    await fetchVault();
    
    logActivity('Import', `Imported ${items.length} credentials from CSV`);
  };

  /**
   * Audits unique passwords against HaveIBeenPwned API in the background.
   * Utilizes k-anonymity so only the first 5 characters of the SHA-1 hash are sent.
   */
  const auditBreachedPasswords = async () => {
    if (isAuditing) return;
    setIsAuditing(true);

    const uniquePasswords = [...new Set(credentials.map(c => c.password))].filter(p => p.length > 0);
    const newBreachedMap = { ...breachedList };
    let hasChanges = false;

    for (const password of uniquePasswords) {
      const sha1 = CryptoJS.SHA1(password).toString(CryptoJS.enc.Hex).toUpperCase();
      
      // If already audited, skip
      if (newBreachedMap[sha1] !== undefined) continue;

      const prefix = sha1.substring(0, 5);
      const suffix = sha1.substring(5);

      try {
        const res = await api.get(`/audit/check-breach/${prefix}`);
        const pwnedData = res.data; // Raw text lines
        
        // Parse results: lines are "SUFFIX:COUNT"
        const lines = pwnedData.split('\n');
        const isBreached = lines.some(line => {
          const parts = line.trim().split(':');
          return parts[0] === suffix;
        });

        newBreachedMap[sha1] = isBreached;
        hasChanges = true;
        
        // Debounce slightly to avoid aggressive hitting
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (err) {
        console.error('Audit check-breach failed for hash prefix', prefix, err.message);
      }
    }

    if (hasChanges) {
      setBreachedList(newBreachedMap);
    }
    setIsAuditing(false);
  };

  // Helper function to check if a specific password is pwned
  const checkPasswordBreach = async (password) => {
    if (!password) return false;
    const sha1 = CryptoJS.SHA1(password).toString(CryptoJS.enc.Hex).toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    try {
      const res = await api.get(`/audit/check-breach/${prefix}`);
      const pwnedData = res.data;
      const lines = pwnedData.split('\n');
      return lines.some(line => line.trim().split(':')[0] === suffix);
    } catch (err) {
      console.error(err);
      return false;
    }
  };

  // COMPUTED STATS FOR DASHBOARD & AUDITS

  // 1. Weak Passwords (score < 3)
  const weakCredentials = credentials.filter(c => analyzePassword(c.password).score < 3);

  // 2. Reused Passwords
  const getReusedCredentials = () => {
    const passwordCounts = {};
    credentials.forEach(c => {
      if (c.password) {
        passwordCounts[c.password] = (passwordCounts[c.password] || 0) + 1;
      }
    });
    return credentials.filter(c => passwordCounts[c.password] > 1);
  };
  const reusedCredentials = getReusedCredentials();

  // 3. Breached Passwords
  const getBreachedCredentials = () => {
    return credentials.filter(c => {
      if (!c.password) return false;
      const sha1 = CryptoJS.SHA1(c.password).toString(CryptoJS.enc.Hex).toUpperCase();
      return breachedList[sha1] === true;
    });
  };
  const breachedCredentials = getBreachedCredentials();

  // 4. Old Passwords (older than 90 days)
  const getOldCredentials = () => {
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    return credentials.filter(c => new Date(c.lastChangedAt) < ninetyDaysAgo);
  };
  const oldCredentials = getOldCredentials();

  // 5. Total Security Score (0 to 100)
  const calculateSecurityScore = () => {
    if (credentials.length === 0) return 100;

    let score = 100;
    
    // Deduct for weak passwords
    const weakPercentage = weakCredentials.length / credentials.length;
    score -= Math.min(weakPercentage * 35, 35); // max 35% deduction

    // Deduct for reused passwords
    const reusedPercentage = reusedCredentials.length / credentials.length;
    score -= Math.min(reusedPercentage * 35, 35); // max 35% deduction

    // Deduct for breached passwords
    const breachedPercentage = breachedCredentials.length / credentials.length;
    score -= Math.min(breachedPercentage * 30, 30); // max 30% deduction

    return Math.max(0, Math.round(score));
  };

  const securityScore = calculateSecurityScore();

  return (
    <VaultContext.Provider value={{
      credentials,
      isVaultLoading,
      activities,
      searchQuery,
      setSearchQuery,
      breachedList,
      weakCredentials,
      reusedCredentials,
      breachedCredentials,
      oldCredentials,
      securityScore,
      fetchVault,
      addCredential,
      updateCredential,
      deleteCredential,
      importCredentials,
      checkPasswordBreach
    }}>
      {children}
    </VaultContext.Provider>
  );
}

export function useVault() {
  return useContext(VaultContext);
}
