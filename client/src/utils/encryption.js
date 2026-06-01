import CryptoJS from 'crypto-js';

/**
 * Derives a 256-bit encryption key and an auth hash from the master password and salt.
 * @param {string} masterPassword Plaintext master password
 * @param {string} salt Hex-encoded salt
 * @returns {{encryptionKey: string, authHash: string}}
 */
export function deriveKeyAndHash(masterPassword, salt) {
  if (!masterPassword || !salt) {
    throw new Error('Master password and salt are required for key derivation.');
  }

  // Derive standard 256-bit encryption key (8 words) using PBKDF2
  const derivedKey = CryptoJS.PBKDF2(masterPassword, salt, {
    keySize: 256 / 32,
    iterations: 10000,
    hasher: CryptoJS.algo.SHA256
  });

  const encryptionKeyHex = derivedKey.toString(CryptoJS.enc.Hex);

  // Derive auth hash by running SHA-256 on derived key concatenated with master password
  // This auth hash will be sent to the server for authentication
  const authHash = CryptoJS.SHA256(encryptionKeyHex + masterPassword).toString(CryptoJS.enc.Hex);

  return {
    encryptionKey: encryptionKeyHex,
    authHash
  };
}

/**
 * Encrypts a plaintext string using AES-256 with the derived key.
 * @param {string} plaintext Plain text to encrypt
 * @param {string} key Hex-encoded key
 * @returns {string} Encrypted cipher text (base64 string)
 */
export function encryptData(plaintext, key) {
  if (!plaintext) return '';
  if (!key) throw new Error('Encryption key is required.');

  // CryptoJS accepts hex string or WordArray
  const ciphertext = CryptoJS.AES.encrypt(plaintext, key).toString();
  return ciphertext;
}

/**
 * Decrypts a ciphertext string using AES-256 with the derived key.
 * @param {string} ciphertext Encrypted cipher text
 * @param {string} key Hex-encoded key
 * @returns {string} Plaintext string (returns empty string if decryption fails)
 */
export function decryptData(ciphertext, key) {
  if (!ciphertext) return '';
  if (!key) throw new Error('Decryption key is required.');

  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    const plaintext = bytes.toString(CryptoJS.enc.Utf8);
    return plaintext;
  } catch (error) {
    console.error('Decryption failed:', error);
    return '';
  }
}

/**
 * Helper to generate a random 16-byte hex salt for registration
 * @returns {string} Hex-encoded random salt
 */
export function generateRandomSalt() {
  return CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex);
}

/**
 * Gets the SubtleCrypto instance depending on browser or Node.js environment.
 */
async function getSubtleCrypto() {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    return window.crypto.subtle;
  }
  const cryptoModule = await import(/* @vite-ignore */ 'crypto');
  return cryptoModule.webcrypto.subtle;
}

/**
 * Encrypts a password using AES-GCM via Web Crypto API.
 * @param {string} plaintext Password plaintext
 * @param {string} hexKey Hex-encoded master encryption key
 * @param {string} kdfSalt Hex-encoded salt used for derivation
 * @returns {Promise<{ciphertext: string, iv: string, kdf_salt: string, enc_algo: string, enc_version: string}>}
 */
export async function encryptPassword(plaintext, hexKey, kdfSalt) {
  if (!plaintext) {
    return { ciphertext: '', iv: '', kdf_salt: '', enc_algo: 'AES-GCM', enc_version: '1' };
  }
  
  const subtle = await getSubtleCrypto();
  
  // Convert hex key to Uint8Array
  const keyBuffer = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  
  // Import the key as a CryptoKey for AES-GCM
  const cryptoKey = await subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  // Generate a 12-byte initialization vector (IV) for AES-GCM
  const iv = (typeof window !== 'undefined' ? window.crypto : (await import(/* @vite-ignore */ 'crypto')).webcrypto).getRandomValues(new Uint8Array(12));
  
  const encoder = new TextEncoder();
  const encryptedBuffer = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    cryptoKey,
    encoder.encode(plaintext)
  );

  // Convert array buffer to base64
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

/**
 * Decrypts a password using AES-GCM via Web Crypto API.
 * @param {string} ciphertext Base64 encoded ciphertext
 * @param {string} hexKey Hex-encoded master encryption key
 * @param {string} ivHex Hex-encoded initialization vector
 * @returns {Promise<string>} Plaintext password
 */
export async function decryptPassword(ciphertext, hexKey, ivHex) {
  if (!ciphertext || !ivHex) return '';
  try {
    const subtle = await getSubtleCrypto();
    const keyBuffer = new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const cryptoKey = await subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const encryptedBuffer = new Uint8Array(
      atob(ciphertext).split('').map(char => char.charCodeAt(0))
    );

    const decryptedBuffer = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      cryptoKey,
      encryptedBuffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (error) {
    console.error('Password decryption failed:', error);
    return '';
  }
}

