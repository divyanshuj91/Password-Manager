import express from 'express';
import bcrypt from 'bcryptjs';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import db from '../models/database.js';
import { authMiddleware } from '../middleware/authMiddleware.js';
import { JWT_SECRET } from '../config.js';

const router = express.Router();

// Helper to generate a deterministic salt for non-existing users to prevent user enumeration
function getMockSalt(email) {
  const hmac = crypto.createHmac('sha256', JWT_SECRET);
  hmac.update(email);
  return hmac.digest('hex').substring(0, 32); // Return 32-character hex salt
}

/**
 * GET /api/auth/salt
 * Retrieves the salt for the specified email.
 * If user does not exist, returns a mock salt to prevent username enumeration.
 */
router.get('/salt', async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: 'Email parameter is required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const userRes = await db.query('SELECT password_hash, salt FROM users WHERE email = $1', [normalizedEmail]);
    const user = userRes.rows[0];
    
    if (user) {
      if (user.password_hash.startsWith("$argon2")) {
        const parts = user.password_hash.split("$");
        if (parts.length >= 5) {
          const saltBase64 = parts[4];
          const saltHex = Buffer.from(saltBase64, "base64").toString("hex");
          return res.json({ salt: saltHex, exists: true });
        }
      }
      if (user.salt) {
        return res.json({ salt: user.salt, exists: true });
      }
    }
    
    // Return deterministic mock salt
    const mockSalt = getMockSalt(normalizedEmail);
    return res.json({ salt: mockSalt, exists: false });
  } catch (error) {
    console.error('Error fetching salt:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /api/auth/register
 * Registers a new user.
 */
router.post('/register', async (req, res) => {
  const { email, authHash, salt, recoveryHash, encryptedMasterKey } = req.body;

  if (!email || !authHash || !salt) {
    return res.status(400).json({ error: 'Email, authHash, and salt are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // Check if user already exists
    const existingRes = await db.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    const existingUser = existingRes.rows[0];
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already registered.' });
    }

    // Hash using Argon2id
    const passwordHash = await argon2.hash(authHash, {
      type: argon2.argon2id,
      salt: Buffer.from(salt, 'hex')
    });

    // Hash the recovery hash if provided using Argon2id with automatic salt
    const hashedRecoveryHash = recoveryHash ? await argon2.hash(recoveryHash, { type: argon2.argon2id }) : null;

    // Insert user into DB (setting salt column to null since it's embedded in passwordHash)
    const insertRes = await db.query(
      'INSERT INTO users (email, password_hash, salt, recovery_hash, encrypted_master_key) VALUES ($1, $2, NULL, $3, $4) RETURNING id',
      [normalizedEmail, passwordHash, hashedRecoveryHash, encryptedMasterKey || null]
    );

    return res.status(201).json({ 
      message: 'User registered successfully.',
      userId: insertRes.rows[0].id 
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /api/auth/login
 * Authenticates user and returns JWT token.
 */
router.post('/login', async (req, res) => {
  const { email, authHash } = req.body;

  if (!email || !authHash) {
    return res.status(400).json({ error: 'Email and authHash are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const userRes = await db.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = userRes.rows[0];
    
    if (!user) {
      // Wait a short random time to mitigate timing attacks on invalid users
      await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));
      return res.status(400).json({ error: 'Invalid email or master password.' });
    }

    let isMatch = false;
    let needsUpgrade = false;

    if (user.password_hash.startsWith("$argon2")) {
      isMatch = await argon2.verify(user.password_hash, authHash);
    } else {
      isMatch = await bcrypt.compare(authHash, user.password_hash);
      needsUpgrade = isMatch;
    }

    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or master password.' });
    }

    // Auto-upgrade legacy users to Argon2id
    if (needsUpgrade && user.salt) {
      try {
        const newPasswordHash = await argon2.hash(authHash, {
          type: argon2.argon2id,
          salt: Buffer.from(user.salt, "hex")
        });
        await db.query('UPDATE users SET password_hash = $1, salt = NULL WHERE id = $2', [newPasswordHash, user.id]);
        console.log(`User ${user.email} successfully upgraded to Argon2id.`);
      } catch (err) {
        console.error('Failed to auto-upgrade user hash to Argon2id:', err);
      }
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * GET /api/auth/me
 * Returns current authenticated user
 */
router.get('/me', authMiddleware, (req, res) => {
  return res.json({ user: req.user });
});

/**
 * POST /api/auth/logout
 * Clears authentication token cookie
 */
router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  });
  return res.json({ message: 'Logged out successfully.' });
});

/**
 * POST /api/auth/change-master-password
 * Changes the user's master password hash and salt.
 */
router.post('/change-master-password', authMiddleware, async (req, res) => {
  const { currentAuthHash, newAuthHash, newSalt } = req.body;
  const userId = req.user.id;

  if (!currentAuthHash || !newAuthHash || !newSalt) {
    return res.status(400).json({ error: 'currentAuthHash, newAuthHash, and newSalt are required.' });
  }

  try {
    const userRes = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    const user = userRes.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    let isMatch = false;
    if (user.password_hash.startsWith("$argon2")) {
      isMatch = await argon2.verify(user.password_hash, currentAuthHash);
    } else {
      isMatch = await bcrypt.compare(currentAuthHash, user.password_hash);
    }

    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect master password.' });
    }

    const newPasswordHash = await argon2.hash(newAuthHash, {
      type: argon2.argon2id,
      salt: Buffer.from(newSalt, 'hex')
    });

    // Update user auth hash and clear salt column
    await db.query(
      'UPDATE users SET password_hash = $1, salt = NULL WHERE id = $2', 
      [newPasswordHash, userId]
    );

    return res.json({ message: 'Master password updated successfully.' });
  } catch (error) {
    console.error('Change master password error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * DELETE /api/auth/delete-account
 * Deletes user account and cascade-deletes credentials.
 */
router.delete('/delete-account', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { authHash } = req.body;

  if (!authHash) {
    return res.status(400).json({ error: 'authHash is required to delete account.' });
  }

  try {
    const userRes = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    const user = userRes.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    let isMatch = false;
    if (user.password_hash.startsWith("$argon2")) {
      isMatch = await argon2.verify(user.password_hash, authHash);
    } else {
      isMatch = await bcrypt.compare(authHash, user.password_hash);
    }

    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect master password.' });
    }

    // Delete user from DB. Cascading foreign keys will delete all credentials
    await db.query('DELETE FROM users WHERE id = $1', [userId]);

    return res.json({ message: 'Account and all vault data deleted successfully.' });
  } catch (error) {
    console.error('Delete account error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /api/auth/reset-request
 * Generates and stores a 6-digit verification code.
 */
router.post('/reset-request', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email parameter is required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const userRes = await db.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    const user = userRes.rows[0];

    // Always return success to prevent user enumeration
    if (user) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 15 * 60000).toISOString(); // 15 mins expiry

      // Store in DB (delete older codes first)
      await db.query('DELETE FROM verification_codes WHERE email = $1', [normalizedEmail]);
      await db.query(
        'INSERT INTO verification_codes (email, code, expires_at) VALUES ($1, $2, $3)',
        [normalizedEmail, code, expiresAt]
      );

      // Simulate email log
      console.log(`\n===============================================`);
      console.log(`  [SIMULATED EMAIL] Password Reset Verification Code`);
      console.log(`  To: ${normalizedEmail}`);
      console.log(`  Code: ${code}`);
      console.log(`  Expires at: ${expiresAt}`);
      console.log(`===============================================\n`);
    }

    return res.json({ message: 'If the email exists, a verification code has been sent.' });
  } catch (error) {
    console.error('Reset request error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /api/auth/reset-verify
 * Verifies the 6-digit code and returns a temporary JWT reset token.
 */
router.post('/reset-verify', async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: 'Email and verification code are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    const now = new Date().toISOString();
    const verifyRes = await db.query(
      'SELECT * FROM verification_codes WHERE email = $1 AND code = $2 AND expires_at > $3',
      [normalizedEmail, code, now]
    );

    const record = verifyRes.rows[0];

    if (!record) {
      return res.status(400).json({ error: 'Invalid or expired verification code.' });
    }

    // Delete verification codes for this email
    await db.query('DELETE FROM verification_codes WHERE email = $1', [normalizedEmail]);

    // Sign a temporary reset token (valid for 15 minutes)
    const resetToken = jwt.sign(
      { email: normalizedEmail, purpose: 'reset-password' },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    return res.json({ resetToken });
  } catch (error) {
    console.error('Reset verify error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /api/auth/reset-complete-destructive
 * Wipes the user's vault completely and saves a new master password.
 */
router.post('/reset-complete-destructive', async (req, res) => {
  const { email, resetToken, newAuthHash, newSalt } = req.body;

  if (!email || !resetToken || !newAuthHash || !newSalt) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // Verify reset token
    const decoded = jwt.verify(resetToken, JWT_SECRET);
    if (decoded.email !== normalizedEmail || decoded.purpose !== 'reset-password') {
      return res.status(400).json({ error: 'Invalid or expired password reset token.' });
    }

    // Hash the new authHash
    const newPasswordHash = await argon2.hash(newAuthHash, {
      type: argon2.argon2id,
      salt: Buffer.from(newSalt, 'hex')
    });

    const userRes = await db.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    const userId = userRes.rows[0]?.id;

    if (!userId) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');

      // 1. Wipe all existing credentials
      await client.query('DELETE FROM credentials WHERE user_id = $1', [userId]);

      // 2. Update user credentials and remove recovery key references, clear salt column
      await client.query(
        'UPDATE users SET password_hash = $1, salt = NULL, recovery_hash = NULL, encrypted_master_key = NULL WHERE id = $2',
        [newPasswordHash, userId]
      );

      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    return res.json({ message: 'Vault wiped and master password reset successfully.' });
  } catch (error) {
    console.error('Destructive reset error:', error);
    return res.status(500).json({ error: 'Internal server error or token expired.' });
  }
});

/**
 * POST /api/auth/reset-complete-recover
 * Restores vault using Recovery Key and saves a new master password.
 */
router.post('/reset-complete-recover', async (req, res) => {
  const { email, resetToken, recoveryAuthHash, newAuthHash, newSalt, newEncryptedMasterKey, credentials } = req.body;

  if (!email || !resetToken || !recoveryAuthHash || !newAuthHash || !newSalt || !newEncryptedMasterKey || !Array.isArray(credentials)) {
    return res.status(400).json({ error: 'Invalid input parameters.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // Verify reset token
    const decoded = jwt.verify(resetToken, JWT_SECRET);
    if (decoded.email !== normalizedEmail || decoded.purpose !== 'reset-password') {
      return res.status(400).json({ error: 'Invalid or expired password reset token.' });
    }

    // Fetch user details
    const userRes = await db.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = userRes.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    if (!user.recovery_hash) {
      return res.status(400).json({ error: 'No recovery key is configured for this account.' });
    }

    // Verify recovery key hash using Argon2id or legacy bcrypt
    let isMatch = false;
    if (user.recovery_hash && user.recovery_hash.startsWith("$argon2")) {
      isMatch = await argon2.verify(user.recovery_hash, recoveryAuthHash);
    } else if (user.recovery_hash) {
      isMatch = await bcrypt.compare(recoveryAuthHash, user.recovery_hash);
    }

    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect recovery key.' });
    }

    // Hash the new authHash
    const newPasswordHash = await argon2.hash(newAuthHash, {
      type: argon2.argon2id,
      salt: Buffer.from(newSalt, 'hex')
    });

    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');

      // 1. Delete all old credentials
      await client.query('DELETE FROM credentials WHERE user_id = $1', [user.id]);

      // 2. Insert new re-encrypted credentials
      const insertText = `
        INSERT INTO credentials (user_id, site_name, url, username, ciphertext, iv, kdf_salt, enc_algo, enc_version, category, notes, last_changed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `;

      for (const item of credentials) {
        const siteName = item.site_name || item.siteName;
        const url = item.url;
        const username = item.username;
        const ciphertext = item.ciphertext;
        const iv = item.iv;
        const kdfSalt = item.kdf_salt || item.kdfSalt;
        const encAlgo = item.enc_algo || item.encAlgo;
        const encVersion = item.enc_version || item.encVersion;
        const category = item.category;
        const notes = item.notes;
        const lastChangedAt = item.last_changed_at || item.lastChangedAt || new Date().toISOString();

        if (!siteName || !username || !ciphertext || !iv || !kdfSalt || !encAlgo || !encVersion) {
          throw new Error('Invalid item. siteName, username, ciphertext, iv, kdfSalt, encAlgo, encVersion are required.');
        }

        await client.query(insertText, [
          user.id,
          siteName,
          url || '',
          username,
          ciphertext,
          iv,
          kdfSalt,
          encAlgo,
          encVersion,
          category || 'Other',
          notes || '',
          lastChangedAt
        ]);
      }

      // 3. Update users table with new credentials, new encrypted master key, clear salt column
      await client.query(
        'UPDATE users SET password_hash = $1, salt = NULL, encrypted_master_key = $2 WHERE id = $3',
        [newPasswordHash, newEncryptedMasterKey, user.id]
      );

      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    return res.json({ message: 'Vault recovered and master password reset successfully.' });
  } catch (error) {
    console.error('Recovery reset error:', error);
    return res.status(500).json({ error: 'Internal server error or token expired.' });
  }
});

/**
 * GET /api/auth/recovery-key
 * Fetches the encrypted_master_key and encrypted credentials for the user during recovery.
 * Protected by resetToken.
 */
router.get('/recovery-key', async (req, res) => {
  const { email, resetToken } = req.query;

  if (!email || !resetToken) {
    return res.status(400).json({ error: 'Email and resetToken are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // Verify reset token
    const decoded = jwt.verify(resetToken, JWT_SECRET);
    if (decoded.email !== normalizedEmail || decoded.purpose !== 'reset-password') {
      return res.status(400).json({ error: 'Invalid or expired password reset token.' });
    }

    const userRes = await db.query('SELECT id, encrypted_master_key FROM users WHERE email = $1', [normalizedEmail]);
    const user = userRes.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Fetch user credentials
    const credentialsRes = await db.query('SELECT * FROM credentials WHERE user_id = $1', [user.id]);

    return res.json({ 
      encryptedMasterKey: user.encrypted_master_key,
      credentials: credentialsRes.rows
    });
  } catch (error) {
    console.error('Get recovery key error:', error);
    return res.status(500).json({ error: 'Internal server error or token expired.' });
  }
});

export default router;
