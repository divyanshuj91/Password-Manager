import express from 'express';
import db from '../models/database.js';
import { authMiddleware } from '../middleware/authMiddleware.js';

const router = express.Router();

/**
 * GET /api/passwords
 * Fetch all encrypted credentials for the authenticated user
 */
router.get('/', authMiddleware, async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await db.query(`
      SELECT id, site_name, url, username, ciphertext, iv, kdf_salt, enc_algo, enc_version, category, notes, last_changed_at, created_at, updated_at
      FROM credentials
      WHERE user_id = $1
      ORDER BY site_name ASC
    `, [userId]);

    // Map database columns to client field names
    const mapped = result.rows.map(row => ({
      id: row.id,
      site_name: row.site_name,
      url: row.url,
      username: row.username,
      ciphertext: row.ciphertext,
      iv: row.iv,
      kdf_salt: row.kdf_salt,
      enc_algo: row.enc_algo,
      enc_version: row.enc_version,
      category: row.category,
      notes: row.notes,
      last_changed_at: row.last_changed_at,
      created_at: row.created_at,
      updated_at: row.updated_at
    }));

    return res.json(mapped);
  } catch (error) {
    console.error('Fetch credentials error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /api/passwords
 * Create a new encrypted credential
 */
router.post('/', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { siteName, url, username, ciphertext, iv, kdfSalt, encAlgo, encVersion, category, notes, lastChangedAt } = req.body;

  if (!siteName || !username || !ciphertext || !iv || !kdfSalt || !encAlgo || !encVersion) {
    return res.status(400).json({ error: 'Required fields missing: siteName, username, ciphertext, iv, kdfSalt, encAlgo, encVersion.' });
  }

  const changeTime = lastChangedAt || new Date().toISOString();

  try {
    const result = await db.query(`
      INSERT INTO credentials (user_id, site_name, url, username, ciphertext, iv, kdf_salt, enc_algo, enc_version, category, notes, last_changed_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, CURRENT_TIMESTAMP)
      RETURNING id
    `, [userId, siteName, url || '', username, ciphertext, iv, kdfSalt, encAlgo, encVersion, category || '', notes || '', changeTime]);

    return res.status(201).json({
      id: result.rows[0].id,
      message: 'Credential created successfully.'
    });
  } catch (error) {
    console.error('Create credential error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * PUT /api/passwords/:id
 * Update an existing encrypted credential
 */
router.put('/:id', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;
  const { siteName, url, username, ciphertext, iv, kdfSalt, encAlgo, encVersion, category, notes, lastChangedAt } = req.body;

  if (!siteName || !username || !ciphertext || !iv || !kdfSalt || !encAlgo || !encVersion) {
    return res.status(400).json({ error: 'Required fields missing: siteName, username, ciphertext, iv, kdfSalt, encAlgo, encVersion.' });
  }

  const changeTime = lastChangedAt || new Date().toISOString();

  try {
    // Check ownership first
    const credRes = await db.query('SELECT id FROM credentials WHERE id = $1 AND user_id = $2', [id, userId]);
    if (credRes.rows.length === 0) {
      return res.status(404).json({ error: 'Credential not found or unauthorized.' });
    }

    await db.query(`
      UPDATE credentials
      SET site_name = $1, url = $2, username = $3, ciphertext = $4, iv = $5, kdf_salt = $6, enc_algo = $7, enc_version = $8, category = $9, notes = $10, last_changed_at = $11, updated_at = CURRENT_TIMESTAMP
      WHERE id = $12 AND user_id = $13
    `, [siteName, url || '', username, ciphertext, iv, kdfSalt, encAlgo, encVersion, category || '', notes || '', changeTime, id, userId]);

    return res.json({ message: 'Credential updated successfully.' });
  } catch (error) {
    console.error('Update credential error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * DELETE /api/passwords/:id
 * Delete an encrypted credential
 */
router.delete('/:id', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;

  try {
    const result = await db.query('DELETE FROM credentials WHERE id = $1 AND user_id = $2', [id, userId]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Credential not found or unauthorized.' });
    }

    return res.json({ message: 'Credential deleted successfully.' });
  } catch (error) {
    console.error('Delete credential error:', error);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

/**
 * POST /api/passwords/sync
 * Bulk sync credentials (deletes all user's credentials and inserts new list in a transaction)
 * Useful for CSV imports and Master Password updates.
 */
router.post('/sync', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { credentials } = req.body; // Array of credentials

  if (!Array.isArray(credentials)) {
    return res.status(400).json({ error: 'Credentials parameter must be an array.' });
  }

  // Get a client from the pg pool to handle the transaction securely
  const client = await db.pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Delete all existing credentials
    await client.query('DELETE FROM credentials WHERE user_id = $1', [userId]);

    // 2. Insert all new items
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
        userId, 
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

    await client.query('COMMIT');
    
    return res.json({ 
      message: `Successfully synchronized ${credentials.length} credentials.`,
      count: credentials.length
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Bulk sync credentials error:', error);
    return res.status(500).json({ error: error.message || 'Internal server error.' });
  } finally {
    // Release client back to the pool
    client.release();
  }
});

export default router;
