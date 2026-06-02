import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { DATABASE_URL, DB_PATH } from '../config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const connectionString = DATABASE_URL;

let pool = null;
let sqliteDb = null;
let isPostgres = false;

// Dynamically load the correct database driver
if (connectionString) {
  isPostgres = true;
  console.log('DATABASE_URL environment variable found. Connecting to PostgreSQL...');
  const { default: pg } = await import('pg');

  let ssl = false;
  if (connectionString && !connectionString.includes('localhost') && !connectionString.includes('127.0.0.1')) {
    ssl = {
      rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false' ? false : true
    };
    if (process.env.PGSSLROOTCERT) {
      try {
        ssl.ca = fs.readFileSync(process.env.PGSSLROOTCERT).toString();
      } catch (err) {
        console.error(`Failed to read PGSSLROOTCERT at ${process.env.PGSSLROOTCERT}:`, err.message);
      }
    }
  }

  pool = new pg.Pool({
    connectionString,
    ssl
  });
} else {
  isPostgres = false;
  console.log('DATABASE_URL is not defined. Connecting to SQLite fallback...');
  const { default: Database } = await import('better-sqlite3');
  const dbPath = DB_PATH;
  const resolvedDbPath = path.isAbsolute(dbPath) 
    ? dbPath 
    : path.resolve(__dirname, '..', dbPath);
  
  console.log(`Connecting to SQLite database at: ${resolvedDbPath}`);
  sqliteDb = new Database(resolvedDbPath, { verbose: console.log });
  sqliteDb.pragma('foreign_keys = ON');
}

// Convert PostgreSQL parameterized query placeholders ($1, $2) to SQLite placeholders (?)
function convertPgToSqliteQuery(text) {
  return text.replace(/\$\d+/g, '?');
}

// Unified query runner
export async function query(text, params = []) {
  if (isPostgres) {
    return pool.query(text, params);
  } else {
    const sqliteText = convertPgToSqliteQuery(text);
    
    // Check if the query is a SELECT or contains RETURNING clause (which produces rows)
    const isQuery = /^\s*select/i.test(sqliteText) || /returning/i.test(sqliteText);
    
    if (isQuery) {
      const rows = sqliteDb.prepare(sqliteText).all(params);
      return {
        rows,
        rowCount: rows.length
      };
    } else {
      const info = sqliteDb.prepare(sqliteText).run(params);
      return {
        rows: [],
        rowCount: info.changes,
        lastInsertRowid: info.lastInsertRowid
      };
    }
  }
}

// Mock pool connection client for transactions (e.g. sync route)
const mockSqliteClient = {
  query: async (text, params) => query(text, params),
  release: () => {}
};

export const dbPool = {
  connect: async () => {
    if (isPostgres) {
      return pool.connect();
    } else {
      return mockSqliteClient;
    }
  }
};

export async function initDatabase() {
  if (isPostgres) {
    // Create Users Table (PostgreSQL format)
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255),
        recovery_hash VARCHAR(255),
        encrypted_master_key TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Run column migrations for existing databases
    try {
      await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_hash VARCHAR(255)`);
    } catch (e) {
      console.warn('Migration warning: could not add recovery_hash', e.message);
    }
    try {
      await query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_master_key TEXT`);
    } catch (e) {
      console.warn('Migration warning: could not add encrypted_master_key', e.message);
    }

    // Create Verification Codes Table (PostgreSQL format)
    await query(`
      CREATE TABLE IF NOT EXISTS verification_codes (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        code VARCHAR(10) NOT NULL,
        expires_at TIMESTAMP NOT NULL
      )
    `);

    // Create Credentials Table (PostgreSQL format)
    await query(`
      CREATE TABLE IF NOT EXISTS credentials (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        site_name VARCHAR(255) NOT NULL,
        url VARCHAR(255),
        username VARCHAR(255) NOT NULL,
        ciphertext TEXT NOT NULL,
        iv VARCHAR(255) NOT NULL,
        kdf_salt VARCHAR(255) NOT NULL,
        enc_algo VARCHAR(50) NOT NULL,
        enc_version VARCHAR(10) NOT NULL,
        category VARCHAR(100),
        notes TEXT,
        last_changed_at VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `);

    // Run column migrations for credentials table
    try {
      await query(`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS ciphertext TEXT`);
      await query(`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS iv VARCHAR(255)`);
      await query(`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS kdf_salt VARCHAR(255)`);
      await query(`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS enc_algo VARCHAR(50)`);
      await query(`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS enc_version VARCHAR(10)`);
      await query(`ALTER TABLE credentials DROP COLUMN IF EXISTS password`);
    } catch (e) {
      console.warn('Migration warning: could not alter credentials columns', e.message);
    }
    console.log('PostgreSQL database tables verified/created successfully.');
  } else {
    // Create Users Table (SQLite format)
    sqliteDb.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT,
        recovery_hash TEXT,
        encrypted_master_key TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();

    // Run column migrations for existing SQLite databases
    try {
      sqliteDb.prepare('ALTER TABLE users ADD COLUMN recovery_hash TEXT').run();
    } catch (e) {
      // Column already exists
    }
    try {
      sqliteDb.prepare('ALTER TABLE users ADD COLUMN encrypted_master_key TEXT').run();
    } catch (e) {
      // Column already exists
    }

    // Create Verification Codes Table (SQLite format)
    sqliteDb.prepare(`
      CREATE TABLE IF NOT EXISTS verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        expires_at DATETIME NOT NULL
      )
    `).run();

    // Create Credentials Table (SQLite format)
    sqliteDb.prepare(`
      CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        site_name TEXT NOT NULL,
        url TEXT,
        username TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        kdf_salt TEXT NOT NULL,
        enc_algo TEXT NOT NULL,
        enc_version TEXT NOT NULL,
        category TEXT,
        notes TEXT,
        last_changed_at TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `).run();

    // Run column migrations for credentials table
    try {
      sqliteDb.prepare('ALTER TABLE credentials ADD COLUMN ciphertext TEXT').run();
    } catch (e) {}
    try {
      sqliteDb.prepare('ALTER TABLE credentials ADD COLUMN iv TEXT').run();
    } catch (e) {}
    try {
      sqliteDb.prepare('ALTER TABLE credentials ADD COLUMN kdf_salt TEXT').run();
    } catch (e) {}
    try {
      sqliteDb.prepare('ALTER TABLE credentials ADD COLUMN enc_algo TEXT').run();
    } catch (e) {}
    try {
      sqliteDb.prepare('ALTER TABLE credentials ADD COLUMN enc_version TEXT').run();
    } catch (e) {}
    try {
      sqliteDb.prepare('ALTER TABLE credentials DROP COLUMN password').run();
    } catch (e) {}
    console.log('SQLite database tables verified/created successfully.');
  }
}

export default {
  query,
  initDatabase,
  pool: dbPool
};
