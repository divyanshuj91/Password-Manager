import dotenv from 'dotenv';
import crypto from 'crypto';

// Initialize environment variables from .env file
dotenv.config();

export const PORT = process.env.PORT || 5000;
export const DB_PATH = process.env.DB_PATH || 'vault.db';
export const DATABASE_URL = process.env.DATABASE_URL;

// Secure session key (JWT_SECRET) loader.
// Prevents standard hardcoded fallback vulnerability. If not present in environment,
// it generates a cryptographically secure random key on startup.
let jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.warn('======================================================================');
  console.warn('  WARNING: JWT_SECRET environment variable is not defined!');
  console.warn('  Generating a cryptographically secure random JWT_SECRET dynamically.');
  console.warn('  Note: All active user sessions will log out on server restart.');
  console.warn('======================================================================');
  jwtSecret = crypto.randomBytes(64).toString('hex');
}

export const JWT_SECRET = jwtSecret;
