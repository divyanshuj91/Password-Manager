import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { initDatabase } from './models/database.js';
import authRoutes from './routes/auth.js';
import passwordRoutes from './routes/passwords.js';
import auditRoutes from './routes/audit.js';
import { PORT } from './config.js';

// Initialize the database (PostgreSQL if DATABASE_URL is set, otherwise SQLite fallback)
(async () => {
  try {
    await initDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
})();

const app = express();

// Enable CORS for local dev server and Vercel production deployment
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://vault-me.vercel.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || origin.endsWith('.vercel.app')) {
      return callback(null, true);
    }
    return callback(new Error('CORS Policy Blocked'), false);
  },
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Mount Routes
app.use('/api/auth', authRoutes);
app.use('/api/passwords', passwordRoutes);
app.use('/api/audit', auditRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date() });
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err);
  res.status(500).json({ error: 'Internal server error occurred.' });
});

// Start Express server
app.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(`  Vaultme Backend Running                      `);
  console.log(`  Port: ${PORT}                                `);
  console.log(`  Mode: ${process.env.NODE_ENV || 'development'}`);
  console.log(`===============================================`);
});
