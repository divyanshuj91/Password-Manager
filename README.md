# Vaultme: Secure Zero-Knowledge Password Manager

Vaultme is a full-stack, local-first web application designed to store, manage, and audit your credentials securely. Built on a **Zero-Knowledge Security Model**, all cryptographic operations occur strictly client-side. The server and database only store fully encrypted blobs, ensuring your master password and credentials never leave your browser in plain text.

---

##  Cryptographic & Security Architecture

1. **Key Derivation (PBKDF2):**
   - When registering or logging in, the client retrieves a random, unique salt from the backend.
   - Using `crypto-js`, the client runs **PBKDF2 (HMAC-SHA256, 10,000 iterations)** on the master password and salt to derive:
     - An **Encryption Key (256-bit):** Kept strictly in-memory (React context state) and used for AES-256 vault encryption.
     - An **Auth Hash:** Sent to the server as a master password validator.
2. **Authentication & Session Security (Argon2id & HttpOnly Cookies):**
   - The server receives the client's `Auth Hash` and hashes it using **Argon2id** (GPU/ASIC-resistant) before storing it in the database.
   - The KDF salt is embedded directly within the Argon2id hash rather than using a separate column, and is extracted dynamically when requested.
   - Session states are maintained via **JWT (JSON Web Tokens) stored securely in HttpOnly, Secure, and SameSite cookies** to prevent XSS-based token theft.
   - A zero-downtime lazy-migration transparently verifies legacy accounts using bcrypt and upgrades them to Argon2id upon their next successful login.
3. **Zero-Knowledge Vault Storage (AES-256):**
   - Every credential field (site name, username, URL, password, category, notes) is encrypted client-side using **AES-256 (Cipher Block Chaining)** before sending it to the server.
   - Searching, filtering, duplicate audits, and strength scores are computed entirely in the browser memory after vault decryption.
4. **Auto-Lock Security:**
   - The React context monitors user activity (mouse moves, clicks, keystrokes).
   - If inactivity exceeds the user-configured timer (1, 5, or 15 minutes), the in-memory `Encryption Key` is wiped, locking the vault.
5. **Clipboard Auto-Clear:**
   - Copied passwords are automatically overwritten and cleared from the system clipboard 30 seconds after copying to prevent visual/malware leakage.
6. **HaveIBeenPwned API Integration (K-Anonymity):**
   - To check if a password is leaked, the client hashes it locally using SHA-1.
   - The client sends only the **first 5 characters** of the SHA-1 hash to the backend range proxy.
   - The backend proxies the list of suffix matches from HaveIBeenPwned, and the client matches the suffix locally. This prevents your IP or full hash from ever being exposed online.

---

##  Design System & Aesthetics

- **Dark-Only Theme:** Sleek deep dark palette: `#0a0a0f` (bg), `#12121a` (cards), `#1a1a2e` (surfaces).
- **Glow Accents:** Electric purple `#7c3aed` and cyan glow `#06b6d4` with custom glassmorphic overrides.
- **Glassmorphism:** Elegant cards styled using `backdrop-blur-md` and semi-transparent outlines.
- **Smooth Animations:** Framer Motion transitions for modal sliding, page flips, and micro-interactions.
- **Typography:** Configured to load clean Google Font **Inter**.
- **Interactive Score:** SVG progress ring visually grading vault health.

---

## Project Structure

```
Vaultme/
├── client/                      # React Frontend (Vite)
│   ├── src/
│   │   ├── components/          # Navbar, PasswordCard, PasswordModal, StrengthMeter, Toast
│   │   ├── context/             # AuthContext (sessions, keys), VaultContext (decryption, audit)
│   │   ├── hooks/               # useAutoLock, useClipboard, useBreachCheck
│   │   ├── pages/               # Login, Dashboard, Vault, Generator, Audit, Settings
│   │   ├── utils/               # api.js, encryption.js, passwordStrength.js
│   │   ├── App.jsx              # Routing & Keyboard shortcuts
│   │   └── index.css            # Tailwind & Glassmorphic stylesheet
│   └── index.html               # Font load & SEO setup
│
├── server/                      # Express Backend
│   ├── middleware/              # JWT authMiddleware
│   ├── models/                  # SQLite db.js schema loader
│   ├── routes/                  # auth.js, passwords.js, audit.js routers
│   ├── utils/                   # hibp.js Range query client
│   ├── .env                     # Server configurations
│   └── server.js                # Express entry point
```

---

##  Installation & Setup

### Prerequisites
- **Node.js** (v18+ recommended)
- **NPM** (v9+ recommended)

### 1. Backend Setup
1. Open a terminal and navigate to `/server`:
   ```bash
   cd server
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```
   *The server starts on `http://localhost:5000` and creates the SQLite database file `vault.db`.*

#### PostgreSQL & TLS Connection Configuration
If connecting to an external PostgreSQL database (like Neon) using `DATABASE_URL`, TLS certificate validation is strictly enforced by default. You can customize the TLS connection settings in your `.env` file using the following options:
* `DB_SSL_REJECT_UNAUTHORIZED`: Set to `false` to disable SSL/TLS certificate verification (only recommended for local development or trusted private networks). Defaults to `true`.
* `PGSSLROOTCERT`: Specify the path to a custom root CA certificate file if needed to verify your database connection.


### 2. Frontend Setup
1. Open a new terminal and navigate to `/client`:
   ```bash
   cd client
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the Vite development server:
   ```bash
   npm run dev
   ```
   *Open `http://localhost:5173` in your browser.*

### 3. Running Automated Tests
1. Navigate to `/server`:
   ```bash
   cd server
   ```
2. Run the native Node.js test runner to verify cryptographic hashing:
   ```bash
   npm run test
   ```

---

##  Keyboard Shortcuts

- `Ctrl + L` / `Cmd + L`: Instantly lock the vault, wiping keys from memory.
- `Ctrl + K` / `Cmd + K`: Focus the global vault search input from anywhere.
