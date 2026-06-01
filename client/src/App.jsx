import React, { useState, useEffect, useRef } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation, useNavigate, Link, Outlet } from 'react-router-dom';
import { useAuth } from './context/AuthContext.jsx';
import { useVault } from './context/VaultContext.jsx';
import { useAutoLock } from './hooks/useAutoLock.js';
import { Shield, Lock, Eye, EyeOff, LayoutDashboard, Key, Sparkles, Award, Settings as SettingsIcon } from 'lucide-react';
import { useToast } from './components/Toast.jsx';

// Pages
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Vault from './pages/Vault.jsx';
import Generator from './pages/Generator.jsx';
import Audit from './pages/Audit.jsx';
import Settings from './pages/Settings.jsx';
import Landing from './pages/Landing.jsx';
import Recover from './pages/Recover.jsx';

// Components
import Navbar from './components/Navbar.jsx';

function AppContent() {
  const { token, isLocked, logout } = useAuth();
  
  // Initialize inactivity auto-lock listener
  useAutoLock();

  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={!token ? <Login /> : <Navigate to="/dashboard" />} />
      <Route path="/recover" element={<Recover />} />

      {/* Protected Routes Layout */}
      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/vault" element={<Vault />} />
        <Route path="/generator" element={<Generator />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/settings" element={<Settings />} />
      </Route>

      {/* Fallback */}
      <Route path="*" element={<Navigate to="/" />} />
    </Routes>
  );
}

// Protected Route Wrapper with In-Place Unlock Screen
function ProtectedRoute() {
  const { token, isLocked, user, unlock, lock } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  // Keyboard Shortcuts (Ctrl+L to lock, Ctrl+K to search)
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ctrl + L (Lock Vault)
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        lock();
        navigate('/login');
      }

      // Ctrl + K (Focus global search bar in Navbar)
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('input[placeholder*="Search vault"]');
        if (searchInput) {
          searchInput.focus();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [lock, navigate]);

  if (!token) {
    return <Navigate to="/login" state={{ from: location }} />;
  }

  // If user is logged in, but vault is locked (no encryption key in-memory)
  if (isLocked) {
    return <UnlockScreen />;
  }

  // Unlocked & Logged In: Render Main Dashboard Layout with Sub-Navigation Links
  return (
    <div className="min-h-screen flex flex-col bg-[#0d0d0d]">
      <Navbar />

      {/* Spacer for fixed Navbar height (h-16 = 4rem) */}
      <div className="h-16 flex-shrink-0" />

      {/* Dynamic Sub-Navigation Bar */}
      <div className="w-full px-6 py-2 border-b border-[#444748] bg-[#131313]/60">
        <div className="max-w-7xl mx-auto flex items-center gap-1 overflow-x-auto" style={{ scrollbarWidth: 'none' }}>
          <SubNavLink to="/dashboard" icon={<LayoutDashboard className="h-4 w-4" />} label="Dashboard" />
          <SubNavLink to="/vault" icon={<Key className="h-4 w-4" />} label="Vault Items" />
          <SubNavLink to="/generator" icon={<Sparkles className="h-4 w-4" />} label="Generator" />
          <SubNavLink to="/audit" icon={<Award className="h-4 w-4" />} label="Security Audit" />
          <SubNavLink to="/settings" icon={<SettingsIcon className="h-4 w-4" />} label="Settings" />
        </div>
      </div>

      {/* Main content routing panel */}
      <main className="flex-1 w-full pb-16">
        <Outlet />
      </main>
    </div>
  );
}

// Sub-Navigation Link Helper
function SubNavLink({ to, icon, label }) {
  const location = useLocation();
  const isActive = location.pathname === to;

  return (
    <Link
      to={to}
      className={`px-3.5 py-2 text-xs font-semibold transition-all flex items-center gap-2 flex-shrink-0 ${
        isActive
          ? 'bg-[#353534] text-white rounded'
          : 'text-[#8e9192] hover:text-white rounded'
      }`}
    >
      {icon}
      <span>{label}</span>
    </Link>
  );
}

// Vault Unlock Overlay Screen
function UnlockScreen() {
  const { user, unlock, logout } = useAuth();
  const [masterPassword, setMasterPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const showToast = useToast();

  const handleUnlockSubmit = async (e) => {
    e.preventDefault();
    if (!masterPassword) return;

    setIsUnlocking(true);
    const success = await unlock(masterPassword);
    setIsUnlocking(false);

    if (success) {
      showToast('Vault unlocked. Access restored.', 'success');
    } else {
      showToast('Incorrect master password.', 'error');
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 bg-black">
      <div className="w-full max-w-[440px] p-4">
        <div className="glass-card-heavy p-10 flex flex-col items-center">
          {/* Shield Icon */}
          <div className="mb-6 flex justify-center">
            <div className="w-12 h-12 rounded-lg border border-white/20 flex items-center justify-center bg-[#121212]">
              <Lock className="h-6 w-6 text-white" />
            </div>
          </div>

          <div className="text-center mb-8">
            <h1 className="text-2xl font-medium text-white mb-1">Vault Locked</h1>
            <p className="text-[14px] text-[#737373]" title={user?.email}>
              {user?.email}
            </p>
          </div>

          <form onSubmit={handleUnlockSubmit} className="w-full space-y-6">
            <div className="space-y-1">
              <label className="label-caps block">MASTER_PASSWORD</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="obsidian-input pr-8"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-0 bottom-3 text-[#8e9192] hover:text-white transition-colors cursor-pointer"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isUnlocking}
              className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isUnlocking ? 'UNLOCKING...' : 'UNLOCK VAULT'}
            </button>
          </form>

          <div className="flex items-center my-6 w-full">
            <div className="flex-1 h-px bg-[#444748]/50" />
            <span className="label-caps px-3">OR</span>
            <div className="flex-1 h-px bg-[#444748]/50" />
          </div>

          <button
            onClick={logout}
            className="label-caps text-[#8e9192] hover:text-white transition-colors cursor-pointer"
          >
            Switch Account / Log Out
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}
