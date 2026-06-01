import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext.jsx';
import { useToast } from '../components/Toast.jsx';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Eye, EyeOff, Mail, Key, ShieldAlert, ArrowLeft, Loader2, Check } from 'lucide-react';

export default function Recover() {
  const { requestReset, verifyResetCode, completeDestructiveReset, completeRecoveryReset } = useAuth();
  const showToast = useToast();
  const navigate = useNavigate();

  const [step, setStep] = useState(1); // 1: Email, 2: Code, 3: Path selection, 4: Reset Pass
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [resetToken, setResetToken] = useState('');
  
  // Recovery options
  const [recoveryPath, setRecoveryPath] = useState(null); // 'recover' or 'wipe'
  const [recoveryKey, setRecoveryKey] = useState('');
  
  // New password input
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Step 1: Send verification code
  const handleRequestCode = async (e) => {
    e.preventDefault();
    if (!email) return;

    setIsLoading(true);
    try {
      await requestReset(email);
      showToast('If the account exists, a 6-digit code has been sent.', 'success');
      setStep(2);
    } catch (err) {
      showToast(err.response?.data?.error || 'Failed to request reset code.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  // Step 2: Verify verification code
  const handleVerifyCode = async (e) => {
    e.preventDefault();
    if (!code || !email) return;

    setIsLoading(true);
    try {
      const token = await verifyResetCode(email, code);
      setResetToken(token);
      showToast('Code verified successfully.', 'success');
      setStep(3);
    } catch (err) {
      showToast(err.response?.data?.error || 'Invalid or expired code.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  // Step 4: Submit Reset
  const handleResetSubmit = async (e) => {
    e.preventDefault();
    if (!newPassword || newPassword !== confirmPassword) {
      showToast('Passwords do not match.', 'error');
      return;
    }
    if (newPassword.length < 8) {
      showToast('Master password must be at least 8 characters long.', 'warning');
      return;
    }

    setIsLoading(true);
    try {
      if (recoveryPath === 'recover') {
        if (!recoveryKey.startsWith('VM-')) {
          showToast('Invalid Recovery Key format. Must start with VM-', 'warning');
          setIsLoading(false);
          return;
        }
        await completeRecoveryReset(email, resetToken, recoveryKey.trim(), newPassword);
        showToast('Vault recovered and master password reset successfully!', 'success');
      } else {
        await completeDestructiveReset(email, resetToken, newPassword);
        showToast('Vault wiped and master password reset successfully.', 'success');
      }
      navigate('/login');
    } catch (err) {
      showToast(err.message || err.response?.data?.error || 'Failed to complete reset.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 bg-black text-[#e5e2e1] font-sans selection:bg-white selection:text-black">
      <div className="w-full max-w-[460px]">
        <div className="glass-card-heavy p-10 flex flex-col items-center">
          
          {/* Header */}
          <header className="text-center mb-8 w-full">
            <div className="mb-2 flex justify-center">
              <div className="w-12 h-12 rounded-lg border border-white/20 flex items-center justify-center bg-[#121212] mb-4">
                <Shield className="h-6 w-6 text-white" />
              </div>
            </div>
            <h1 className="text-2xl font-medium text-white mb-1">Recover Vault</h1>
            <p className="text-[13px] text-[#737373]">
              {step === 1 && "Request a secure email verification code"}
              {step === 2 && "Enter the 6-digit verification code"}
              {step === 3 && "Choose how to recover your account"}
              {step === 4 && "Set a new master password"}
            </p>
          </header>

          {/* STEP 1: Enter Email */}
          {step === 1 && (
            <form onSubmit={handleRequestCode} className="w-full space-y-6">
              <div className="space-y-1">
                <label className="label-caps block">EMAIL_ADDRESS</label>
                <div className="relative">
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="user@domain.com"
                    className="obsidian-input"
                  />
                </div>
              </div>
              
              <button
                type="submit"
                disabled={isLoading}
                className="btn-primary w-full flex items-center justify-center gap-2"
              >
                {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : "SEND RECOVERY CODE"}
              </button>

              <div className="text-center pt-2">
                <Link to="/login" className="label-caps text-[#8e9192] hover:text-white transition-colors flex items-center justify-center gap-1.5 cursor-pointer">
                  <ArrowLeft className="h-3 w-3" /> Back to Login
                </Link>
              </div>
            </form>
          )}

          {/* STEP 2: Enter Code */}
          {step === 2 && (
            <form onSubmit={handleVerifyCode} className="w-full space-y-6">
              <div className="space-y-1">
                <label className="label-caps block">6-DIGIT_CODE</label>
                <input
                  type="text"
                  maxLength={6}
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="000000"
                  className="obsidian-input text-center tracking-[0.5em] text-lg font-bold font-mono"
                />
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="btn-primary w-full flex items-center justify-center gap-2"
              >
                {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : "VERIFY CODE"}
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="label-caps text-[#8e9192] hover:text-white transition-colors flex items-center justify-center gap-1.5 mx-auto cursor-pointer"
                >
                  <ArrowLeft className="h-3 w-3" /> Edit Email Address
                </button>
              </div>
            </form>
          )}

          {/* STEP 3: Choose Path */}
          {step === 3 && (
            <div className="w-full space-y-4">
              
              {/* Option A: Recover with Key */}
              <button
                onClick={() => { setRecoveryPath('recover'); setStep(4); }}
                className="w-full text-left p-5 border border-[#444748] hover:border-white transition-all bg-black flex flex-col gap-2 cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <Key className="h-4 w-4 text-white" />
                  <span className="text-sm font-bold text-white uppercase tracking-wider">Option A: Full Recovery</span>
                </div>
                <p className="text-xs text-[#8e9192] leading-relaxed">
                  Provide your saved **Recovery Key** to decrypt your vault items. You will keep all your passwords.
                </p>
              </button>

              {/* Option B: Wipe Vault */}
              <button
                onClick={() => { setRecoveryPath('wipe'); setStep(4); }}
                className="w-full text-left p-5 border border-[#444748] hover:border-white transition-all bg-black flex flex-col gap-2 cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-white" />
                  <span className="text-sm font-bold text-white uppercase tracking-wider">Option B: Wipe & Reset</span>
                </div>
                <p className="text-xs text-[#8e9192] leading-relaxed">
                  Reset your master password and **wipe all credentials**. Use this if you lost your Recovery Key.
                </p>
              </button>

              <div className="text-center pt-4">
                <button
                  type="button"
                  onClick={logout => navigate('/login')}
                  className="label-caps text-[#8e9192] hover:text-white transition-colors cursor-pointer"
                >
                  Cancel and Log Out
                </button>
              </div>

            </div>
          )}

          {/* STEP 4: Reset Password Screen */}
          {step === 4 && (
            <form onSubmit={handleResetSubmit} className="w-full space-y-6">
              
              {/* If full recovery path, require the Recovery Key */}
              {recoveryPath === 'recover' ? (
                <div className="space-y-1">
                  <label className="label-caps block">RECOVERY_KEY</label>
                  <input
                    type="text"
                    required
                    placeholder="VM-XXXX-XXXX-XXXX-XXXX"
                    value={recoveryKey}
                    onChange={(e) => setRecoveryKey(e.target.value.toUpperCase())}
                    className="obsidian-input tracking-wider font-mono"
                  />
                  <p className="text-[10px] text-[#8e9192] pt-1">
                    Enter the recovery key generated when you registered.
                  </p>
                </div>
              ) : (
                <div className="p-4 border border-[#444748] bg-[#121212] flex gap-3 text-xs text-[#8e9192] leading-relaxed">
                  <ShieldAlert className="h-5 w-5 text-white flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="text-white font-bold block mb-1">Destructive Vault Wipe</span>
                    Because you don't have a recovery key, all existing passwords in your vault will be permanently deleted.
                  </div>
                </div>
              )}

              {/* New Password */}
              <div className="space-y-1">
                <label className="label-caps block">NEW_MASTER_PASSWORD</label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
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

              {/* Confirm Password */}
              <div className="space-y-1">
                <label className="label-caps block">CONFIRM_NEW_PASSWORD</label>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="obsidian-input"
                />
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="btn-primary w-full flex items-center justify-center gap-2"
              >
                {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : "RESET MASTER PASSWORD"}
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => setStep(3)}
                  className="label-caps text-[#8e9192] hover:text-white transition-colors flex items-center justify-center gap-1.5 mx-auto cursor-pointer"
                >
                  <ArrowLeft className="h-3 w-3" /> Change Recovery Path
                </button>
              </div>

            </form>
          )}

        </div>
      </div>
    </div>
  );
}
