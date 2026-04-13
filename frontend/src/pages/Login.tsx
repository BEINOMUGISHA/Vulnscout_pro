import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, AlertCircle, Mail, Lock, Zap, ArrowRight, ShieldCheck, KeyRound, User, Copy, CheckCircle2 } from 'lucide-react';
import { authApi } from '../api/client';
import { motion, AnimatePresence } from 'framer-motion';

const Login: React.FC = () => {
  const navigate = useNavigate();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [step, setStep] = useState<'credentials' | 'enroll' | 'totp' | 'verify_email' | 'forgot_password' | 'reset_password'>('credentials');
  
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [resetToken, setResetToken] = useState('');
  
  const [totpCode, setTotpCode] = useState('');
  const [factorId, setFactorId] = useState('');
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [totpSecret, setTotpSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const formatError = (err: any): string => {
    if (!err) return '';
    let msg = '';
    if (typeof err === 'string') msg = err;
    else if (err.message) msg = typeof err.message === 'string' ? err.message : JSON.stringify(err.message);
    else msg = 'NETWORK OPERATIONAL FAILURE.';
    
    return msg.toUpperCase();
  };

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      if (mode === 'register') {
        const { data } = await authApi.signup({
          email,
          password,
          name,
        });
        
        if (data?.qr_svg) {
          if (data.login_token) localStorage.setItem('login_token', data.login_token);
          setQrCode(data.qr_svg);
          setTotpSecret(data.totp_secret);
          setStep('enroll');
        } else {
          setStep('verify_email');
        }
      } else {
        const { data } = await authApi.login({
          email,
          password,
        });

        if (data?.totp_required && data.login_token) {
          localStorage.setItem('login_token', data.login_token);
          setStep('totp');
        } else if (data?.access_token) {
          localStorage.setItem('access_token', data.access_token);
          if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);
          navigate('/dashboard');
        }
      }
    } catch (err: any) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleTotpVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const loginToken = localStorage.getItem('login_token') || '';
      const { data } = await authApi.verifyTotp({
        login_token: loginToken,
        code: totpCode,
      });
      
      if (data?.access_token) {
        localStorage.setItem('access_token', data.access_token);
        localStorage.removeItem('login_token');
        navigate('/dashboard');
      }
    } catch (err: any) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleResetRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const { data } = await authApi.requestReset(email);
      setStep('reset_password');
    } catch (err: any) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleResetComplete = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
       setError("CREDENTIAL MISMATCH. RE-ENTER PASSWORDS.");
       return;
    }
    setLoading(true);
    setError(null);
    try {
      const { data } = await authApi.completeReset(resetToken, password);
      setMode('login');
      setStep('credentials');
    } catch (err: any) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  };

  const copySecret = () => {
    if (totpSecret) {
      navigator.clipboard.writeText(totpSecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4 relative overflow-hidden cyber-grid">
      <div className="absolute top-0 left-0 w-full h-full pointer-events-none opacity-20">
         <div className="absolute inset-0 bg-[#0ea5e9]/5 blur-[120px] rounded-full scale-150 transform -translate-y-1/2"></div>
      </div>
      
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-[480px] relative z-10"
      >
        <div className="glass p-10 rounded-[32px] border border-border shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4">
             <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Secure Uplink</span>
             </div>
          </div>

          <div className="flex flex-col items-center mb-10">
            <div className="relative mb-6">
              <div className="w-20 h-20 bg-primary/20 rounded-[24px] flex items-center justify-center border border-primary/30 shadow-[0_0_30px_rgba(14,165,233,0.3)]">
                <ShieldAlert className="w-10 h-10 text-primary" />
              </div>
              <motion.div 
                animate={{ rotate: 360 }}
                transition={{ duration: 10, repeat: Infinity, ease: 'linear' }}
                className="absolute -inset-2 border border-dashed border-primary/20 rounded-full pointer-events-none"
              />
            </div>
            
            <h1 className="text-4xl font-black tracking-tighter text-white uppercase leading-none mb-2">VulnScout <span className="text-primary italic">Pro</span></h1>
            <p className="text-[10px] font-black text-muted-foreground uppercase tracking-[0.4em] text-center">Operational Access Terminal</p>
          </div>

          <AnimatePresence mode="wait">
            {error && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mb-8 overflow-hidden"
              >
                <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-2xl flex gap-3 text-destructive text-[11px] font-black uppercase tracking-wider items-center">
                  <AlertCircle size={18} className="shrink-0" />
                  <p>{error}</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <AnimatePresence mode="wait">
            {step === 'credentials' ?
              <motion.form 
                key="creds"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                onSubmit={handleCredentialsSubmit} 
                className="space-y-5"
              >
                {mode === 'register' && (
                  <motion.div 
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    className="space-y-2"
                  >
                    <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Operative Name</label>
                    <div className="relative group">
                      <User className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground group-focus-within:text-primary transition-colors" size={18} />
                      <input
                        type="text"
                        required
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        className="w-full pl-12 pr-4 py-4 bg-card/60 border border-border rounded-2xl focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all font-mono text-sm uppercase tracking-tight"
                        placeholder="NAME"
                      />
                    </div>
                  </motion.div>
                )}

                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Identity Protocol (Email)</label>
                  <div className="relative group">
                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground group-focus-within:text-primary transition-colors" size={18} />
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full pl-12 pr-4 py-4 bg-card/60 border border-border rounded-2xl focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all font-mono text-sm uppercase tracking-tight"
                      placeholder="analyst@vulnscout.pro"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between px-1">
                    <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">Access Key (Password)</label>
                    {mode === 'login' && <button type="button" onClick={() => setStep('forgot_password')} className="text-[10px] font-black uppercase text-primary hover:underline">Revoke Access</button>}
                  </div>
                  <div className="relative group">
                    <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground group-focus-within:text-primary transition-colors" size={18} />
                    <input
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full pl-12 pr-4 py-4 bg-card/60 border border-border rounded-2xl focus:border-primary focus:ring-2 focus:ring-primary/20 outline-none transition-all font-mono text-sm tracking-[0.3em]"
                      placeholder="••••••••"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-8 bg-primary hover:bg-primary/90 text-white font-black py-4 rounded-2xl transition-all shadow-xl neon-blue uppercase tracking-[0.2em] text-sm flex items-center justify-center gap-3 group disabled:opacity-50"
                >
                  {loading ? (
                    <Zap className="animate-spin text-white" size={20} />
                  ) : (
                    <>
                      {mode === 'login' ? 'Execute Authorization' : 'Initialize Registration'}
                      <ArrowRight size={18} className="group-hover:translate-x-1 transition-transform" />
                    </>
                  )}
                </button>
                
                <p className="text-center text-[10px] font-black text-muted-foreground uppercase tracking-widest pt-2">
                  {mode === 'login' ? 'NEW RECRUIT? ' : 'ALREADY AN OPERATIVE? '}
                  <button 
                    type="button" 
                    onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
                    className="text-primary hover:underline"
                  >
                    {mode === 'login' ? 'REGISTER HERE' : 'ACCESS TERMINAL'}
                  </button>
                </p>
              </motion.form>

            : step === 'verify_email' ?
              <motion.div 
                key="verify"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                className="space-y-6 text-center"
              >
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-[20px] bg-primary/10 text-primary mb-4 border border-primary/20">
                  <Mail className="w-8 h-8" />
                </div>
                <h2 className="text-sm font-black text-white uppercase tracking-widest">Awaiting Verification</h2>
                <p className="text-[10px] text-muted-foreground uppercase tracking-widest mx-auto max-w-[300px] mb-8">
                  Security policies require email confirmation. A secure uplink has been dispatched to your inbox.
                </p>
                <p className="text-[10px] text-white/70 uppercase tracking-widest mx-auto max-w-[300px]">
                  Please verify the link to activate your operative status.
                </p>
                <button
                  onClick={() => { setStep('credentials'); setMode('login'); }}
                  className="w-full mt-6 py-2 text-[10px] font-black text-muted-foreground hover:text-white transition-colors uppercase tracking-[0.3em]"
                >
                  &larr; Return to Terminal
                </button>
              </motion.div>

            : step === 'enroll' ?
              <motion.form 
                key="enroll"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                onSubmit={handleTotpVerify} 
                className="space-y-6 text-center"
              >
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-[16px] bg-primary/10 text-primary mb-2 border border-primary/20">
                  <KeyRound size={24} />
                </div>
                <h2 className="text-sm font-black text-white uppercase tracking-widest">Device Synchronization</h2>
                <p className="text-[10px] text-muted-foreground uppercase tracking-widest mx-auto max-w-[300px]">
                  Scan the sequence below in your hardware token (Authy, Google Auth) to bind this device.
                </p>

                <div className="bg-white p-3 rounded-2xl inline-block mx-auto shadow-2xl">
                  {qrCode ? (
                    <div dangerouslySetInnerHTML={{ __html: qrCode }} className="w-48 h-48" />
                  ) : (
                     <div className="w-48 h-48 flex items-center justify-center bg-gray-100 text-[10px] font-black text-gray-400 uppercase tracking-widest text-center px-4">
                        QR Generation Failed
                     </div>
                  )}
                </div>

                <div className="space-y-2 text-left">
                  <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest pl-1">Manual Setup Key</p>
                  <div className="flex items-center gap-2 bg-card/60 p-3 rounded-xl border border-border group">
                    <code className="flex-1 font-mono text-xs text-primary font-bold tracking-widest">{totpSecret}</code>
                    <button type="button" onClick={copySecret} className="p-2 hover:bg-primary/20 rounded-lg text-muted-foreground hover:text-primary transition-all">
                      {copied ? <CheckCircle2 size={16} /> : <Copy size={16} />}
                    </button>
                  </div>
                </div>

                <input
                  type="text"
                  required
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  className="w-full px-4 py-4 bg-card/60 border border-border rounded-2xl focus:border-primary outline-none transition-all text-center text-3xl tracking-[0.6em] font-black text-white border-b-4 border-b-primary shadow-inner mt-4"
                  placeholder="000000"
                />

                <button
                  type="submit"
                  disabled={loading || totpCode.length !== 6}
                  className="w-full bg-success hover:bg-success/90 text-black font-black py-4 rounded-2xl transition-all shadow-xl neon-green uppercase tracking-[0.2em] text-sm flex items-center justify-center gap-3 disabled:opacity-50"
                >
                  {loading ? <Zap className="animate-spin" size={20} /> : <ShieldCheck size={20} />}
                  Verify & Bind Identity
                </button>
              </motion.form>

            : step === 'totp' ?
              <motion.form 
                key="totp"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                onSubmit={handleTotpVerify} 
                className="space-y-6"
              >
                <div className="text-center mb-8">
                  <div className="inline-flex items-center justify-center w-16 h-16 rounded-[20px] bg-primary/10 text-primary mb-4 border border-primary/20">
                    <KeyRound size={32} />
                  </div>
                  <h2 className="text-sm font-black text-white uppercase tracking-widest">Defensive Override</h2>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-widest mt-2">Enter 6-digit sequence from hardware token.</p>
                </div>

                <input
                  type="text"
                  required
                  autoFocus
                  maxLength={6}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  className="w-full px-4 py-5 bg-card/60 border border-border rounded-2xl focus:border-primary outline-none transition-all text-center text-4xl tracking-[0.6em] font-black text-white border-b-4 border-b-primary shadow-inner"
                  placeholder="000000"
                />

                <button
                  type="submit"
                  disabled={loading || totpCode.length !== 6}
                  className="w-full bg-primary hover:bg-primary/90 text-white font-black py-4 rounded-2xl transition-all shadow-xl neon-blue uppercase tracking-[0.2em] text-sm flex items-center justify-center gap-3 disabled:opacity-50"
                >
                  {loading ? <Zap className="animate-spin" size={20} /> : <ShieldCheck size={20} />}
                  Synchronize Sequence
                </button>
              </motion.form>

            : step === 'forgot_password' ?
              <motion.form 
                key="forgot"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                onSubmit={handleResetRequest} 
                className="space-y-6"
              >
                <div className="text-center mb-8">
                  <div className="inline-flex items-center justify-center w-16 h-16 rounded-[20px] bg-primary/10 text-primary mb-4 border border-primary/20">
                    <ShieldAlert size={32} />
                  </div>
                  <h2 className="text-sm font-black text-white uppercase tracking-widest">Emergency Override</h2>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-widest mt-2">Enter your identity protocol (Email) to initiate credential revocation.</p>
                </div>

                <div className="space-y-2">
                  <div className="relative group">
                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full pl-12 pr-4 py-4 bg-card/60 border border-border rounded-2xl focus:border-primary outline-none transition-all font-mono text-sm uppercase tracking-tight"
                      placeholder="EMAIL"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-primary hover:bg-primary/90 text-white font-black py-4 rounded-2xl transition-all shadow-xl neon-blue uppercase tracking-[0.2em] text-sm flex items-center justify-center gap-3 disabled:opacity-50"
                >
                  {loading ? <Zap className="animate-spin" size={20} /> : <ArrowRight size={20} />}
                  Initiate Revocation
                </button>
                
                <button 
                  type="button" 
                  onClick={() => setStep('credentials')}
                  className="w-full text-[10px] font-black uppercase text-muted-foreground hover:text-white transition-colors"
                >
                  CANCEL REQUEST
                </button>
              </motion.form>

            :
              <motion.form 
                key="reset"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                onSubmit={handleResetComplete} 
                className="space-y-5"
              >
                <div className="text-center mb-6">
                  <div className="inline-flex items-center justify-center w-12 h-12 rounded-[16px] bg-primary/10 text-primary mb-2 border border-primary/20">
                    <KeyRound size={24} />
                  </div>
                  <h2 className="text-sm font-black text-white uppercase tracking-widest">Synchronize New Key</h2>
                </div>

                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Override Token</label>
                  <input
                    type="text"
                    required
                    value={resetToken}
                    onChange={(e) => setResetToken(e.target.value)}
                    className="w-full px-4 py-3 bg-card/60 border border-border rounded-xl focus:border-primary outline-none transition-all font-mono text-xs text-primary text-center tracking-[0.2em]"
                    placeholder="TOKEN_SEQUENCE"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">New Access Key</label>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-4 py-3 bg-card/60 border border-border rounded-xl focus:border-primary outline-none transition-all font-mono text-sm tracking-[0.3em]"
                    placeholder="••••••••"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Confirm Key</label>
                  <input
                    type="password"
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full px-4 py-3 bg-card/60 border border-border rounded-xl focus:border-primary outline-none transition-all font-mono text-sm tracking-[0.3em]"
                    placeholder="••••••••"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-4 bg-success hover:bg-success/90 text-black font-black py-4 rounded-xl transition-all shadow-xl neon-green uppercase tracking-[0.2em] text-sm flex items-center justify-center gap-3 disabled:opacity-50"
                >
                  {loading ? <Zap className="animate-spin" size={20} /> : <ShieldCheck size={20} />}
                  Replace Authorization
                </button>
              </motion.form>
            }
          </AnimatePresence>
        </div>

        <div className="mt-8 flex justify-center gap-6">
           <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-success shadow-[0_0_8px_rgba(34,197,94,0.5)]"></div>
              <span className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">Global Relay Active</span>
           </div>
           <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_rgba(14,165,233,0.5)]"></div>
              <span className="text-[8px] font-black text-muted-foreground uppercase tracking-widest">Encrypted v2.4.1</span>
           </div>
        </div>
      </motion.div>
    </div>
  );
};

export default Login;
