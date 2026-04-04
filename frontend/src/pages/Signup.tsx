import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldAlert, AlertCircle, Mail, Lock, Zap, ArrowRight, User, CheckCircle2 } from 'lucide-react';
import { authApi } from '../api/client';
import { motion, AnimatePresence } from 'framer-motion';
import { VulnScoutSounds } from '../lib/sounds';

const Signup: React.FC = () => {
  const navigate = useNavigate();

  const [step, setStep] = useState<'details' | 'success'>('details');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const formatError = (err: any): string => {
    return (err.message || 'REGISTRATION REJECTED.').toUpperCase();
  };

  const handleDetailsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError('PASSWORDS DO NOT MATCH.');
      return;
    }
    
    setLoading(true);
    setError(null);
    try {
      const { data, error: signUpError } = await authApi.signup({
        email,
        password,
        name,
      });
      
      if (signUpError) throw signUpError;
      
      if (data?.qr_svg) {
        localStorage.setItem('signup_token', data.provisioning_uri);
        setStep('success');
      } else {
        setStep('success');
      }
      VulnScoutSounds.play('radarPing');
    } catch (err: any) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4 relative overflow-hidden cyber-grid">
      <div className="absolute top-0 left-0 w-full h-full pointer-events-none opacity-20">
         <div className="absolute inset-0 bg-primary/5 blur-[120px] rounded-full scale-150 transform -translate-y-1/2"></div>
      </div>
      
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-[520px] relative z-10"
      >
        <div className="glass p-10 rounded-[32px] border border-border shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4">
             <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Recruitment Portal</span>
             </div>
          </div>

          <div className="flex flex-col items-center mb-10">
            <div className="relative mb-6">
              <div className="w-16 h-16 bg-primary/20 rounded-[20px] flex items-center justify-center border border-primary/30 shadow-[0_0_30px_rgba(14,165,233,0.3)]">
                <ShieldAlert className="w-8 h-8 text-primary" />
              </div>
            </div>
            
            <h1 className="text-3xl font-black tracking-tighter text-white uppercase leading-none mb-2">Initialize <span className="text-primary italic">Identity</span></h1>
            <p className="text-[10px] font-black text-muted-foreground uppercase tracking-[0.4em] text-center">New Operative Enrollment</p>
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
            {step === 'details' ? (
              <motion.form 
                key="details"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                onSubmit={handleDetailsSubmit} 
                className="grid grid-cols-1 gap-5"
              >
                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Full Name</label>
                  <div className="relative group">
                    <User className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground group-focus-within:text-primary transition-colors" size={18} />
                    <input
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      className="w-full pl-12 pr-4 py-3 bg-card/60 border border-border rounded-2xl focus:border-primary outline-none transition-all font-mono text-sm uppercase"
                      placeholder="OPERATIVE NAME"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Email Address</label>
                  <div className="relative group">
                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground group-focus-within:text-primary transition-colors" size={18} />
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full pl-12 pr-4 py-3 bg-card/60 border border-border rounded-2xl focus:border-primary outline-none transition-all font-mono text-sm uppercase"
                      placeholder="RECRUIT@VULNSCOUT.PRO"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Password</label>
                    <div className="relative group">
                      <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground group-focus-within:text-primary transition-colors" size={18} />
                      <input
                        type="password"
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full pl-12 pr-4 py-3 bg-card/60 border border-border rounded-2xl focus:border-primary outline-none transition-all font-mono text-sm tracking-widest"
                        placeholder="••••••••"
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Confirm</label>
                    <div className="relative group">
                      <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground group-focus-within:text-primary transition-colors" size={18} />
                      <input
                        type="password"
                        required
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className="w-full pl-12 pr-4 py-3 bg-card/60 border border-border rounded-2xl focus:border-primary outline-none transition-all font-mono text-sm tracking-widest"
                        placeholder="••••••••"
                      />
                    </div>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full mt-4 bg-primary hover:bg-primary/90 text-white font-black py-4 rounded-2xl transition-all shadow-xl neon-blue uppercase tracking-[0.2em] text-sm flex items-center justify-center gap-3 group disabled:opacity-50"
                >
                  {loading ? (
                    <Zap className="animate-spin text-white" size={20} />
                  ) : (
                    <>
                      Begin Enrollment
                      <ArrowRight size={18} className="group-hover:translate-x-1 transition-transform" />
                    </>
                  )}
                </button>
                
                <p className="text-center text-[10px] font-black text-muted-foreground uppercase tracking-widest">
                  ALREADY AN OPERATIVE? <Link to="/login" className="text-primary hover:underline">ACCESS TERMINAL</Link>
                </p>
              </motion.form>

            ) : (
              <motion.div 
                key="success"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="text-center py-10"
              >
                <div className="w-20 h-20 bg-success/20 rounded-full flex items-center justify-center mx-auto mb-6 border border-success/30 shadow-[0_0_30px_rgba(34,197,94,0.3)]">
                  <CheckCircle2 size={40} className="text-success" />
                </div>
                <h2 className="text-2xl font-black text-white uppercase tracking-tighter mb-2">Access Granted</h2>
                <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-10">
                  Operative identity initialized and secured. Proceed to the access terminal.
                </p>
                <button
                  onClick={() => navigate('/login')}
                  className="px-10 bg-primary hover:bg-primary/90 text-white font-black py-4 rounded-2xl transition-all shadow-xl neon-blue uppercase tracking-[0.2em] text-sm"
                >
                  Finalize Uplink
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </div>
  );
};

export default Signup;
