import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { targetsApi } from '../api/client';
import { 
  Target as TargetIcon, ArrowLeft, Shield, 
  Search, CheckCircle2, AlertTriangle, 
  Settings2, Globe, Cpu, Wifi
} from 'lucide-react';
import { motion } from 'framer-motion';
import { VulnScoutSounds } from '../lib/sounds';

const NewTarget: React.FC = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [industry, setIndustry] = useState('general');
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any>(null);
  const [submitting, setSubmitting] = useState(false);

  const validateUrl = async () => {
    if (!url || !url.startsWith('http')) return;
    VulnScoutSounds.play('radarPing');
    try {
      setValidating(true);
      const res = await targetsApi.validate(url);
      setValidationResult(res.data);
      if (!name) setName(res.data.hostname || '');
    } catch (err) {
      console.error('Validation failed:', err);
    } finally {
      setValidating(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    VulnScoutSounds.play('buttonClick');
    try {
      setSubmitting(true);
      await targetsApi.create({ url, name, industry });
      navigate('/targets');
    } catch (err) {
      console.error('Creation failed:', err);
      alert('Failed to register target. Verify scope authorisation.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-4xl mx-auto p-4 sm:p-8 cyber-grid min-h-screen"
    >
      <button 
        onClick={() => {
            VulnScoutSounds.play('buttonClick');
            navigate(-1);
        }}
        className="flex items-center gap-2 text-muted-foreground hover:text-white transition-colors mb-6 group"
      >
        <ArrowLeft className="group-hover:-translate-x-1 transition-transform" size={18} />
        Back to Registry
      </button>

      <div className="mb-10 text-center sm:text-left">
        <h1 className="text-4xl font-black tracking-tighter mb-2 flex flex-col sm:flex-row items-center sm:items-start gap-3">
          <TargetIcon className="text-primary h-12 w-12 sm:h-10 sm:w-10" />
          DEPLOY SURVEILLANCE
        </h1>
        <p className="text-muted-foreground text-lg">Define new perimeter assets for security fingerprinting.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          <form id="target-form" onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <label className="text-xs font-bold uppercase tracking-widest text-muted-foreground ml-1">Target URL</label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Globe className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
                  <input 
                    type="url"
                    required
                    placeholder="https://example.com"
                    className="w-full bg-card border border-border rounded-lg py-3 pl-10 pr-4 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all font-mono"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                  />
                </div>
                <button 
                  type="button"
                  onClick={validateUrl}
                  disabled={validating || !url}
                  className="bg-secondary hover:bg-secondary/80 text-white px-4 rounded-lg font-bold text-xs uppercase transition-all disabled:opacity-50"
                >
                  {validating ? <Cpu className="animate-spin" size={18} /> : 'Probe'}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-xs font-bold uppercase tracking-widest text-muted-foreground ml-1">Friendly Name</label>
                <input 
                  type="text"
                  required
                  placeholder="Acme Production API"
                  className="w-full bg-card border border-border rounded-lg py-3 px-4 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-bold uppercase tracking-widest text-muted-foreground ml-1">Industry Sector</label>
                <select 
                  className="w-full bg-card border border-border rounded-lg py-3 px-4 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all appearance-none"
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                >
                  <option value="general">General Technology</option>
                  <option value="banking">Banking & Finance</option>
                  <option value="mobile_money">Mobile Money / Fintech</option>
                  <option value="ecommerce">E-Commerce</option>
                  <option value="government">Government / Public</option>
                </select>
              </div>
            </div>

            <div className="glass p-6 rounded-xl border border-border">
              <h3 className="text-sm font-bold mb-4 flex items-center gap-2">
                <Settings2 size={16} className="text-primary" />
                ADVANCED CONFIGURATION
              </h3>
              <div className="space-y-4 opacity-50 pointer-events-none">
                <div className="flex items-center justify-between">
                  <span className="text-xs">Deep Scan subdomains</span>
                  <div className="w-10 h-5 bg-border rounded-full relative">
                    <div className="absolute left-1 top-1 w-3 h-3 bg-white rounded-full"></div>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs">Authorised Perimeter Only</span>
                  <div className="w-10 h-5 bg-primary/40 rounded-full relative">
                    <div className="absolute right-1 top-1 w-3 h-3 bg-white rounded-full"></div>
                  </div>
                </div>
              </div>
              <p className="text-[10px] text-muted-foreground mt-4 italic">Advanced scope controls are dynamically inherited from team policy.</p>
            </div>

            <button 
              type="submit"
              disabled={submitting || !validationResult?.scope_valid}
              className="w-full bg-primary py-4 rounded-xl font-black text-lg tracking-widest uppercase hover:bg-primary/90 transition-all neon-blue disabled:opacity-50 disabled:grayscale"
            >
              {submitting ? 'Registering...' : 'Confirm & Deploy'}
            </button>
          </form>
        </div>

        <div className="space-y-6">
          <div className="glass p-6 rounded-xl border-border h-fit">
            <h3 className="text-xs font-bold uppercase tracking-widest text-muted-foreground mb-6">Probe Results</h3>
            
            {validationResult ? (
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="space-y-6"
              >
                <div className="flex items-start gap-4 p-4 rounded-lg bg-white/5 border border-white/5">
                  {validationResult.scope_valid ? (
                    <CheckCircle2 className="text-success mt-1" size={20} />
                  ) : (
                    <AlertTriangle className="text-destructive mt-1" size={20} />
                  )}
                  <div>
                    <h4 className="font-bold text-sm">Scope Authorisation</h4>
                    <p className="text-xs text-muted-foreground mt-1">
                      {validationResult.message}
                    </p>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground flex items-center gap-2"><Wifi size={14}/> Reachable</span>
                    <span className="text-success font-bold">YES</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground flex items-center gap-2"><Shield size={14}/> SSL/TLS</span>
                    <span className={validationResult.is_https ? 'text-success font-bold' : 'text-warning font-bold'}>
                      {validationResult.is_https ? 'SECURE' : 'INSECURE'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground flex items-center gap-2"><Cpu size={14}/> Infrastructure</span>
                    <span className="font-mono text-[10px] bg-secondary px-2 py-0.5 rounded">{validationResult.target_type}</span>
                  </div>
                </div>

                <div className="pt-4 border-t border-border">
                  <p className="text-[10px] text-muted-foreground leading-relaxed">
                    Automated probing confirms this asset is eligible for high-fidelity surveillance. 
                    Target fingerprint remains valid for 24 hours.
                  </p>
                </div>
              </motion.div>
            ) : (
              <div className="py-20 text-center space-y-4">
                <Search className="mx-auto text-muted-foreground/20" size={48} />
                <p className="text-xs font-mono text-muted-foreground uppercase leading-relaxed">
                  Awaiting asset DNA...<br/>Probe target URL to begin fingerprinting.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default NewTarget;
