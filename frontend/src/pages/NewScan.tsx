import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../api/client';
import { 
  AlertCircle, Zap, ShieldAlert, ArrowLeft, 
  Settings2, Activity, Globe, Target, 
  MousePointer2, ClipboardCheck
} from 'lucide-react';
import { motion } from 'framer-motion';

const NewScan: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const formatError = (err: any): string => {
    if (!err) return '';
    if (typeof err === 'string') return err.toUpperCase();
    if (Array.isArray(err)) {
      return err.map(e => (typeof e === 'string' ? e : e.msg || JSON.stringify(e))).join(' | ').toUpperCase();
    }
    if (typeof err === 'object') {
      return (err.detail || err.message || JSON.stringify(err)).toUpperCase();
    }
    return 'SCAN FAILED.';
  };

  const [formData, setFormData] = useState({
    target_url: '',
    authorised_by: '',
    authorisation_notes: '',
    crawl_depth: '3',
    rate_limit_rps: '2',
    include_ea_context: true,
    respect_robots_txt: true,
    smart_crawling: true,
    auth_type: 'none',
    auth_credentials: {},
  });

  const [enabledChecks, setEnabledChecks] = useState<Set<string>>(new Set(['sqli', 'xss', 'misconfig', 'sensitive_data']));

  const checks = [
    { key: 'sqli', label: 'SQL Injection', hint: 'Blind, Error-Based, Boolean' },
    { key: 'xss', label: 'Cross-Site Scripting', hint: 'Reflected, Stored, DOM' },
    { key: 'xxe', label: 'XXE Detection', hint: 'XML External Entities' },
    { key: 'ssrf', label: 'SSRF Vectors', hint: 'Infrastructure Discovery' },
    { key: 'idor', label: 'IDOR / BOLA', hint: 'Object Level Auth' },
    { key: 'auth_bypass', label: 'Auth Bypass', hint: 'Broken Authentication' },
    { key: 'misconfig', label: 'Misconfiguration', hint: 'Headers, Debug Modes' },
    { key: 'sensitive_data', label: 'Data Leakage', hint: 'Keys, PII, Secrets' },
  ];

  const toggleCheck = (key: string) => {
    const newSession = new Set(enabledChecks);
    if (newSession.has(key)) newSession.delete(key);
    else newSession.add(key);
    setEnabledChecks(newSession);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    // Route directly to live scan view
    navigate('/scans/live');
  };

  return (
    <div className="space-y-8 cyber-grid min-h-screen p-4 sm:p-8">
      <motion.div 
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4"
      >
        <div>
          <h1 className="text-4xl font-black tracking-tighter mb-2 flex items-center gap-3 text-white uppercase">
            <Zap className="text-primary h-10 w-10" />
            New Scan
          </h1>
          <p className="text-muted-foreground font-mono text-xs uppercase tracking-widest px-1">Configure and start a new security scan.</p>
        </div>
        <Link 
          to="/scans" 
          className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-muted-foreground hover:text-white transition-colors group"
        >
          <ArrowLeft size={16} className="group-hover:-translate-x-1 transition-transform" />
          Cancel
        </Link>
      </motion.div>

      {error && (
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-destructive/10 border border-destructive/20 rounded-2xl p-4 flex gap-4 text-destructive items-center shadow-lg"
        >
          <div className="p-2 bg-destructive/20 rounded-lg"><AlertCircle size={20} /></div>
          <div>
            <p className="text-xs font-black uppercase tracking-widest">Scan Failed</p>
            <p className="text-[10px] font-mono mt-1 opacity-80">{error}</p>
          </div>
        </motion.div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-8">
        <form onSubmit={handleSubmit} className="space-y-8">
          
          <div className="glass p-8 rounded-[32px] border border-border shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-10"><Target size={120} /></div>
            
            <div className="relative z-10 space-y-8">
              <div className="flex items-center gap-3 border-b border-border pb-4">
                <Globe className="text-primary" size={20} />
                <h2 className="text-sm font-black uppercase tracking-widest text-white">Target Information</h2>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Target URL <span className="text-destructive">*</span></label>
                  <input 
                    type="url" required placeholder="https://api.v1.target.node"
                    value={formData.target_url} onChange={e => setFormData({...formData, target_url: e.target.value})}
                    className="w-full bg-card border border-border rounded-xl px-4 py-3.5 text-sm font-mono focus:ring-2 focus:ring-primary/40 outline-none transition-all" 
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Authorized Person <span className="text-destructive">*</span></label>
                  <input 
                    type="text" required placeholder="Authorized Identity Name"
                    value={formData.authorised_by} onChange={e => setFormData({...formData, authorised_by: e.target.value})}
                    className="w-full bg-card border border-border rounded-xl px-4 py-3.5 text-sm font-mono focus:ring-2 focus:ring-primary/40 outline-none transition-all" 
                  />
                </div>

                <div className="space-y-2 md:col-span-2">
                  <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground ml-1">Authorization Details</label>
                  <textarea 
                    rows={2} placeholder="Security clearance reference or tactical justification."
                    value={formData.authorisation_notes} onChange={e => setFormData({...formData, authorisation_notes: e.target.value})}
                    className="w-full bg-card border border-border rounded-xl px-4 py-3.5 text-sm font-mono focus:ring-2 focus:ring-primary/40 outline-none transition-all resize-none" 
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="glass p-8 rounded-[32px] border border-border shadow-2xl relative overflow-hidden">
             <div className="relative z-10 space-y-8">
                <div className="flex items-center gap-3 border-b border-border pb-4">
                  <Settings2 className="text-primary" size={20} />
                  <h2 className="text-sm font-black uppercase tracking-widest text-white">Scan Settings</h2>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                   <div className="space-y-6">
                      <div className="space-y-3">
                        <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">Scan Depth</label>
                        <div className="grid grid-cols-4 gap-2">
                           {['1', '2', '3', '5'].map(d => (
                             <button
                               key={d} type="button"
                               onClick={() => setFormData({...formData, crawl_depth: d})}
                               className={`py-3 rounded-xl border text-[10px] font-black uppercase transition-all ${formData.crawl_depth === d ? 'bg-primary border-primary text-white shadow-lg neon-blue' : 'bg-card border-border text-muted-foreground hover:border-primary/50'}`}
                             >
                               Lv {d}
                             </button>
                           ))}
                        </div>
                      </div>

                      <div className="space-y-3">
                        <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">Scan Speed (Requests Per Second)</label>
                        <select 
                          className="w-full bg-card border border-border rounded-xl px-4 py-3 text-xs font-black uppercase tracking-widest focus:ring-2 focus:ring-primary/40 outline-none appearance-none"
                          value={formData.rate_limit_rps} onChange={e => setFormData({...formData, rate_limit_rps: e.target.value})}
                        >
                          <option value="0.5">0.5 (Shadow / Stealth)</option>
                          <option value="1">1.0 (Safe / Standard)</option>
                          <option value="2">2.0 (High Priority)</option>
                          <option value="5">5.0 (Accelerated)</option>
                          <option value="10">UNLIMIT (War Mode)</option>
                        </select>
                      </div>

                      <div className="space-y-3 pt-2">
                        <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">System Overrides</label>
                        <div className="space-y-3">
                           {[
                            { id: 'respect_robots_txt', label: 'Follow robots.txt' },
                             { id: 'smart_crawling', label: 'Use Smart Crawling' },
                           ].map(opt => (
                             <label key={opt.id} className="flex items-center gap-3 cursor-pointer group">
                                <div className={`w-8 h-4 rounded-full relative transition-all ${formData[opt.id as keyof typeof formData] ? 'bg-primary' : 'bg-muted'}`}>
                                   <div className={`absolute top-0.5 w-3 h-3 bg-white rounded-full transition-all ${formData[opt.id as keyof typeof formData] ? 'right-0.5' : 'left-0.5'}`} />
                                </div>
                                <input 
                                  type="checkbox" className="hidden" 
                                  checked={!!formData[opt.id as keyof typeof formData]} 
                                  onChange={e => setFormData({...formData, [opt.id]: e.target.checked})} 
                                />
                                <span className={`text-[10px] font-black uppercase tracking-widest group-hover:text-white transition-colors ${formData[opt.id as keyof typeof formData] ? 'text-primary' : 'text-muted-foreground'}`}>
                                   {opt.label}
                                </span>
                             </label>
                           ))}
                        </div>
                      </div>
                   </div>

                   <div className="space-y-4">
                      <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">Vulnerability Modules</label>
                      <div className="grid grid-cols-1 gap-2 h-[300px] overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-primary/20">
                        {checks.map(c => (
                          <div 
                            key={c.key} 
                            onClick={() => toggleCheck(c.key)}
                            className={`p-3 rounded-2xl border cursor-pointer transition-all flex items-center justify-between group ${enabledChecks.has(c.key) ? 'bg-primary/5 border-primary/40' : 'bg-card border-border hover:border-primary/30'}`}
                          >
                            <div className="flex items-center gap-3">
                               <div className={`p-2 rounded-lg transition-colors ${enabledChecks.has(c.key) ? 'bg-primary text-white shadow-lg neon-blue' : 'bg-secondary text-muted-foreground'}`}>
                                  <MousePointer2 size={14} />
                               </div>
                               <div>
                                  <p className={`text-[10px] font-black uppercase tracking-tighter ${enabledChecks.has(c.key) ? 'text-white' : 'text-muted-foreground'}`}>{c.label}</p>
                                  <p className="text-[8px] text-muted-foreground/60 uppercase">{c.hint}</p>
                               </div>
                            </div>
                            {enabledChecks.has(c.key) && <ClipboardCheck size={16} className="text-primary" />}
                          </div>
                        ))}
                      </div>
                   </div>
                </div>
             </div>
          </div>

          <div className="flex gap-4">
            <button 
              type="submit" 
              disabled={loading} 
              className="flex-1 bg-primary hover:bg-primary/90 text-white font-black px-8 py-5 rounded-3xl transition-all shadow-xl neon-blue uppercase tracking-[0.3em] flex items-center justify-center gap-3 disabled:opacity-50"
            >
              {loading ? <Activity className="animate-spin" size={24} /> : <Zap size={24} />}
              Start Scan
            </button>
          </div>
        </form>

          <div className="space-y-8">
            <div className="glass p-8 rounded-[32px] border border-primary/20 bg-primary/5 relative overflow-hidden">
               <div className="absolute top-0 right-0 p-4 opacity-5"><ShieldAlert size={80} /></div>
               <div className="flex items-center gap-3 mb-4 text-primary">
                  <Activity size={24} />
                  <h3 className="font-black uppercase tracking-widest text-sm italic">Operational Guidance</h3>
               </div>
               <p className="text-[11px] leading-loose text-muted-foreground/80 uppercase font-mono">
                  Ensure all targets are within authorized project scope. 
                  This sequence will perform active vulnerability discovery 
                  and may trigger intrusion detection systems on the target network.
               </p>
            </div>
          </div>
      </div>
    </div>
  );
};

export default NewScan;
