import React, { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, Shield, Key, 
  Bell, Cpu, Trash2, Save, RefreshCw, AlertTriangle
} from 'lucide-react';
import { motion } from 'framer-motion';
import { settingsApi } from '../api/client';
import { VulnScoutSounds } from '../lib/sounds';

const Settings: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'general' | 'security' | 'api' | 'notifications'>('general');
  const [loading, setLoading] = useState(false);
  const [settings, setSettings] = useState<any>(null);
  const [enrollment, setEnrollment] = useState<{ totp_secret: string; qr_svg: string } | null>(null);
  const [revealing2fa, setRevealing2fa] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      const res = await settingsApi.get();
      setSettings(res.data.settings);
    } catch (e) {
      console.error(e);
    }
  };

   const handleSave = async () => {
    setLoading(true);
    try {
      if (settings && settings[activeTab]) {
        await settingsApi.update({ category: activeTab, settings: settings[activeTab] });
        alert('CONFIGURATION SYNCHRONIZED SUCCESSFULLY.');
      }
    } catch (e) {
      console.error('Failed to sync', e);
      alert('FAILED TO SYNCHRONIZE.');
    } finally {
      setLoading(false);
    }
  };

  const fetch2faEnrollment = async () => {
    setRevealing2fa(true);
    try {
      const res = await settingsApi.get2fa();
      setEnrollment(res.data);
      VulnScoutSounds.play('radarPing');
    } catch (e) {
      console.error(e);
      alert('FAILED TO RETRIEVE 2FA ENROLLMENT.');
    } finally {
      setRevealing2fa(false);
    }
  };

  const copySecret = () => {
    if (enrollment?.totp_secret) {
      navigator.clipboard.writeText(enrollment.totp_secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      VulnScoutSounds.play('buttonClick');
    }
  };

  const handleReset = async () => {
    VulnScoutSounds.play('buttonClick');
    if (!window.confirm("Are you sure you want to reset all configurations to factory defaults?")) return;
    try {
      setLoading(true);
      const res = await settingsApi.reset();
      setSettings(res.data.settings);
      alert('RESET APPLIED.');
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const updateSetting = (category: string, key: string, value: any) => {
    VulnScoutSounds.play('buttonClick');
    setSettings((prev: any) => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value
      }
    }));
  };

  if (!settings) {
    return <div className="p-8 cyber-grid min-h-screen text-white font-mono uppercase">Retrieving Configuration...</div>;
  }

  return (
    <div className="space-y-8 cyber-grid min-h-screen p-4 sm:p-8">
      <div>
        <h1 className="text-4xl font-black tracking-tighter mb-2 flex items-center gap-3 text-white uppercase">
          <SettingsIcon className="text-primary h-10 w-10" />
          System Configuration
        </h1>
        <p className="text-muted-foreground font-mono text-xs uppercase tracking-widest">
          Manage core operational parameters and secure access protocols.
        </p>
      </div>

      <div className="flex flex-col lg:flex-row gap-8">
        <div className="lg:w-64 space-y-2">
          {[
            { id: 'general', label: 'Operational Core', icon: Cpu },
            { id: 'security', label: 'Defense Protocols', icon: Shield },
            { id: 'api', label: 'Linked Interfaces', icon: Key },
            { id: 'notifications', label: 'Alerting Mesh', icon: Bell },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${
                activeTab === tab.id 
                  ? 'bg-primary text-white shadow-lg neon-blue' 
                  : 'text-muted-foreground hover:bg-white/5 hover:text-white border border-transparent hover:border-border'
              }`}
            >
              <tab.icon size={18} />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex-1 space-y-6">
          <div className="glass p-8 rounded-3xl border border-border shadow-2xl relative overflow-hidden">
             {activeTab === 'general' && (
               <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6">
                 <div className="border-b border-border pb-4 mb-6">
                   <h3 className="text-lg font-black tracking-tight text-white uppercase">Operational Core Settings</h3>
                   <p className="text-xs text-muted-foreground font-mono">Fundamental system behaviors and resource allocation.</p>
                 </div>
                 
                 <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                   <div className="space-y-2">
                     <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground px-1">Global Scan Concurrency</label>
                     <input type="number" value={settings.general['Global Scan Concurrency'] || ''} onChange={e => updateSetting('general', 'Global Scan Concurrency', parseInt(e.target.value))} className="w-full bg-card border border-border rounded-xl px-4 py-3 text-sm font-mono focus:ring-2 focus:ring-primary/50 outline-none transition-all" />
                   </div>
                   <div className="space-y-2">
                     <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground px-1">Telemetry Retention (Days)</label>
                     <input type="number" value={settings.general['Telemetry Retention (Days)'] || ''} onChange={e => updateSetting('general', 'Telemetry Retention (Days)', parseInt(e.target.value))} className="w-full bg-card border border-border rounded-xl px-4 py-3 text-sm font-mono focus:ring-2 focus:ring-primary/50 outline-none transition-all" />
                   </div>
                   <div className="space-y-2 md:col-span-2">
                     <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground px-1">Operational Environment ID</label>
                     <input type="text" value={settings.general['Operational Environment ID'] || ''} onChange={e => updateSetting('general', 'Operational Environment ID', e.target.value)} className="w-full bg-card border border-border rounded-xl px-4 py-3 text-sm font-mono focus:ring-2 focus:ring-primary/50 outline-none transition-all" />
                   </div>
                 </div>
               </motion.div>
             )}

             {activeTab === 'security' && (
               <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6">
                 <div className="border-b border-border pb-4 mb-6">
                   <h3 className="text-lg font-black tracking-tight text-white uppercase">Defense Protocols</h3>
                   <p className="text-xs text-muted-foreground font-mono">Encryption standards and access restriction layers.</p>
                 </div>
                 
                 <div className="space-y-4">
                   <div className="flex items-center justify-between p-4 bg-white/5 border border-border rounded-2xl group transition-all hover:border-primary/30" onClick={() => updateSetting('security', 'Two-Factor Encryption (2FA)', !settings.security['Two-Factor Encryption (2FA)'])}>
                     <div>
                       <p className="text-sm font-bold text-white uppercase tracking-tight">Two-Factor Encryption (2FA)</p>
                       <p className="text-xs text-muted-foreground">Require biometrics or hardware tokens for critical extractions.</p>
                     </div>
                     <div className={`w-12 h-6 rounded-full relative cursor-pointer ${settings.security['Two-Factor Encryption (2FA)'] ? 'bg-primary/20' : 'bg-muted'}`}>
                        <div className={`absolute top-1 w-4 h-4 rounded-full transition-all ${settings.security['Two-Factor Encryption (2FA)'] ? 'right-1 bg-primary shadow-lg neon-blue' : 'left-1 bg-muted-foreground'}`}></div>
                     </div>
                   </div>

                    <div className="flex items-center justify-between p-4 bg-white/5 border border-border rounded-2xl group transition-all hover:border-destructive/30" onClick={() => updateSetting('security', 'Air-Gapped Mode', !settings.security['Air-Gapped Mode'])}>
                      <div>
                        <p className="text-sm font-bold text-white uppercase tracking-tight">Air-Gapped Mode</p>
                        <p className="text-xs text-muted-foreground">Sever all external telemetry feeds and operate in high-secrecy state.</p>
                      </div>
                      <div className={`w-12 h-6 rounded-full relative cursor-pointer ${settings.security['Air-Gapped Mode'] ? 'bg-destructive/20' : 'bg-muted'}`}>
                         <div className={`absolute top-1 w-4 h-4 rounded-full transition-all ${settings.security['Air-Gapped Mode'] ? 'right-1 bg-destructive shadow-lg shadow-destructive/50' : 'left-1 bg-muted-foreground'}`}></div>
                      </div>
                    </div>

                    <div className="p-6 bg-primary/5 border border-primary/20 rounded-2xl space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-bold text-white uppercase tracking-tight">Multi-Factor Authentication</p>
                          <p className="text-xs text-muted-foreground">TOTP-based second layer for operational access.</p>
                        </div>
                        <button 
                          onClick={fetch2faEnrollment}
                          disabled={revealing2fa}
                          className="px-4 py-2 bg-primary/10 hover:bg-primary text-primary hover:text-white border border-primary/30 rounded-lg text-[10px] font-black uppercase transition-all shadow-lg"
                        >
                          {revealing2fa ? 'Processing...' : enrollment ? 'Refetch Sequence' : 'Reveal Enrollment'}
                        </button>
                      </div>

                      {enrollment && (
                        <motion.div 
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          className="pt-4 border-t border-primary/20 flex flex-col items-center gap-6"
                        >
                          <div className="bg-white p-3 rounded-2xl inline-block mx-auto shadow-2xl">
                            <div dangerouslySetInnerHTML={{ __html: enrollment.qr_svg }} className="w-40 h-40" />
                          </div>
                          
                          <div className="w-full space-y-2">
                             <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest text-center">Manual Secret Key</p>
                             <div className="flex items-center gap-2 bg-card/60 p-3 rounded-xl border border-border group w-full">
                               <code className="flex-1 font-mono text-xs text-primary font-bold tracking-widest text-center">{enrollment.totp_secret}</code>
                               <button 
                                  onClick={copySecret}
                                  className="p-2 hover:bg-primary/20 rounded-lg text-muted-foreground hover:text-primary transition-all"
                               >
                                 {copied ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
                               </button>
                             </div>
                          </div>
                        </motion.div>
                      )}
                    </div>
                  </div>
               </motion.div>
             )}

             {activeTab === 'api' && (
               <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6">
                 <div className="border-b border-border pb-4 mb-6 flex justify-between items-end">
                   <div>
                     <h3 className="text-lg font-black tracking-tight text-white uppercase">Linked Interfaces</h3>
                     <p className="text-xs text-muted-foreground font-mono">Secure API gateways and service mesh tokens.</p>
                   </div>
                   <button className="text-[10px] font-black uppercase text-primary hover:underline">Rotate All Keys</button>
                 </div>
                 
                 <div className="space-y-4">
                   {['Production Gateway', 'Analytics Socket', 'Compliance Node'].map((api) => (
                     <div key={api} className="p-4 bg-card border border-border rounded-2xl flex items-center justify-between">
                       <div className="flex items-center gap-3">
                         <div className="p-2 bg-secondary rounded-lg text-muted-foreground"><Key size={16} /></div>
                         <span className="text-sm font-bold">{api}</span>
                       </div>
                       <input value={settings.api[api] || ''} onChange={e => updateSetting('api', api, e.target.value)} className="text-[10px] font-mono bg-white/5 px-3 py-1.5 rounded text-primary border border-primary/20 outline-none focus:border-primary/50 focus:bg-white/10 w-48 transition-all" />
                     </div>
                   ))}
                 </div>
               </motion.div>
             )}

             {activeTab === 'notifications' && (
               <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-6">
                 <div className="border-b border-border pb-4 mb-6">
                   <h3 className="text-lg font-black tracking-tight text-white uppercase">Alerting Mesh</h3>
                   <p className="text-xs text-muted-foreground font-mono">Relay sequences for critical discoveries and system events.</p>
                 </div>
                 
                 <div className="space-y-4">
                   <div className="p-6 bg-white/5 border border-border rounded-2xl">
                     <p className="text-sm font-bold mb-4 uppercase">Discovery Relays</p>
                     <div className="space-y-3">
                        {['Critical Vulnerability', 'Scan Start/Stop', 'Node Offline'].map(item => (
                          <div key={item} className="flex items-center gap-3">
                            <input type="checkbox" checked={!!settings.notifications[item]} onChange={e => updateSetting('notifications', item, e.target.checked)} className="w-4 h-4 rounded border-border bg-card text-primary focus:ring-primary/50" />
                            <span className="text-xs text-muted-foreground font-mono uppercase">{item}</span>
                          </div>
                        ))}
                     </div>
                   </div>
                 </div>
               </motion.div>
             )}

             <div className="mt-12 flex justify-end gap-4">
               <button onClick={handleReset} className="px-6 py-3 text-xs font-black uppercase text-muted-foreground hover:text-white transition-colors">Reset to Default</button>
               <button 
                onClick={handleSave}
                disabled={loading}
                className="bg-primary hover:bg-primary/90 text-white font-black px-8 py-3 rounded-xl transition-all shadow-xl neon-blue uppercase tracking-widest text-xs flex items-center gap-2"
               >
                 {loading ? <RefreshCw className="animate-spin" size={16} /> : <Save size={16} />}
                 Commit Changes
               </button>
             </div>
          </div>

          <div className="glass p-6 rounded-3xl border border-destructive/20 flex items-center justify-between">
            <div className="flex items-center gap-4 text-destructive">
               <div className="p-3 bg-destructive/10 rounded-2xl"><AlertTriangle /></div>
               <div>
                 <p className="text-sm font-black uppercase">Destroy Repository</p>
                 <p className="text-xs text-muted-foreground">Permanent erasure of all scan history, targets, and reports.</p>
               </div>
            </div>
            <button className="p-3 hover:bg-destructive text-muted-foreground hover:text-white border border-border hover:border-destructive rounded-xl transition-all group">
              <Trash2 size={20} className="group-hover:scale-110" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
