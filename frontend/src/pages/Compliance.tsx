import React, { useState, useEffect } from 'react';
import { complianceApi } from '../api/client';
import { 
  CheckCircle2, Shield, 
  Globe, Landmark, Smartphone, Lock,
  ChevronRight, Download, RefreshCw, BarChart3, LucideIcon
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { VulnScoutSounds } from '../lib/sounds';

type Standard = {
  id: string;
  name: string;
  status: string;
  score: number;
};

const mapIcon = (id: string, name: string): LucideIcon => {
    if (id.includes('dp') || name.includes('Data') || id.includes('soc')) return Shield;
    if (id.includes('bou') || id.includes('cbk')) return Landmark;
    if (name.includes('Mobile')) return Smartphone;
    if (id.includes('iso')) return Lock;
    return Globe;
};

const Compliance: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'core' | 'api' | 'global'>('core');
  const [standards, setStandards] = useState<Record<string, Standard[]>>({
      core: [], api: [], global: []
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
      fetchStandards();
  }, []);

  const fetchStandards = async () => {
    try {
        const res = await complianceApi.get();
        setStandards(res.data.standards);
    } catch (e) {
        console.error(e);
    }
  };

  const handleRecalculate = async () => {
      VulnScoutSounds.play('radarPing');
      setLoading(true);
      try {
          const res = await complianceApi.recalculate();
          setStandards(res.data.standards);
      } catch (e) {
          console.error(e);
      } finally {
          setLoading(false);
      }
  };

  const handleExport = async () => {
      VulnScoutSounds.play('exportBlip');
      try {
          const res = await complianceApi.export();
          const url = window.URL.createObjectURL(new Blob([res.data]));
          const link = document.createElement('a');
          link.href = url;
          link.setAttribute('download', 'compliance_ledger.json');
          document.body.appendChild(link);
          link.click();
          link.remove();
      } catch (e) {
          console.error('Export failed', e);
      }
  };

  return (
    <div className="space-y-8 cyber-grid min-h-screen p-4 sm:p-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-4xl font-black tracking-tighter mb-2 flex items-center gap-3 text-white uppercase leading-none">
            <CheckCircle2 className="text-success h-10 w-10" />
            Audit <span className="text-primary italic">Compliance</span>
          </h1>
          <p className="text-muted-foreground font-mono text-[10px] uppercase tracking-widest px-1">Universal framework alignment and security posture auditing.</p>
        </div>
        <button onClick={handleRecalculate} disabled={loading} className="bg-primary hover:bg-primary/90 text-white font-black px-6 py-3 rounded-xl transition-all shadow-xl neon-blue uppercase tracking-widest text-[10px] flex items-center gap-2">
           <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
           Recalculate Mesh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 bg-card/40 backdrop-blur-xl p-2 rounded-2xl border border-border">
         {[
           { id: 'core', label: 'Core Web Security', icon: Shield },
           { id: 'api', label: 'API Integrity', icon: Lock },
           { id: 'global', label: 'Global Frameworks', icon: Globe },
         ].map(tab => (
           <button
             key={tab.id}
             onClick={() => {
                 VulnScoutSounds.play('buttonClick');
                 setActiveTab(tab.id as any);
             }}
             className={`flex items-center justify-center gap-3 py-3 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${activeTab === tab.id ? 'bg-primary text-white shadow-lg neon-blue' : 'text-muted-foreground hover:bg-white/5 hover:text-white'}`}
           >
             <tab.icon size={16} />
             {tab.label}
           </button>
         ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
        <div className="xl:col-span-2 space-y-4">
           <AnimatePresence mode="wait">
              <motion.div 
                key={activeTab}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="grid grid-cols-1 gap-4"
              >
                {standards[activeTab]?.map((std) => {
                  const Icon = mapIcon(std.id, std.name);
                  return (
                    <div key={std.id} className="glass p-6 rounded-3xl border border-border group hover:border-primary/30 transition-all flex items-center justify-between">
                       <div className="flex items-center gap-6">
                          <div className={`w-14 h-14 rounded-2xl flex items-center justify-center border transition-all ${
                            std.status === 'PASS' ? 'bg-success/5 border-success/20 text-success shadow-[0_0_20px_rgba(34,197,94,0.1)]' :
                            std.status === 'WARN' ? 'bg-warning/5 border-warning/20 text-warning' :
                            'bg-destructive/5 border-destructive/20 text-destructive shadow-[0_0_20px_rgba(239,68,68,0.1)]'
                          }`}>
                             {Icon && <Icon size={24} />}
                          </div>
                          <div>
                             <h3 className="text-sm font-black text-white uppercase tracking-tighter mb-1">{std.name}</h3>
                             <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-widest">{std.id} • Regulatory Framework</p>
                          </div>
                       </div>

                       <div className="flex items-center gap-12">
                          <div className="hidden md:block">
                             <div className="flex justify-between items-end mb-1">
                                <span className="text-[10px] font-black text-muted-foreground uppercase">Alignment</span>
                                <span className="text-[10px] font-black text-white">{std.score}%</span>
                             </div>
                             <div className="w-32 h-1.5 bg-muted rounded-full overflow-hidden">
                                <motion.div 
                                  initial={{ width: 0 }} 
                                  animate={{ width: `${std.score}%` }} 
                                  className={`h-full ${
                                    std.score > 80 ? 'bg-success shadow-[0_0_8px_rgba(34,197,94,0.5)]' :
                                    std.score > 50 ? 'bg-warning' :
                                    'bg-destructive'
                                  }`} 
                                />
                             </div>
                          </div>

                          <div className="flex flex-col items-end min-w-[80px]">
                             <span className={`text-[10px] font-black px-3 py-1 rounded-full uppercase tracking-widest ${
                               std.status === 'PASS' ? 'bg-success/20 text-success border border-success/30' :
                               std.status === 'WARN' ? 'bg-warning/20 text-warning border border-warning/30' :
                               'bg-destructive/20 text-destructive border border-destructive/30'
                             }`}>
                               {std.status}
                             </span>
                          </div>

                          <button className="p-2 text-muted-foreground hover:text-white hover:bg-white/5 rounded-lg transition-all">
                             <ChevronRight size={20} />
                          </button>
                       </div>
                    </div>
                  );
                })}
              </motion.div>
           </AnimatePresence>
        </div>

        <div className="space-y-6">
           <div className="glass p-8 rounded-[32px] border border-border relative overflow-hidden">
              <div className="absolute top-0 right-0 p-4 opacity-5"><BarChart3 size={80} /></div>
              <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white mb-6">Aggregated Posture</h3>
              
              <div className="space-y-8">
                 <div className="text-center">
                    <div className="inline-flex items-center justify-center w-24 h-24 rounded-full border-4 border-primary shadow-[0_0_40px_rgba(14,165,233,0.2)] mb-4">
                       <span className="text-3xl font-black text-white italic">78<span className="text-lg opacity-50">%</span></span>
                    </div>
                    <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Global Regulatory Maturity</p>
                 </div>

                 <div className="space-y-4">
                    <div className="p-4 bg-white/5 border border-border rounded-2xl flex items-center justify-between">
                       <span className="text-[10px] font-black text-muted-foreground uppercase">Violations Found</span>
                       <span className="text-sm font-black text-destructive">14 High Risk</span>
                    </div>
                    <div className="p-4 bg-white/5 border border-border rounded-2xl flex items-center justify-between">
                       <span className="text-[10px] font-black text-muted-foreground uppercase">Review Required</span>
                       <span className="text-sm font-black text-warning">08 Critical Nodes</span>
                    </div>
                 </div>

                 <button onClick={handleExport} className="w-full bg-secondary hover:bg-white/5 border border-border text-white font-black py-4 rounded-2xl transition-all uppercase tracking-widest text-[10px] flex items-center justify-center gap-3">
                    <Download size={16} />
                    Export Compliance Ledger
                 </button>
              </div>
           </div>

           <div className="p-6 bg-primary/5 border border-primary/20 rounded-[32px] text-center">
              <Shield className="mx-auto text-primary mb-3" size={32} />
              <p className="text-[10px] font-black text-white uppercase tracking-widest">Enterprise Shield v4.0</p>
              <p className="text-[9px] text-muted-foreground uppercase tracking-widest mt-1">Real-time legislative tracking active.</p>
           </div>
        </div>
      </div>
    </div>
  );
};

export default Compliance;
