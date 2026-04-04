import React, { useState, useEffect } from 'react';
import { 
  Calendar, Clock, Plus, Trash2, 
  RefreshCw, Play, Pause, AlertCircle,
  Shield, Target
} from 'lucide-react';
import { motion } from 'framer-motion';
import { schedulesApi, targetsApi } from '../api/client';
import { VulnScoutSounds } from '../lib/sounds';

const ScanSchedule: React.FC = () => {
  const [schedules, setSchedules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchSchedules = async () => {
    setLoading(true);
    try {
      const res = await schedulesApi.list();
      setSchedules(res.data as any[] || []);
    } catch (err) {
      console.error('Failed to fetch schedules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSchedules();
  }, []);

  const handleCreate = async () => {
    VulnScoutSounds.play('scanStart');
    try {
      setLoading(true);
      // Fetch available targets to pick one for the demo schedule
      const targetRes = await targetsApi.list();
      const targets = (targetRes.data as any).items || (targetRes.data as any).targets || [];
      if (targets.length === 0) {
        alert("Please create a target first before scheduling a scan.");
        return;
      }
      const target = targets[0];
      
      await schedulesApi.create({
        name: `Automated Perimeter Check - ${target.name || target.url}`,
        target_id: target.target_id,
        frequency: 'weekly',
        enabled: true
      });
      fetchSchedules();
    } catch (e) {
      console.error('Failed to create sequence', e);
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async (s: any) => {
    VulnScoutSounds.play('buttonClick');
    try {
      await schedulesApi.update(s.id, {
        name: s.name,
        target_id: s.target_id,
        frequency: s.frequency,
        enabled: !s.enabled
      });
      fetchSchedules();
    } catch (e) {
      console.error("Failed to toggle schedule", e);
    }
  };

  const handleDelete = async (id: string) => {
    VulnScoutSounds.play('buttonClick');
    if(!window.confirm("Delete this scheduled sequence?")) return;
    try {
      await schedulesApi.delete(id);
      fetchSchedules();
    } catch (e) {
      console.error("Failed to delete schedule", e);
    }
  };

  return (
    <div className="space-y-8 cyber-grid min-h-screen p-4 sm:p-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-4xl font-black tracking-tighter mb-2 flex items-center gap-3">
            <Calendar className="text-primary h-10 w-10" />
            AUTOMATION ORCHESTRATOR
          </h1>
          <p className="text-muted-foreground font-mono text-xs uppercase tracking-widest">
            Configure autonomous surveillance sequences for persistent perimeter defense.
          </p>
        </div>
        <button 
          onClick={handleCreate}
          disabled={loading}
          className="bg-primary hover:bg-primary/90 text-white font-black px-6 py-3 rounded-xl transition-all neon-blue uppercase tracking-widest text-xs flex items-center gap-2"
        >
          <Plus size={16} /> Create Sequence
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          <div className="glass rounded-2xl border-border overflow-hidden">
            <div className="px-6 py-4 border-b border-border bg-white/5 flex justify-between items-center">
              <h3 className="text-xs font-black uppercase tracking-widest text-muted-foreground flex items-center gap-2">
                <Clock size={14} /> Active Schedules
              </h3>
              <button onClick={fetchSchedules} className="text-muted-foreground hover:text-white transition-colors">
                <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
              </button>
            </div>

            <div className="divide-y divide-border/30">
              {loading ? (
                <div className="p-20 text-center animate-pulse font-mono text-xs uppercase tracking-widest text-muted-foreground">
                  Synchronizing Timelines...
                </div>
              ) : schedules.length === 0 ? (
                <div className="p-20 text-center space-y-4">
                  <Shield className="mx-auto opacity-10" size={64} />
                  <p className="text-sm font-mono text-muted-foreground uppercase tracking-widest">No autonomous operations scheduled.</p>
                </div>
              ) : (
                schedules.map((s, idx) => (
                  <motion.div 
                    key={s.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className="p-6 hover:bg-white/[0.02] transition-all flex flex-col sm:flex-row justify-between items-start sm:items-center gap-6"
                  >
                    <div className="flex gap-4 items-start">
                      <button onClick={() => handleToggle(s)} className={`p-3 rounded-xl border transition-colors ${s.enabled ? 'bg-primary/10 border-primary/30 text-primary hover:bg-primary/20' : 'bg-muted border-border text-muted-foreground hover:bg-white/10'}`}>
                        {s.enabled ? <Play size={20} /> : <Pause size={20} />}
                      </button>
                      <div>
                        <h4 className="font-bold text-lg tracking-tight flex items-center gap-2">
                          {s.name}
                          {!s.enabled && <span className="text-[10px] font-black uppercase px-2 py-0.5 bg-muted border border-border rounded">Paused</span>}
                        </h4>
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1">
                          <span className="text-xs text-muted-foreground flex items-center gap-1 font-mono">
                            <Target size={12} /> {s.target_url}
                          </span>
                          <span className="text-xs text-primary font-bold flex items-center gap-1 uppercase tracking-widest">
                            <Clock size={12} /> Every {s.frequency || '24h'}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 w-full sm:w-auto">
                      <div className="flex-1 sm:flex-none text-right px-4 py-2 bg-white/5 border border-border rounded-lg">
                        <span className="block text-[10px] font-black uppercase text-muted-foreground tracking-tighter">Next Execution</span>
                        <span className="text-xs font-mono font-bold text-primary">
                          {s.next_run ? new Date(s.next_run).toLocaleString() : 'CALCULATING...'}
                        </span>
                      </div>
                      <button onClick={() => handleDelete(s.id)} className="p-2 hover:bg-destructive/10 text-muted-foreground hover:text-destructive border border-transparent hover:border-destructive/30 rounded-lg transition-all">
                        <Trash2 size={18} />
                      </button>
                    </div>
                  </motion.div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="glass p-6 rounded-2xl border-border">
            <h3 className="text-xs font-black uppercase tracking-[0.2em] text-muted-foreground flex items-center gap-2 border-b border-border pb-4 mb-6">
              <AlertCircle size={16} className="text-primary"/> Operational Logic
            </h3>
            <ul className="space-y-4 text-xs text-muted-foreground leading-relaxed">
              <li className="flex gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1 shrink-0"></div>
                Autonomous scans inherit full target profiles and technology fingerprints.
              </li>
              <li className="flex gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1 shrink-0"></div>
                Dynamic throttling is applied based on perimeter latency detected during initial probe.
              </li>
              <li className="flex gap-3">
                <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1 shrink-0"></div>
                Critical discoveries trigger immediate secure alerts to designated responders.
              </li>
            </ul>
          </div>

          <div className="bg-card/30 border border-primary/20 p-6 rounded-2xl relative overflow-hidden group">
            <div className="absolute top-0 right-0 w-32 h-32 bg-primary/10 blur-3xl -mr-16 -mt-16 transition-all group-hover:bg-primary/20"></div>
            <h3 className="text-sm font-bold mb-2">SYSTEM ADVISORY</h3>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Recurring surveillance ensures compliance with industry standards like PCI-DSS and SOC2. 
              Schedule sequences for off-peak hours to minimize operational impact.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanSchedule;
