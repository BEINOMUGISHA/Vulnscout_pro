import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  Activity, 
  History, 
  Zap, 
  Search, 
  Shield, 
  Compass, 
  AlertTriangle, 
  ArrowRight,
  Globe,
  Cpu,
  Crosshair,
  Terminal
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import api, { scansApi } from '../api/client';
import LiveMetrics from '../components/LiveMetrics';
import { useAlerts } from '../components/WarRoom/AlertToastProvider';
import PhaseTracker, { ScanPhase } from '../components/WarRoom/PhaseTracker';
import FindingModal, { Finding } from '../components/WarRoom/FindingModal';
import TacticalHUD from '../components/WarRoom/TacticalHUD';
import { VulnScoutSounds } from '../lib/sounds';

import TacticalTerminal from '../components/TacticalTerminal';
import QuickProbeHUD from '../components/QuickProbeHUD';

import ThreatMap from '../components/three/ThreatMap';
import LiveScanEngine from '../components/three/LiveScanEngine';
import CVSSRadialChart from '../components/CVSSRadialChart';

const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({});
  const [globalRisk, setGlobalRisk] = useState<number>(0);
  const [recentFindings, setRecentFindings] = useState<any[]>([]);
  const navigate = useNavigate();
  const [targetUrl, setTargetUrl] = useState('');
  const [showTerminal, setShowTerminal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isProjecting, setIsProjecting] = useState(false);
  
  useEffect(() => {
    document.body.classList.toggle('projector-open', isProjecting);
    return () => { document.body.classList.remove('projector-open'); };
  }, [isProjecting]);

  useEffect(() => {
    document.body.classList.toggle('terminal-open', showTerminal);
    return () => { document.body.classList.remove('terminal-open'); };
  }, [showTerminal]);

  const [probeScanId, setProbeScanId] = useState<string | null>(null);
  const [isProbeOpen, setIsProbeOpen] = useState(false);
  const { showAlert } = useAlerts();
  const prevFindingsCount = useRef<number>(0);

  // Finding Modal State
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const openFinding = (f: any) => {
    setSelectedFinding({
        id: f.id || Math.random().toString(36).substr(2, 9),
        title: f.title || 'Security Finding',
        severity: f.severity || 'low',
        vuln_type: f.vuln_type || 'Discovery',
        description: f.description || 'No detailed analysis available for this indicator.',
        remediation: f.remediation || 'Conduct manual verification of the reported endpoint.',
        url: f.url || f.target_url,
        timestamp: f.timestamp || f.created_at,
        evidence: f.evidence || f.proof
    });
    setIsModalOpen(true);
  };

  const activeScans = scans.filter(s => s.status === 'running');
  const activeScan = activeScans[0];
  const riskScore = globalRisk || Math.min(100, (stats.critical_count * 15) + ((stats.total_findings - stats.critical_count) * 2)) || 0;

  const loadData = async () => {
    try {
      const scansRes = await scansApi.list({ limit: 10 });
      setScans((scansRes.data.items as any[]) || []);

      const statsRes = await scansApi.getStats();
      const newStats = statsRes.data || { total_findings: 0, critical_count: 0 };
      setStats(newStats);
      prevFindingsCount.current = newStats.total_findings;

      try {
        const riskRes = await api.get('/scans/analytics/risk-score');
        setGlobalRisk(riskRes.data.risk_score);
      } catch (e) {
        console.warn("Analytics risk link offline, falling back to local calc.");
      }

      const findingsRes = await scansApi.getRecentFindings(5);
      setRecentFindings(findingsRes.data || []);
      
    } catch (e) {
      console.error("Dashboard intel synch failure:", e);
    }
  };

  useEffect(() => {
    loadData();

    let timerId: ReturnType<typeof setTimeout>;
    const scheduleNext = () => {
      const hasActive = scans.some((s: any) => s.status === 'running');
      timerId = setTimeout(async () => {
        await loadData();
        scheduleNext();
      }, hasActive ? 3000 : 15000);
    };
    scheduleNext();

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.altKey && e.key.toLowerCase() === 'p') {
        setIsProjecting(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      clearTimeout(timerId);
      window.removeEventListener('keydown', handleKeyDown);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!activeScan) return;

    const token = localStorage.getItem('token');
    const scanId = activeScan.id || activeScan.scan_id;
    const url = `/api/v1/scans/${scanId}/status?stream=true&token=${token}`;
    const es = new EventSource(url);
    
    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setScans(prev => prev.map(s => {
          const sid = s.id || s.scan_id;
          if (sid === scanId) return { ...s, ...data };
          return s;
        }));

        if (data.total_findings > prevFindingsCount.current) {
          prevFindingsCount.current = data.total_findings;
          loadData();
        }
      } catch (e) {
        console.error("Dashboard SSE Parse Error:", e);
      }
    };

    es.onerror = () => { es.close(); };
    return () => es.close();
  }, [activeScan?.id || activeScan?.scan_id, activeScan?.status]);

  const handleQuickScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    setIsSubmitting(true);
    setIsProbeOpen(true);
    VulnScoutSounds.play('scanStart');
    try {
      const res = await scansApi.create({ target_url: targetUrl });
      const sid = res.data.id || res.data.scan_id;
      setProbeScanId(sid);
      setScans(prev => [{ id: sid, scan_id: sid, status: 'running', target_url: targetUrl, progress: 2, current_phase: 'starting...', total_findings: 0, created_at: new Date().toISOString() }, ...prev]);
    } catch (e) {
      console.error("Quick deployment failed:", e);
      setIsProbeOpen(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`space-y-6 cyber-grid ${isProjecting ? 'projector-active' : ''}`}
    >
      <QuickProbeHUD isOpen={isProbeOpen} scanId={probeScanId} targetUrl={targetUrl} onClose={() => setIsProbeOpen(false)} onViewDetails={() => navigate(`/scans/${probeScanId}`)} />
      <TacticalTerminal isOpen={showTerminal} onClose={() => setShowTerminal(false)} targetUrl={activeScan?.target_url || targetUrl} />
      
      <div className="fixed inset-0 pointer-events-none opacity-20 overflow-hidden z-0">
        <div className="absolute top-[-10%] right-[-10%] w-[500px] h-[500px] bg-primary/20 blur-[130px] rounded-full"></div>
      </div>

      <div className="flex flex-col xl:flex-row justify-between items-start xl:items-center gap-4 border-b border-white/5 pb-6 relative z-10">
        <div className="flex flex-col xl:flex-row xl:items-center gap-6 flex-1">
          <div>
            <h1 className="text-4xl font-black tracking-tighter text-white mb-1 flex items-center gap-3">
              <Compass className="text-primary h-10 w-10 animate-pulse" />
              DASHBOARD
            </h1>
            <p className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest">
                System Operational | Risk: <span className={riskScore > 70 ? 'text-destructive' : 'text-success'}>{riskScore > 70 ? 'Critical' : 'Nominal'}</span>
            </p>
          </div>

          <div className="flex gap-4">
              <button 
                onClick={() => setShowTerminal(true)} 
                className="flex items-center gap-3 bg-primary/10 text-primary border border-primary/20 px-6 py-3 rounded-xl font-black text-[10px] uppercase tracking-widest hover:bg-primary hover:text-white transition-all"
              >
                <Terminal size={18} /> System Terminal
              </button>
              <button 
                onClick={() => setIsProjecting(!isProjecting)} 
                className={`flex items-center gap-3 border px-6 py-3 rounded-xl font-black text-[10px] uppercase tracking-widest transition-all ${isProjecting ? 'bg-amber-500 text-black border-amber-500' : 'bg-transparent text-amber-500 border-amber-500/30'}`}
              >
                <Shield size={18} /> {isProjecting ? 'Exit Projector' : 'Projector Mode'}
              </button>
          </div>
        </div>
        
        <div className="w-full xl:w-[400px] flex bg-black/40 border border-white/10 p-1 rounded-xl items-center glass">
          <form onSubmit={handleQuickScan} className="flex flex-1">
            <input 
              type="url" required value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} 
              placeholder="PROBE TARGET URL..." className="bg-transparent border-none outline-none text-white px-4 py-3 flex-1 text-[10px] font-mono" 
            />
            <button type="submit" disabled={isSubmitting} className="bg-primary hover:opacity-90 text-white font-black text-[10px] uppercase px-6 py-3 rounded-lg">
              {isSubmitting ? '...' : 'START'}
            </button>
          </form>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 relative z-10">
        <div className="xl:col-span-3 space-y-6">
          <div className="bg-card border border-border rounded-[32px] p-6 text-center shadow-2xl">
            <div className="space-y-3">
              <div className="flex justify-between items-center px-2">
                <Shield size={16} className="text-primary/60" /><span className="text-[9px] font-black uppercase text-muted-foreground">Risk Matrix</span><Activity size={16} className="text-accent/60" />
              </div>
              <div className={`text-7xl font-black tracking-tighter ${riskScore > 75 ? 'text-destructive' : riskScore > 40 ? 'text-warning' : 'text-success'}`}>{riskScore}</div>
              <div className={`text-[10px] font-black uppercase py-1 px-3 rounded-lg bg-black/40 border inline-block ${riskScore > 75 ? 'text-destructive border-destructive/30' : 'text-success border-success/30'}`}>{riskScore > 75 ? 'CRITICAL' : 'SECURE'}</div>
            </div>
          </div>

          <div className="bg-card/40 border border-white/5 rounded-2xl p-6 space-y-6 glass">
            <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-primary/80 flex items-center gap-2"><Cpu size={14} /> Telemetry</h3>
            <div className="space-y-5">
              <div className="space-y-2">
                <div className="flex justify-between items-end"><div className="text-[9px] font-black text-muted-foreground uppercase">Nodes</div><div className="font-mono text-sm font-black text-white">04</div></div>
                <div className="h-1.5 bg-black/50 rounded-full border border-white/5 overflow-hidden"><div className="h-full bg-primary rounded-full w-[65%]"></div></div>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between items-end"><div className="text-[9px] font-black text-muted-foreground uppercase">Efficiency</div><div className="font-mono text-sm font-black text-white">88%</div></div>
                <div className="h-1.5 bg-black/50 rounded-full border border-white/5 overflow-hidden"><div className="h-full bg-accent rounded-full w-[88%]"></div></div>
              </div>
            </div>
          </div>
        </div>

        <div className="xl:col-span-9 space-y-6">
          <AnimatePresence mode="wait">
            {activeScan ? (
              <motion.div key="active" className="bg-primary/5 border border-primary/20 rounded-[32px] overflow-hidden p-6 shadow-2xl flex flex-col lg:flex-row items-center gap-8 group">
                <div className="relative w-32 h-32 rounded-full border-2 border-primary/20 bg-black/20 flex items-center justify-center shrink-0">
                  <Crosshair className="text-primary w-10 h-10 animate-pulse" />
                </div>
                <div className="flex-1 space-y-3">
                    <div className="inline-flex items-center gap-2 bg-primary text-white text-[9px] font-black px-4 py-1.5 rounded-full uppercase italic">Active Mission</div>
                    <h2 className="text-2xl font-black text-white uppercase italic truncate max-w-2xl">{activeScan.target_url}</h2>
                    <div className="w-full space-y-4">
                      <div className="space-y-2">
                        <div className="flex justify-between items-center text-[9px] font-black uppercase text-muted-foreground"><span className="flex items-center gap-2"><Zap size={12} className="text-amber-500" /> Progress</span><span className="text-primary font-mono text-base">{Math.round(activeScan.progress || 1)}%</span></div>
                        <div className="h-2 bg-black/60 rounded-full border border-white/10 overflow-hidden"><motion.div initial={{ width: 0 }} animate={{ width: `${activeScan.progress || 1}%` }} className="h-full bg-primary" /></div>
                      </div>
                      <div className="flex gap-6 pt-1">
                        <div className="flex flex-col gap-0.5"><span className="text-[9px] font-black text-muted-foreground uppercase">Phase</span><span className="text-white font-black font-mono text-[10px] uppercase bg-primary/20 px-2 py-0.5 rounded border border-primary/30">{activeScan.current_phase?.toUpperCase() || 'INIT'}</span></div>
                        <button onClick={() => navigate(`/scans/${activeScan.id}`)} className="ml-auto bg-white text-black text-[10px] font-black uppercase px-6 py-3 rounded-xl">Open Console</button>
                      </div>
                    </div>
                </div>
              </motion.div>
            ) : (
              <motion.div key="idle" className="bg-card border border-border rounded-2xl p-8 text-center space-y-4"><Search className="mx-auto text-muted-foreground/10" size={48} /><h3 className="text-lg font-bold">NO ACTIVE SEQUENCES</h3></motion.div>
            )}
          </AnimatePresence>

          <TacticalHUD activeDetectors={activeScan?.active_detectors || []} findingsByClass={activeScan?.findings_by_class || {}} isScanning={!!activeScan} />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-card/40 border border-white/5 p-6 rounded-[32px] glass"><h3 className="text-[10px] font-black uppercase text-primary mb-6 flex items-center gap-3"><Globe size={18} /> Threat Map</h3><div className="h-[300px] w-full rounded-2xl overflow-hidden border border-white/5"><ThreatMap /></div></div>
            <div className="bg-card/40 border border-white/5 p-6 rounded-[32px] glass"><h3 className="text-[10px] font-black uppercase text-destructive mb-6 flex items-center gap-3"><Shield size={18} /> Vulnerabilities</h3><div className="flex-1 flex items-center justify-center p-2"><CVSSRadialChart data={{critical: stats.critical_count || 0, high: stats.high_count || 0, medium: stats.medium_count || 0, low: stats.low_count || 0, informational: stats.info_count || 0}} total={stats.total_findings || 0} averageScore={riskScore / 10} /></div></div>
          </div>

          <div className="bg-card/40 border border-white/5 p-6 rounded-[32px] glass space-y-8"><h3 className="text-[10px] font-black uppercase text-white/60 flex items-center gap-3 italic"><Crosshair size={18} className="text-amber-500" /> Propagation Intelligence</h3><div className="h-[400px] w-full rounded-2xl overflow-hidden border border-white/5"><LiveScanEngine /></div></div>
          <LiveMetrics />
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-8 pb-10">
          <div className="xl:col-span-2 space-y-8">
              <PhaseTracker currentPhase={(activeScan?.current_phase as ScanPhase) || 'recon'} progress={activeScan?.progress || 0} scanId={activeScan?.id} target={activeScan?.target_url} />
              <div className="bg-card border border-border rounded-3xl overflow-hidden flex flex-col"><div className="p-6 border-b border-border bg-white/5"><h3 className="font-black text-sm uppercase flex items-center gap-3"><History size={18} /> Scan History</h3></div><table className="w-full text-left"><thead><tr className="bg-white/[0.01]"><th className="p-5 text-[10px] font-black text-muted-foreground uppercase">Target</th><th className="p-5 text-[10px] font-black text-muted-foreground uppercase">Status</th><th className="p-5 text-[10px] font-black text-muted-foreground uppercase text-right">Hits</th></tr></thead><tbody className="divide-y divide-border/30">{scans.slice(0, 5).map((s, i) => (<tr key={i} className="hover:bg-white/[0.02] cursor-pointer" onClick={() => navigate(`/scans/${s.id}`)}><td className="p-5 text-sm font-bold text-white">{s.target_url}</td><td className="p-5 text-[10px] font-black uppercase text-white/70">{s.status}</td><td className="p-5 text-right font-mono text-white">{s.total_findings || 0}</td></tr>))}</tbody></table></div>
          </div>
          <div className="xl:col-span-1 border border-border bg-card rounded-2xl overflow-hidden flex flex-col"><div className="p-4 border-b border-border bg-white/5"><h3 className="font-black text-xs uppercase flex items-center gap-2"><AlertTriangle size={14} /> Findings</h3></div><div className="p-4 space-y-4 flex-1 overflow-y-auto max-h-[400px]">{recentFindings.map((f, i) => (<div key={i} onClick={() => openFinding(f)} className="flex flex-col gap-1 border-b border-white/5 pb-3 last:border-0 cursor-pointer hover:text-primary transition-all"><div className="flex justify-between text-[9px] font-black uppercase"><span>{f.vuln_type}</span><span className="text-destructive">{f.severity}</span></div><div className="text-xs font-bold">{f.title}</div></div>))}</div></div>
      </div>

      <FindingModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} finding={selectedFinding} />
      <style>{`
        .projector-active { padding: 40px !important; max-width: 100vw !important; height: 100vh !important; background: #000 !important; position: fixed !important; top: 0 !important; left: 0 !important; z-index: 10000 !important; overflow-y: auto !important; }
        .projector-active::after { content: ""; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.1) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.02), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.02)); background-size: 100% 2px, 2px 100%; pointer-events: none; z-index: 10001; }

        /* Sync with MainLayout to hide tabs/sidebars */
        body.projector-open aside, body.projector-open header, 
        body.terminal-open aside, body.terminal-open header {
            display: none !important;
        }
        body.projector-open main, body.terminal-open main {
            margin: 0 !important;
            padding: 0 !important;
            border: none !important;
        }
        body.projector-open .cyber-grid, body.terminal-open .cyber-grid {
            background: #000 !important;
        }
      `}</style>
    </motion.div>
  );
};

export default Dashboard;
