import React from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { 
  ShieldAlert, Activity, FileText, Calendar, 
  Settings, LogOut, CheckCircle, Crosshair, Target,
  Bell, Hexagon, Server, Code, Zap, AlertTriangle
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import LiveClock from '../components/WarRoom/LiveClock';

import RiskScorePanel from '../components/WarRoom/RiskScorePanel';

import StatusStrip from '../components/WarRoom/StatusStrip';
import { scansApi } from '../api/client';

const MainLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);
  
  // Dynamic HUD State
  const [riskScore, setRiskScore] = React.useState(45);
  const [apiStatus, setApiStatus] = React.useState('online');
  const [alertCount, setAlertCount] = React.useState(0);
  const [nodeId] = React.useState(() => `VS-PRO-${Math.random().toString(36).substring(2, 6).toUpperCase()}`);
  const [hasActiveScans, setHasActiveScans] = React.useState(false);

  const loadHudData = async () => {
    try {
        const statsRes = await scansApi.getStats();
        const stats = statsRes.data || {};
        setAlertCount(stats.total_findings || 0);
        
        // Calculate dynamic risk if analytics not available
        const calcRisk = Math.min(100, (stats.critical_count * 15) + ((stats.total_findings - stats.critical_count) * 2)) || 0;
        setRiskScore(calcRisk);

        const scansRes = await scansApi.list({ limit: 5 });
        const scans = (scansRes.data.items as any[]) || [];
        setHasActiveScans(scans.some(s => s.status === 'running'));
        setApiStatus('online');
    } catch (e) {
        setApiStatus('offline');
    }
  };

  React.useEffect(() => {
    loadHudData();
    const interval = setInterval(loadHudData, 10000);
    return () => clearInterval(interval);
  }, []);

  const NavItems = () => (
    <>
      <div className="space-y-8">
        <div>
          <p className="px-4 text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-4">Operations Center</p>
          <nav className="space-y-1">
            {[
              { to: '/dashboard', icon: Activity, label: 'Dashboard' },
              { to: '/scans', icon: Crosshair, label: 'Scans' },
              { to: '/targets', icon: Target, label: 'Targets' },
              { to: '/proxy', icon: Server, label: 'Proxy' },
              { to: '/repeater', icon: Code, label: 'Repeater' },
            ].map((item) => (
              <NavLink 
                key={item.to}
                to={item.to} 
                onClick={() => setIsMobileMenuOpen(false)}
                className={({isActive}) => `flex items-center gap-3 px-4 py-3 rounded-xl transition-all group ${isActive ? 'bg-primary text-white shadow-lg neon-blue' : 'text-muted-foreground hover:text-white hover:bg-white/5'}`}
              >
                <item.icon size={18} className="group-hover:scale-110 transition-transform" />
                <span className="text-xs font-black uppercase tracking-widest">{item.label}</span>
                {item.to === '/dashboard' && <div className="ml-auto w-1.5 h-1.5 rounded-full bg-success animate-pulse" />}
              </NavLink>
            ))}
          </nav>
        </div>

        <div>
          <p className="px-4 text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-4">Intelligence & Reports</p>
          <nav className="space-y-1">
            {[
              { to: '/reports', icon: FileText, label: 'Evidence logs' },
              { to: '/schedule', icon: Calendar, label: 'Scheduler' },
              { to: '/compliance', icon: CheckCircle, label: 'Audit Compliance' },
            ].map((item) => (
              <NavLink 
                key={item.to}
                to={item.to} 
                onClick={() => setIsMobileMenuOpen(false)}
                className={({isActive}) => `flex items-center gap-3 px-4 py-3 rounded-xl transition-all group ${isActive ? 'bg-primary text-white shadow-lg neon-blue' : 'text-muted-foreground hover:text-white hover:bg-white/5'}`}
              >
                <item.icon size={18} className="group-hover:scale-110 transition-transform" />
                <span className="text-xs font-black uppercase tracking-widest">{item.label}</span>
              </NavLink>
            ))}
          </nav>
        </div>
      </div>

      <div className="mt-auto pt-8 border-t border-border">
        <RiskScorePanel score={riskScore} />
        
        <NavLink to="/settings" onClick={() => setIsMobileMenuOpen(false)} className={({isActive}) => `flex items-center gap-3 px-4 py-3 rounded-xl transition-all my-4 ${isActive ? 'bg-primary text-white shadow-lg neon-blue' : 'text-muted-foreground hover:text-white hover:bg-white/5'}`}>
          <Settings size={18} />
          <span className="text-xs font-black uppercase tracking-widest">Settings</span>
        </NavLink>
        
        <div className="flex items-center justify-between p-3 bg-card border border-border rounded-2xl group transition-all hover:border-primary/30">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-10 h-10 shrink-0 rounded-xl bg-secondary flex items-center justify-center text-sm font-black text-primary border border-primary/20">
              {user?.email?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-[10px] font-black text-white truncate uppercase tracking-tighter">{user?.email?.split('@')[0]}</div>
              <div className="text-[8px] text-primary/70 font-black uppercase tracking-widest">Agent Level {user?.role === 'admin' ? 5 : 1}</div>
            </div>
          </div>
          <button onClick={logout} className="p-2 text-muted-foreground hover:text-destructive transition-colors">
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </>
  );

  return (
    <div className="min-h-screen flex bg-background cyber-grid">
      {/* Sidebar */}
      <aside className="w-72 bg-card/40 backdrop-blur-xl border-r border-border hidden md:flex flex-col relative z-20">
        <div className="p-8">
          <div className="flex items-center gap-4">
            <div className="relative">
              <div className="w-10 h-10 rounded-xl bg-primary flex items-center justify-center shadow-lg neon-blue">
                <ShieldAlert className="w-6 h-6 text-white" />
              </div>
              <motion.div 
                animate={{ scale: [1, 1.2, 1] }} 
                transition={{ repeat: Infinity, duration: 2 }}
                className="absolute -top-1 -right-1 w-3 h-3 bg-success rounded-full border-2 border-background" 
              />
            </div>
            <div>
              <span className="font-black text-sm tracking-tighter text-white block uppercase leading-tight">Web Vulnerability Scanner</span>
              <span className="text-[8px] font-black tracking-[0.25em] text-primary/70 uppercase">VulnScout Pro</span>
            </div>
          </div>
        </div>

        <div className="flex-1 px-4 py-4 overflow-y-auto flex flex-col">
          <NavItems />
        </div>
      </aside>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <>
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMobileMenuOpen(false)}
              className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 md:hidden"
            />
            <motion.aside 
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed inset-y-0 left-0 w-80 bg-card border-r border-border z-50 md:hidden p-6 flex flex-col"
            >
              <div className="flex items-center justify-between mb-10 px-2">
                <div className="flex items-center gap-3">
                   <ShieldAlert className="w-6 h-6 text-primary" />
                 <div>
                   <span className="font-black text-sm tracking-tighter text-white block uppercase leading-tight">Web Vulnerability Scanner</span>
                   <span className="text-[9px] font-black tracking-[0.25em] text-primary/70 uppercase">VulnScout Pro</span>
                 </div>
                </div>
                <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 text-muted-foreground">
                   <Hexagon size={24} className="rotate-90" />
                </button>
              </div>
              <div className="flex-1 flex flex-col overflow-y-auto pr-2">
                <NavItems />
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
        {/* Header */}
        <header className="h-20 border-b border-border bg-card/40 backdrop-blur-xl flex items-center justify-between px-4 md:px-8 relative z-10">
          <div className="flex items-center gap-4">
             <button 
               onClick={() => setIsMobileMenuOpen(true)}
               className="p-2.5 bg-card/60 hover:bg-white/5 border border-border rounded-xl transition-all md:hidden"
             >
               <Activity size={20} className="text-primary" />
             </button>
              <div className="flex items-center gap-2 p-1.5 bg-card/60 rounded-xl border border-border">
                <div className="p-1.5 bg-primary/10 text-primary rounded-lg border border-primary/20"><Hexagon size={16} /></div>
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest px-2 hidden lg:inline">System Node: {nodeId}</span>
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest px-2 lg:hidden">{nodeId.replace('VS-PRO-', '')}</span>
             </div>

             {/* OpSec Badge */}
             <div className={`hidden sm:flex items-center gap-2 px-3 py-1.5 border rounded-lg transition-all ${hasActiveScans ? 'bg-amber-500/5 border-amber-500/20' : 'bg-cyan-500/5 border-cyan-500/20'}`}>
                <span className={`text-[9px] font-mono font-black tracking-[0.2em] uppercase ${hasActiveScans ? 'text-amber-500 animate-pulse' : 'text-cyan-500'}`}>
                    OP SEC: {hasActiveScans ? 'OVERT' : 'UMBRA'}
                </span>
             </div>
          </div>
          
          <div className="flex items-center gap-4 md:gap-8">
            {/* Live Stats Row */}
            <div className="hidden md:flex items-center gap-6 mr-2">
               {/* Risk Pill */}
               <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border transition-all ${
                 riskScore > 70 ? 'bg-red-500/10 border-red-500/30 text-red-500 animate-pulse' : 
                 riskScore > 40 ? 'bg-amber-500/10 border-amber-500/30 text-amber-500' : 
                 'bg-success/10 border-success/30 text-success'
               }`}>
                 <Zap size={12} />
                 <span className="text-[10px] font-black uppercase tracking-widest">
                   RISK: {riskScore > 70 ? 'CRITICAL' : riskScore > 40 ? 'HIGH' : 'NOMINAL'}
                 </span>
               </div>

               {/* Backend Status */}
               <div className="flex items-center gap-2 group">
                 <div className={`w-2 h-2 rounded-full ${apiStatus === 'online' ? 'bg-success shadow-[0_0_8px_rgba(34,197,94,0.5)]' : 'bg-destructive'}`} />
                 <span className="text-[10px] font-mono font-black text-muted-foreground uppercase tracking-tighter group-hover:text-white transition-colors">
                   API :8000 {apiStatus === 'online' ? '✔' : '✗'}
                 </span>
               </div>

               {/* Alert Badge */}
               {alertCount > 0 && (
                 <motion.div 
                   animate={{ opacity: [1, 0.5, 1] }}
                   transition={{ duration: 1.4, repeat: Infinity }}
                   className="flex items-center gap-2 px-3 py-1.5 bg-red-500 text-white rounded-full shadow-lg shadow-red-500/20 cursor-pointer hover:scale-105 transition-transform"
                   onClick={() => document.getElementById('findings-feed')?.scrollIntoView({ behavior: 'smooth' })}
                 >
                   <AlertTriangle size={12} />
                   <span className="text-[10px] font-black uppercase tracking-widest">
                     {alertCount} ALERTS
                   </span>
                 </motion.div>
               )}
            </div>

            <div className="flex items-center gap-6">
              <LiveClock />
              <button 
                onClick={logout}
                className="p-2.5 bg-card/60 hover:bg-destructive/10 border border-border hover:border-destructive/30 rounded-xl transition-all group flex items-center gap-2"
                title="Logout"
              >
                <LogOut size={18} className="text-muted-foreground group-hover:text-destructive transition-colors" />
                <span className="text-[10px] font-black text-muted-foreground group-hover:text-destructive uppercase tracking-widest hidden xl:inline">Logout</span>
              </button>
              <button className="relative p-2.5 bg-card/60 hover:bg-white/5 border border-border rounded-xl transition-all group">
                <Bell size={18} className="text-muted-foreground group-hover:text-white transition-colors" />
                <div className="absolute top-2.5 right-2.5 w-2 h-2 bg-destructive rounded-full border border-background shadow-lg shadow-destructive/50" />
              </button>
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-auto relative z-0 p-6 md:p-10">
          <motion.div
            initial={{ opacity: 0, scale: 0.99 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5 }}
            className="max-w-7xl mx-auto"
          >
            <Outlet />
          </motion.div>
        </div>
      </main>
      {/* Status Strip (Block 9) */}
      <StatusStrip />
    </div>
  );
};

export default MainLayout;
