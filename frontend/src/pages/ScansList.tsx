import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api, { scansApi } from '../api/client';
import { 
  Filter, RefreshCw, Search, StopCircle, 
  ChevronRight, CheckSquare, Square,
  Activity, ShieldCheck, Zap
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { VulnScoutSounds } from '../lib/sounds';

const ScansList: React.FC = () => {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const params: any = { limit: 100 };
      if (statusFilter) params.status = statusFilter;
      const res = await api.get('/scans', { params });
      setScans(res.data.items || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [statusFilter]);

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const toggleSelectAll = () => {
    if (selectedIds.length === filteredScans.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredScans.map(s => s.id || s.scan_id));
    }
  };

  const handleBulkTerminate = async () => {
    if (!confirm(`Confirm termination of ${selectedIds.length} active scans?`)) return;
    try {
      await Promise.all(selectedIds.map(id => scansApi.cancel(id)));
      fetchScans();
      setSelectedIds([]);
    } catch (err) {
      alert("Error during bulk termination sequence.");
    }
  };

  const filteredScans = scans.filter(s => 
    s.target_url?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (s.id || s.scan_id).toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-8 cyber-grid">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-6">
        <div>
          <h1 className="text-4xl font-black tracking-tighter mb-2 flex items-center gap-3">
            <Activity className="text-primary h-10 w-10" />
            SCAN LIST
          </h1>
          <p className="text-muted-foreground font-mono text-xs uppercase tracking-widest">
            <span className="text-primary font-bold">{scans.length}</span> SCANS FOUND | SYSTEM READY
          </p>
        </div>
        <Link to="/scans/new" className="w-full md:w-auto bg-primary hover:bg-primary/90 text-white font-black px-8 py-3 rounded-xl transition-all neon-blue uppercase tracking-widest text-sm text-center">
          Start New Scan
        </Link>
      </div>

      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input 
            type="text"
            placeholder="SEARCH BY URL OR ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-12 pr-4 py-3 bg-card border border-border rounded-xl text-xs font-mono uppercase focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
          />
        </div>
        
        <div className="flex gap-2">
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
            <select 
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="pl-10 pr-8 py-3 bg-card border border-border rounded-xl text-xs font-bold uppercase tracking-widest appearance-none outline-none focus:ring-2 focus:ring-primary/50 transition-all"
            >
              <option value="">All Statuses</option>
              <option value="pending">Pending</option>
              <option value="running">Running</option>
              <option value="complete">Complete</option>
              <option value="failed">Failed</option>
            </select>
          </div>
          <button 
            onClick={fetchScans} 
            className="flex items-center gap-2 px-5 py-3 bg-secondary hover:bg-secondary/80 border border-border rounded-xl text-xs font-bold uppercase transition-all"
          >
            <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      <AnimatePresence>
        {selectedIds.length > 0 && (
          <motion.div 
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="bg-primary/10 border border-primary/20 p-4 rounded-xl flex items-center justify-between mb-2">
              <span className="text-xs font-black uppercase tracking-widest text-primary">
                {selectedIds.length} SCANS SELECTED
              </span>
              <div className="flex gap-2">
                <button 
                  onClick={handleBulkTerminate}
                  className="flex items-center gap-2 px-4 py-2 bg-destructive/20 text-destructive hover:bg-destructive hover:text-white border border-destructive/30 rounded-lg text-xs font-bold uppercase transition-all"
                >
                  <StopCircle size={14} /> Stop
                </button>
                <button 
                  onClick={() => setSelectedIds([])}
                  className="px-4 py-2 text-xs font-bold uppercase text-muted-foreground hover:text-white"
                >
                  Clear Selection
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="glass rounded-2xl border-border overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-white/5 border-b border-border">
                <th className="p-5 w-12">
                  <button onClick={toggleSelectAll} className="text-muted-foreground hover:text-primary transition-colors">
                    {selectedIds.length === filteredScans.length && filteredScans.length > 0 ? <CheckSquare size={18} /> : <Square size={18} />}
                  </button>
                </th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Scan ID</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Target URL</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Status</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Vulnerabilities</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Timestamp</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em] text-right">View</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {loading ? (
                <tr><td colSpan={7} className="p-20 text-center text-muted-foreground animate-pulse font-mono uppercase text-xs tracking-widest">Synthesizing Registry...</td></tr>
              ) : filteredScans.length === 0 ? (
                <tr><td colSpan={7} className="p-20 text-center text-muted-foreground space-y-4">
                  <Zap className="mx-auto opacity-20" size={48} />
                  <p className="font-mono uppercase text-xs tracking-widest">No matching sequences found.</p>
                </td></tr>
              ) : (
                filteredScans.map((s, idx) => {
                  const id = s.id || s.scan_id || 'unknown';
                  const isSelected = selectedIds.includes(id);
                  return (
                    <motion.tr 
                      key={id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.03 }}
                      className={`group transition-all ${isSelected ? 'bg-primary/5' : 'hover:bg-white/[0.03]'}`}
                    >
                      <td className="p-5">
                        <button onClick={() => toggleSelect(id)} className={isSelected ? 'text-primary' : 'text-muted-foreground group-hover:text-primary/50'}>
                          {isSelected ? <CheckSquare size={18} /> : <Square size={18} />}
                        </button>
                      </td>
                      <td className="p-5 font-mono text-xs text-primary font-bold">
                        <Link to={`/scans/${id}`} className="hover:underline flex items-center gap-2">
                          #{id.substring(0,8).toUpperCase()}
                          <ChevronRight size={12} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                        </Link>
                      </td>
                      <td className="p-5">
                        <div className="max-w-[180px] sm:max-w-[250px]">
                          <div className="text-sm font-bold truncate group-hover:text-primary transition-colors" title={s.target_url}>{s.target_url}</div>
                          <div className="text-[10px] text-muted-foreground font-mono uppercase">{s.target?.industry || 'GLOBAL SCOPE'}</div>
                        </div>
                      </td>
                      <td className="p-5 text-xs font-bold uppercase">
                        <span className={`flex items-center gap-2 w-fit px-3 py-1 rounded-full border ${
                          s.status === 'running' ? 'bg-primary/10 text-primary border-primary/30 neon-blue animate-pulse' : 
                          s.status === 'complete' ? 'bg-success/10 text-success border-success/30' : 
                          s.status === 'failed' ? 'bg-destructive/10 text-destructive border-destructive/30' : 
                          'bg-muted text-muted-foreground border-border'
                        }`}>
                          {s.status === 'running' && <Activity size={12} />}
                          {s.status}
                        </span>
                      </td>
                      <td className="p-5">
                         <div className="flex gap-1.5 items-center">
                           {(s.findings?.critical > 0 || s.critical_count > 0) ? (
                             <span className="bg-destructive text-white px-2 py-0.5 rounded text-[10px] font-black neon-red">
                               {s.findings?.critical || s.critical_count} 
                             </span>
                           ) : (
                             <ShieldCheck size={16} className="text-success opacity-50" />
                           )}
                           {s.findings?.high > 0 && (
                             <span className="bg-warning text-black px-2 py-0.5 rounded text-[10px] font-black">
                               {s.findings.high}
                             </span>
                           )}
                           <span className="text-[10px] font-mono text-muted-foreground ml-1">
                             / {s.finding_count || s.findings?.total || 0} TOTAL
                           </span>
                         </div>
                      </td>
                      <td className="p-5 text-xs text-muted-foreground font-mono">
                        {new Date(s.created_at || s.start_time).toLocaleDateString()}
                        <span className="block opacity-40 text-[10px]">{new Date(s.created_at || s.start_time).toLocaleTimeString()}</span>
                      </td>
                      <td className="p-5 text-right">
                        <Link 
                          to={`/scans/${id}`} 
                          onClick={() => VulnScoutSounds.play('buttonClick')}
                          className="bg-white/5 hover:bg-primary hover:text-white text-foreground border border-border px-4 py-2 rounded-lg transition-all font-bold text-xs uppercase tracking-widest"
                        >
                          VIEW
                        </Link>
                      </td>
                    </motion.tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ScansList;
