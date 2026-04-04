import React, { useEffect, useState } from 'react';
import { reportsApi } from '../api/client';
import { 
  FileText, Download, RefreshCw, 
  Search, AlertCircle, CheckCircle2, 
  FileJson, FileBarChart2, MoreVertical,
  CheckSquare, Square, ChevronRight,
  Shield, Zap, Activity
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { VulnScoutSounds } from '../lib/sounds';

const Reports: React.FC = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<'all' | 'executive' | 'technical' | 'compliance'>('all');

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async (playAudio = false) => {
    if (playAudio) VulnScoutSounds.play('radarPing');
    try {
      setLoading(true);
      const response = await reportsApi.list();
      setReports(response.data.reports as any[] || []);
    } catch (error) {
      console.error('Failed to fetch reports:', error);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async (id: string, format: string) => {
    VulnScoutSounds.play('exportBlip');
    try {
      const response = await reportsApi.download(id, format);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `report-${id}.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error('Download failed:', error);
      alert('Failed to download report. It may still be generating.');
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const toggleSelectAll = () => {
    if (selectedIds.length === filteredReports.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredReports.map(r => r.report_id || r.id));
    }
  };

  const filteredReports = reports.filter(r => {
    const matchesSearch = r.title?.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         r.report_type.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesTab = activeTab === 'all' || r.report_type === activeTab;
    return matchesSearch && matchesTab;
  });

  return (
    <div className="space-y-8 cyber-grid p-4 sm:p-8 min-h-screen">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-6">
        <div>
          <h1 className="text-4xl font-black tracking-tighter mb-2 flex items-center gap-3">
            <FileBarChart2 className="text-primary h-10 w-10" />
            INTELLIGENCE REPOSITORY
          </h1>
          <p className="text-muted-foreground font-mono text-xs uppercase tracking-widest">
            <span className="text-primary font-bold">{reports.length}</span> SECURE RECORDS | ARCHIVE STATUS: NOMINAL
          </p>
        </div>
        
        <button 
          onClick={() => fetchReports(true)}
          className="w-full md:w-auto flex items-center justify-center gap-2 bg-secondary text-foreground hover:bg-secondary/80 border border-border px-6 py-3 rounded-xl font-bold uppercase tracking-widest text-xs transition-all"
        >
          <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
          Sync Intelligence
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
            <input 
              type="text"
              placeholder="SEARCH BY RECORD TITLE OR SEQUENCE..."
              className="w-full bg-card border border-border rounded-xl py-3 pl-12 pr-4 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all font-mono text-xs uppercase"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          
          <div className="flex bg-card border border-border rounded-xl p-1">
            {(['all', 'executive', 'technical', 'compliance'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => {
                  VulnScoutSounds.play('buttonClick');
                  setActiveTab(tab);
                }}
                className={`px-4 py-2 rounded-lg text-[10px] font-black uppercase tracking-tighter transition-all ${
                  activeTab === tab ? 'bg-primary text-white shadow-lg neon-blue' : 'text-muted-foreground hover:text-white'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>
        
        <div className="bg-primary/10 border border-primary/20 rounded-xl px-4 py-2 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity size={14} className="text-primary" />
            <span className="text-[10px] font-black tracking-widest text-primary uppercase">Extraction Ready</span>
          </div>
          <span className="text-sm font-mono font-black text-primary">PDF / JSON</span>
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
            <div className="bg-white/5 border border-border p-4 rounded-xl flex items-center justify-between mb-4">
              <span className="text-xs font-black uppercase tracking-widest text-muted-foreground">
                <span className="text-primary">{selectedIds.length}</span> INTELLIGENCE RECORDS SELECTED
              </span>
              <div className="flex gap-2">
                <button 
                  onClick={async () => {
                      for (const id of selectedIds) {
                          await downloadReport(id, 'pdf');
                      }
                      setSelectedIds([]);
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-primary/20 text-primary hover:bg-primary hover:text-white border border-primary/30 rounded-lg text-xs font-bold uppercase transition-all"
                >
                  <Download size={14} /> Bulk Extract
                </button>
                <button 
                  onClick={() => setSelectedIds([])}
                  className="px-4 py-2 text-xs font-bold uppercase text-muted-foreground hover:text-white"
                >
                  Cancel
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="glass rounded-2xl overflow-hidden border border-border shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-white/5 border-b border-border">
                <th className="p-5 w-12">
                  <button onClick={toggleSelectAll} className="text-muted-foreground hover:text-primary transition-colors">
                    {selectedIds.length === filteredReports.length && filteredReports.length > 0 ? <CheckSquare size={18} /> : <Square size={18} />}
                  </button>
                </th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Intel Package</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Classification</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Asset Status</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Recorded At</th>
                <th className="p-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em] text-right">Extraction</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {loading ? (
                <tr><td colSpan={6} className="p-20 text-center text-muted-foreground animate-pulse font-mono uppercase text-xs tracking-widest">Decrypting Records...</td></tr>
              ) : filteredReports.length === 0 ? (
                <tr><td colSpan={6} className="p-20 text-center space-y-4">
                  <Shield className="mx-auto opacity-10" size={64} />
                  <p className="text-xs font-mono text-muted-foreground uppercase tracking-widest">NO INTELLIGENCE RECORDS MATCH THE CURRENT PARAMETERS.</p>
                </td></tr>
              ) : (
                filteredReports.map((report, idx) => {
                  const reportId = report.report_id || report.id;
                  const isSelected = selectedIds.includes(reportId);
                  return (
                    <motion.tr 
                      key={reportId}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.03 }}
                      className={`hover:bg-white/[0.03] transition-all group ${isSelected ? 'bg-primary/5' : ''}`}
                    >
                      <td className="p-5">
                        <button onClick={() => toggleSelect(reportId)} className={isSelected ? 'text-primary' : 'text-muted-foreground group-hover:text-primary/50'}>
                          {isSelected ? <CheckSquare size={18} /> : <Square size={18} />}
                        </button>
                      </td>
                      <td className="p-5">
                        <div className="flex items-center gap-4">
                          <div className={`p-3 rounded-xl border ${
                            report.report_type === 'executive' ? 'bg-accent/10 border-accent/20 text-accent' :
                            report.report_type === 'compliance' ? 'bg-success/10 border-success/20 text-success' :
                            'bg-primary/10 border-primary/20 text-primary'
                          }`}>
                            <FileText size={20} />
                          </div>
                          <div>
                            <p className="font-black text-sm tracking-tight group-hover:text-primary transition-colors">{report.title}</p>
                            <p className="text-[10px] font-mono text-muted-foreground uppercase flex items-center gap-2">
                              {reportId} <ChevronRight size={10} className="opacity-30" /> REF: SEQ-{reportId?.substring(0,6).toUpperCase() || 'UNKNOWN'}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="p-5">
                        <span className={`text-[9px] font-black px-3 py-1 rounded-full border ${
                          report.report_type === 'executive' ? 'bg-accent/20 text-accent border-accent/40' :
                          report.report_type === 'compliance' ? 'bg-success/20 text-success border-success/40 shadow-[0_0_10px_rgba(34,197,94,0.2)]' :
                          'bg-primary/20 text-primary border-primary/40 shadow-[0_0_10px_rgba(59,130,246,0.2)]'
                        } uppercase tracking-widest`}>
                          {report.report_type}
                        </span>
                      </td>
                      <td className="p-5">
                        <div className="flex items-center gap-2 text-xs font-bold uppercase">
                          {report.status === 'complete' ? (
                            <div className="flex items-center gap-2 text-success">
                              <CheckCircle2 size={16} /> NOMINAL
                            </div>
                          ) : report.status === 'failed' ? (
                            <div className="flex items-center gap-2 text-destructive">
                              <AlertCircle size={16} /> COMPROMISED
                            </div>
                          ) : (
                            <div className="flex items-center gap-2 text-primary">
                              <RefreshCw size={16} className="animate-spin" /> SYNCHRONIZING
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="p-5 text-xs text-muted-foreground font-mono">
                        {new Date(report.created_at).toLocaleDateString()}
                        <span className="block opacity-40 text-[10px]">{new Date(report.created_at).toLocaleTimeString()}</span>
                      </td>
                      <td className="p-5 text-right">
                        <div className="flex items-center justify-end gap-2 sm:opacity-0 group-hover:opacity-100 transition-all">
                          <button 
                            onClick={() => downloadReport(reportId, 'pdf')}
                            className="flex items-center gap-2 bg-primary/10 hover:bg-primary text-primary hover:text-white border border-primary/30 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-tighter transition-all shadow-lg"
                          >
                            <Download size={14} /> PDF
                          </button>
                          <button 
                            onClick={() => downloadReport(reportId, 'json')}
                            className="flex items-center gap-2 bg-secondary hover:bg-white/10 text-foreground border border-border px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-tighter transition-all"
                          >
                            <FileJson size={14} /> JSON
                          </button>
                          <button className="p-1.5 hover:bg-white/5 rounded-lg text-muted-foreground hover:text-white transition-all">
                            <MoreVertical size={16} />
                          </button>
                        </div>
                      </td>
                    </motion.tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 pt-4">
        {[
          { icon: Zap, label: 'Real-time Extraction', value: 'Enabled', color: 'text-primary' },
          { icon: Shield, label: 'Data Integrity', value: 'SHA-256 Verified', color: 'text-success' },
          { icon: Activity, label: 'Retention Policy', value: '90 Days', color: 'text-accent' }
        ].map((stat, i) => (
          <div key={i} className="glass p-4 rounded-xl border border-border flex items-center gap-4 group">
            <div className={`p-3 rounded-lg bg-white/5 border border-white/5 ${stat.color} group-hover:scale-110 transition-transform`}>
              <stat.icon size={20} />
            </div>
            <div>
              <p className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">{stat.label}</p>
              <p className="text-sm font-bold text-white uppercase">{stat.value}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Reports;
