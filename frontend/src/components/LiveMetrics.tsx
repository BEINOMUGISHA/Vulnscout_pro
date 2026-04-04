import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, Zap, ShieldCheck, Bug, RefreshCw } from 'lucide-react';
import { scansApi } from '../api/client';

interface MetricData {
  label: string;
  value: string;
  icon: React.ElementType;
  color: string;
  bg: string;
  border: string;
  live?: boolean;
}

const LiveMetrics: React.FC = () => {
  const [scanCount, setScanCount] = useState<number | null>(null);
  const [findingCount, setFindingCount] = useState<number | null>(null);
  const [targetCount, setTargetCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = async () => {
    try {
      const res = await scansApi.getStats();
      const data = res.data;
      
      setScanCount(data.total_scans as number ?? 0);
      setTargetCount(Object.values(data.status_counts || {}).reduce((a: any, b: any) => a + (b as number), 0) as number); 
      setFindingCount(data.total_findings as number ?? 0);
      
      // If we want real target count, we should ideally have a targetsApi.getStats() too
      // but scansApi.getStats() gives us the most important live numbers.
    } catch (e) {
      console.error("Metrics synchronization failure", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 30_000); // refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fmt = (n: number | null) =>
    n === null ? '—' : n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n);

  const metrics: MetricData[] = [
    {
      label: 'Active Targets',
      value: fmt(targetCount),
      icon: Activity,
      color: 'text-primary',
      bg: 'bg-primary/10',
      border: 'border-primary/20',
      live: true,
    },
    {
      label: 'Scans Executed',
      value: fmt(scanCount),
      icon: Zap,
      color: 'text-warning',
      bg: 'bg-warning/10',
      border: 'border-warning/20',
    },
    {
      label: 'Scanner Status',
      value: loading ? 'POLLING' : 'ONLINE',
      icon: ShieldCheck,
      color: 'text-success',
      bg: 'bg-success/10',
      border: 'border-success/20',
    },
    {
      label: 'Reports Generated',
      value: fmt(findingCount),
      icon: Bug,
      color: 'text-destructive',
      bg: 'bg-destructive/10',
      border: 'border-destructive/20',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
      {metrics.map((stat, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: i * 0.1 }}
          className={`relative overflow-hidden glass p-8 rounded-[32px] border ${stat.border} group hover:bg-white/[0.08] transition-all shadow-xl hover:shadow-${stat.color.split('-')[1]}/5 hover:-translate-y-1`}
        >
          <div className="absolute top-0 left-0 w-2 h-full bg-current opacity-30 shadow-[0_0_10px_currentColor] transition-all group-hover:opacity-80" />
          <div className="absolute -top-12 -right-12 w-24 h-24 bg-current opacity-[0.03] rounded-full blur-2xl group-hover:opacity-[0.08] transition-opacity" />

          <div className="flex items-center gap-4 mb-8">
            <div className={`p-3 rounded-xl ${stat.bg} ${stat.color} shadow-lg shadow-black/20`}>
              <stat.icon size={22} className="animate-pulse" />
            </div>
            <span className="text-[11px] font-black text-muted-foreground uppercase tracking-[0.3em] italic">
              {stat.label}
            </span>
            {stat.live && (
              <span className="ml-auto flex items-center gap-2 text-[10px] font-black text-success uppercase tracking-[0.2em] bg-success/10 px-3 py-1 rounded-full animate-pulse border border-success/20">
                <span className="w-1.5 h-1.5 rounded-full bg-success shadow-[0_0_5px_#22c55e]" />
                LIVE
              </span>
            )}
          </div>

          <div className="flex items-end justify-between relative z-10">
            <div className={`text-6xl font-black tracking-tighter leading-none select-all ${stat.color} drop-shadow-[0_0_20px_rgba(0,0,0,0.5)]`}>
              {loading && stat.value === '—' ? (
                <RefreshCw size={36} className="animate-spin opacity-40 text-primary" />
              ) : (
                stat.value
              )}
            </div>
            <div className="flex gap-1.5 items-end h-12 pb-1">
              {[...Array(6)].map((_, j) => (
                <motion.div
                  key={j}
                  animate={{ 
                    height: [10, 35, 15, 45, 10][(i + j) % 5] 
                  }}
                  transition={{ 
                    repeat: Infinity, 
                    duration: 1.2, 
                    ease: "easeInOut",
                    delay: j * 0.15 
                  }}
                  className={`w-1.5 rounded-full ${stat.color} opacity-40 shadow-[0_0_8px_currentColor]`}
                />
              ))}
            </div>
          </div>
          <AnimatePresence>
            {i === 0 && (
              <motion.div
                key="pulse"
                initial={{ opacity: 0.5, scale: 0.8 }}
                animate={{ opacity: 0, scale: 2 }}
                transition={{ duration: 2, repeat: Infinity }}
                className={`absolute top-4 right-4 w-3 h-3 rounded-full ${stat.bg} ${stat.color} border border-current`}
              />
            )}
          </AnimatePresence>
        </motion.div>
      ))}
    </div>
  );
};

export default LiveMetrics;
