import React, { useEffect, useState } from 'react';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts';
import { motion } from 'framer-motion';
import { ShieldAlert, RefreshCw } from 'lucide-react';
import api from '../api/client';

const VULN_CATEGORIES = ['SQLi', 'XSS', 'XXE', 'SSRF', 'IDOR', 'Auth', 'CSRF', 'BizLogic'];

const buildRadarData = (findingsBySeverity: Record<string, number>) => {
  return VULN_CATEGORIES.map((subject) => ({
    subject,
    A: Math.min(150, (findingsBySeverity[subject.toLowerCase()] ?? 0) * 20 + 30),
    fullMark: 150,
  }));
};

const SecurityPosture: React.FC = () => {
  const [radarData, setRadarData] = useState(buildRadarData({}));
  const [topVuln, setTopVuln] = useState<string>('N/A');
  const [coverage, setCoverage] = useState<string>('—');
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      // Get recent findings from top scan to build the radar
      const scansRes = await api.get('/scans?limit=5&status=complete');
      const scans = scansRes.data?.items ?? scansRes.data ?? [];

      const vulnCounts: Record<string, number> = {};
      let totalTargets = 0;

      if (Array.isArray(scans) && scans.length > 0) {
        // Aggregate findings for up to 3 most recent completed scans
        for (const scan of scans.slice(0, 3)) {
          if (scan.metrics?.detection?.confirmed_findings) {
            const f = scan.metrics.detection.confirmed_findings;
            // Map to radar categories based on what backend returns
            if (scan.top_severity) vulnCounts[scan.top_severity] = (vulnCounts[scan.top_severity] ?? 0) + f;
          }
        }
        totalTargets = scans.length;
      }

      const targetsRes = await api.get('/targets?limit=1');
      const total = targetsRes.data?.total ?? 0;
      if (total > 0) {
        setCoverage(`${Math.min(100, Math.round((totalTargets / total) * 100))}% Assets`);
      } else {
        setCoverage('No targets');
      }

      // Find the top vulnerability category
      const topEntry = Object.entries(vulnCounts).sort(([, a], [, b]) => b - a)[0];
      setTopVuln(topEntry ? topEntry[0].toUpperCase() : 'Not scanned');
      setRadarData(buildRadarData(vulnCounts));
    } catch {
      // Keep defaults on failure
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 60_000);
    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="security-posture-card flex flex-col gap-4"
    >
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-2">
          <ShieldAlert size={18} className="text-primary" />
          <span className="text-[10px] font-black text-primary uppercase tracking-[0.2em]">
            Attack Surface Map
          </span>
        </div>
        <div className="flex items-center gap-2">
          {loading && <RefreshCw size={10} className="text-muted-foreground animate-spin" />}
          <div className="text-[8px] font-mono text-muted-foreground uppercase tracking-widest bg-white/5 px-2 py-0.5 rounded border border-border">
            {loading ? 'Scanning...' : 'Live Intel'}
          </div>
        </div>
      </div>

      <div className="h-[240px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
            <PolarGrid stroke="rgba(59, 130, 246, 0.1)" />
            <PolarAngleAxis dataKey="subject" tick={{ fill: '#848d97', fontSize: 10, fontWeight: 700 }} />
            <PolarRadiusAxis angle={30} domain={[0, 150]} tick={false} axisLine={false} />
            <Radar
              name="Attack Surface"
              dataKey="A"
              stroke="#3b82f6"
              fill="#3b82f6"
              fillOpacity={0.3}
              strokeWidth={2}
            />
            <Tooltip
              contentStyle={{
                background: 'rgba(15, 23, 42, 0.9)',
                border: '1px solid rgba(59, 130, 246, 0.2)',
                borderRadius: '12px',
                fontSize: '10px',
                fontWeight: 'bold',
                textTransform: 'uppercase',
                backdropFilter: 'blur(8px)',
                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
              }}
              itemStyle={{ color: '#60a5fa' }}
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-2 gap-2 mt-2">
        <div className="p-3 bg-white/5 border border-border rounded-xl">
          <p className="text-[8px] font-black text-muted-foreground uppercase tracking-widest mb-1">Highest Risk Vector</p>
          <p className="text-xs font-bold text-white uppercase">{topVuln}</p>
        </div>
        <div className="p-3 bg-white/5 border border-border rounded-xl">
          <p className="text-[8px] font-black text-muted-foreground uppercase tracking-widest mb-1">Scope Coverage</p>
          <p className="text-xs font-bold text-white uppercase">{coverage}</p>
        </div>
      </div>
    </motion.div>
  );
};

export default SecurityPosture;
