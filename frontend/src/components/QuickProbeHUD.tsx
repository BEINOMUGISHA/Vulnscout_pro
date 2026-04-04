import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  X, Activity, 
  Target, ChevronRight
} from 'lucide-react';
import { VulnScoutSounds } from '../lib/sounds';

interface QuickProbeHUDProps {
  scanId: string | null;
  targetUrl: string;
  isOpen: boolean;
  onClose: () => void;
  onViewDetails: () => void;
}

const QuickProbeHUD: React.FC<QuickProbeHUDProps> = ({ scanId, targetUrl, isOpen, onClose, onViewDetails }) => {
  const [status, setStatus] = useState<any>(null);
  const [progress, setProgress] = useState(2); // Start at 2% optimistically
  const esRef = useRef<EventSource | null>(null);

  // Live progress for perceived performance while waiting for SSE link
  useEffect(() => {
    if (isOpen && !status) {
      const interval = setInterval(() => {
        setProgress(prev => {
          if (prev < 12) return prev + 0.5; // Slowly crawl to 12% while starting
          return prev;
        });
      }, 100);
      return () => clearInterval(interval);
    }
  }, [isOpen, status]);

  useEffect(() => {
    if (isOpen && scanId) {
      const token = localStorage.getItem('token');
      const url = `/api/v1/scans/${scanId}/status?stream=true&token=${token}`;
      
      esRef.current = new EventSource(url);
      
      esRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setStatus(data);
          // Only update progress if the server provides a higher value than our live estimate
          if (data.progress > progress || data.status === 'complete') {
            setProgress(data.progress || 0);
          }
          
          if (data.new_findings > 0) {
            VulnScoutSounds.play('nodeDetect');
          }
          
          if (data.status === 'complete') {
            VulnScoutSounds.play('missionComplete');
          }
        } catch (e) {
          console.error("Probe SSE Parse Error:", e);
        }
      };

      esRef.current.onerror = (e) => {
        console.error("Probe SSE Connection Error:", e);
        // Try to reconnect once if it fails early
        esRef.current?.close();
      };
    }

    return () => {
      esRef.current?.close();
    };
  }, [isOpen, scanId]);

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div 
        initial={{ opacity: 0, backdropFilter: "blur(0px)" }}
        animate={{ opacity: 1, backdropFilter: "blur(10px)" }}
        exit={{ opacity: 0, backdropFilter: "blur(0px)" }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60"
      >
        <motion.div 
          initial={{ scale: 0.9, opacity: 0, y: 20 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.9, opacity: 0, y: 20 }}
          className="w-full max-w-2xl glass rounded-[40px] border border-primary/30 shadow-[0_0_50px_rgba(59,130,246,0.2)] overflow-hidden relative"
        >
          {/* Tactical Header */}
          <div className="bg-primary/10 border-b border-white/10 px-8 py-6 flex justify-between items-center relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-full opacity-10 pointer-events-none">
                <div className="absolute inset-0 bg-gradient-to-r from-primary to-transparent animate-scan"></div>
            </div>
            
            <div className="flex items-center gap-4 relative z-10">
              <div className="relative">
                <Target className="text-primary h-8 w-8" />
                <div className="absolute inset-0 text-primary h-8 w-8 animate-ping opacity-20" />
              </div>
              <div>
                <h3 className="text-xl font-black italic uppercase tracking-tighter text-white">Instant Probe Active</h3>
                <p className="text-[10px] font-mono text-primary/60 uppercase tracking-widest truncate max-w-[300px]">{targetUrl}</p>
              </div>
            </div>

            <button 
              onClick={() => {
                VulnScoutSounds.play('buttonClick');
                onClose();
              }}
              className="p-3 hover:bg-white/10 rounded-full transition-colors relative z-10 text-white/50 hover:text-white"
            >
              <X size={24} />
            </button>
          </div>

          <div className="p-8 space-y-8">
            {/* Main Progress Ring / Arc Area */}
            <div className="flex flex-col items-center justify-center py-6 relative">
                 <div className="relative w-48 h-48 flex items-center justify-center">
                    <svg className="w-full h-full -rotate-90">
                        <circle
                            cx="96" cy="96" r="88"
                            fill="transparent"
                            stroke="currentColor"
                            strokeWidth="8"
                            className="text-white/5"
                        />
                        <motion.circle
                            cx="96" cy="96" r="88"
                            fill="transparent"
                            stroke="currentColor"
                            strokeWidth="8"
                            strokeDasharray={553}
                            initial={{ strokeDashoffset: 553 }}
                            animate={{ strokeDashoffset: 553 - (553 * progress) / 100 }}
                            className="text-primary"
                        />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-5xl font-black font-mono tracking-tighter text-white">{Math.round(status ? progress : 1)}%</span>
                        <span className="text-[10px] uppercase font-black tracking-[0.2em] text-primary/60">{status?.phase?.toUpperCase() || 'STARTING...'}</span>
                    </div>
                 </div>
                 
                 {/* Linear Progress Bar below the ring */}
                 <div className="w-full max-w-md mt-6 space-y-2">
                    <div className="h-2 bg-white/5 rounded-full border border-white/5 overflow-hidden p-0.5">
                       <motion.div 
                         initial={{ width: 0 }}
                         animate={{ width: `${progress}%` }}
                         className="h-full bg-gradient-to-r from-primary to-accent rounded-full neon-blue"
                       />
                    </div>
                 </div>
            </div>

            {/* Findings Summary Stats */}
            <div className="grid grid-cols-4 gap-4">
               {[
                 { label: 'CRITICAL', value: status?.findings_by_class?.critical || 0, color: 'text-destructive', bg: 'bg-destructive/10' },
                 { label: 'HIGH', value: status?.findings_by_class?.high || 0, color: 'text-orange-500', bg: 'bg-orange-500/10' },
                 { label: 'MEDIUM', value: status?.findings_by_class?.medium || 0, color: 'text-primary', bg: 'bg-primary/10' },
                 { label: 'LOW', value: status?.findings_by_class?.low || 0, color: 'text-muted-foreground', bg: 'bg-muted/10' }
               ].map(stat => (
                 <div key={stat.label} className={`${stat.bg} p-4 rounded-2xl border border-white/5 flex flex-col items-center gap-1`}>
                    <span className={`text-2xl font-black font-mono ${stat.value > 0 ? stat.color : 'text-white/20'}`}>{stat.value}</span>
                    <span className="text-[8px] font-black uppercase tracking-widest text-white/40">{stat.label}</span>
                 </div>
               ))}
            </div>

            {/* Active Detectors Feed */}
            <div className="bg-black/40 border border-white/5 rounded-2xl p-6 h-32 overflow-hidden relative">
               <div className="flex items-center gap-2 mb-3">
                  <Activity size={12} className="text-primary animate-pulse" />
                  <span className="text-[9px] font-black uppercase tracking-widest text-primary/60">Live Detector Mesh</span>
               </div>
               <div className="flex flex-wrap gap-2">
                  <AnimatePresence>
                  {(status?.active_detectors || []).map((det: string, i: number) => (
                    <motion.span 
                      key={det + i}
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="px-3 py-1 bg-primary/20 border border-primary/40 rounded text-[9px] font-mono text-primary uppercase"
                    >
                      {det}
                    </motion.span>
                  ))}
                  </AnimatePresence>
               </div>
            </div>

            {/* Action Footer */}
            <div className="flex gap-4 pt-4 border-t border-white/5">
                <button 
                  onClick={onViewDetails}
                  className="flex-1 bg-white text-black font-black text-xs uppercase tracking-widest py-4 rounded-xl hover:bg-primary hover:text-white transition-all flex items-center justify-center gap-2 group"
                >
                  Enter Detailed Sequence <ChevronRight size={16} className="group-hover:translate-x-1 transition-transform" />
                </button>
                <button 
                  onClick={onClose}
                  className="px-8 bg-secondary border border-border text-white font-black text-xs uppercase tracking-widest py-4 rounded-xl hover:bg-white/5 transition-all"
                >
                  Acknowledge
                </button>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default QuickProbeHUD;
