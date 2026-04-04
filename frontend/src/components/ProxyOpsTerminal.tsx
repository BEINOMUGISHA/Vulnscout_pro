import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { Terminal, Play, Cpu, Activity, Globe } from 'lucide-react';

interface ProxyEvent {
  id: string;
  type: 'request' | 'response' | 'error' | 'state';
  method?: string;
  url?: string;
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  error?: string;
  intercept_mode?: boolean;
}

interface ProxyOpsTerminalProps {
  events: ProxyEvent[];
  interceptEnabled: boolean;
  onForward: (id: string) => void;
  onDrop: (id: string) => void;
  onClear: () => void;
}

const ProxyOpsTerminal: React.FC<ProxyOpsTerminalProps> = ({ events, interceptEnabled, onForward, onDrop, onClear }) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  const formatTimestamp = () => {
    const d = new Date();
    return d.getHours().toString().padStart(2, '0') + ':' + 
           d.getMinutes().toString().padStart(2, '0') + ':' + 
           d.getSeconds().toString().padStart(2, '0') + '.' + 
           d.getMilliseconds().toString().padStart(3, '0');
  };

  return (
    <div className="flex flex-col h-full bg-[#050507] border border-primary/20 rounded-2xl overflow-hidden shadow-[0_0_30px_rgba(0,0,0,0.5)]">
      {/* Header */}
      <div className="bg-white/5 px-6 py-3 border-b border-white/5 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <Terminal size={14} className="text-primary animate-pulse" />
          <span className="text-[10px] font-black uppercase tracking-[0.2em] text-white/50">Tactical Traffic Stream</span>
        </div>
        <div className="flex items-center gap-4">
           <label className="flex items-center gap-2 cursor-pointer group">
              <input 
                type="checkbox" 
                checked={autoScroll} 
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="hidden"
              />
              <div className={`w-3 h-3 rounded-sm border transition-all ${autoScroll ? 'bg-primary border-primary' : 'border-white/20'}`} />
              <span className="text-[9px] font-black uppercase tracking-widest text-white/30 group-hover:text-white/60">Auto-Scroll</span>
           </label>
           <button 
             onClick={onClear}
             className="text-[9px] font-black uppercase tracking-widest text-white/30 hover:text-destructive transition-colors"
           >
             [ Reset Stream ]
           </button>
        </div>
      </div>

      {/* Terminal Body */}
      <div 
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-6 font-mono text-[11px] space-y-1 custom-scrollbar"
      >
        <div className="text-primary/40 mb-4 flex items-center gap-2">
           <Activity size={12} />
           <span>UPLINK_ESTABLISHED // CAPTURING_TRAFFIC...</span>
        </div>

        {events.length === 0 && (
          <div className="h-full flex items-center justify-center opacity-10 flex-col gap-4">
            <Globe size={48} />
            <span className="text-xs tracking-[0.4em] uppercase font-black">Waiting for packets</span>
          </div>
        )}

        {events.map((event, i) => {
          const isRequest = event.type === 'request';
          const isIntercepted = interceptEnabled && isRequest;
          
          return (
            <motion.div 
              key={event.id + i}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className={`group relative flex gap-4 py-0.5 border-l-2 ${
                event.type === 'error' ? 'border-destructive/30 bg-destructive/5' :
                isIntercepted ? 'border-warning/50 bg-warning/5' : 
                'border-transparent hover:bg-white/[0.02]'
              }`}
            >
              <span className="text-white/10 select-none w-10 shrink-0 text-right">{i + 1}</span>
              <span className="text-white/20 select-none shrink-0 italic">{formatTimestamp()}</span>
              
              <div className="flex-1 flex flex-col">
                <div className="flex items-center gap-3">
                  <span className={`font-black uppercase px-1.5 rounded-[2px] ${
                    event.method === 'GET' ? 'text-primary' : 
                    event.method === 'POST' ? 'text-success' : 
                    event.type === 'response' ? 'text-purple-400' : 'text-warning'
                  }`}>
                    {event.type === 'response' ? `RES_${event.status}` : event.method || event.type.toUpperCase()}
                  </span>
                  
                  <span className={`truncate max-w-[500px] ${
                    event.type === 'error' ? 'text-destructive' : 'text-white/70'
                  }`}>
                    {event.url || event.error || 'N/A'}
                  </span>

                  {isIntercepted && (
                    <motion.span 
                      animate={{ opacity: [1, 0.5, 1] }}
                      transition={{ duration: 1, repeat: Infinity }}
                      className="bg-warning text-black px-2 py-0.5 rounded text-[8px] font-black uppercase tracking-tighter shadow-[0_0_10px_rgba(245,158,11,0.5)]"
                    >
                      HELD_FOR_INTERCEPT
                    </motion.span>
                  )}
                </div>

                {/* Inline Controls for Intercepted */}
                {isIntercepted && (
                  <div className="mt-2 flex gap-4 animate-in fade-in slide-in-from-left-2 duration-300">
                     <button 
                        onClick={() => onForward(event.id)}
                        className="flex items-center gap-1.5 text-success hover:text-white transition-colors uppercase font-black text-[9px] tracking-widest"
                     >
                       <Play size={10} fill="currentColor" /> [ Forward Packet ]
                     </button>
                     <button 
                        onClick={() => onDrop(event.id)}
                        className="text-destructive/60 hover:text-destructive transition-colors uppercase font-black text-[9px] tracking-widest"
                     >
                       [ Drop Packet ]
                     </button>
                  </div>
                )}
              </div>

              {/* Hover Details Toggle (Visual only for now) */}
              <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity">
                 <span className="text-[8px] text-primary/40 font-black cursor-help uppercase tracking-widest">SEQ_{event.id.substring(0,8)}</span>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Footer / Status Bar */}
      <div className="bg-white/5 px-6 py-2 border-t border-white/5 flex justify-between items-center shrink-0">
         <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
               <div className="w-1.5 h-1.5 rounded-full bg-success shadow-[0_0_5px_#22c55e]"></div>
               <span className="text-[8px] font-mono text-white/40 uppercase">Buffer: {events.length}/1000</span>
            </div>
            <div className="w-px h-3 bg-white/10"></div>
            <div className="flex items-center gap-2">
               <Cpu size={10} className="text-primary" />
               <span className="text-[8px] font-mono text-white/40 uppercase">Thread: Intercept_Main</span>
            </div>
         </div>
         <div className="flex items-center gap-2">
            <span className="text-[8px] font-mono text-primary/60 uppercase animate-pulse">Ops_Live_Stream</span>
         </div>
      </div>
    </div>
  );
};

export default ProxyOpsTerminal;
