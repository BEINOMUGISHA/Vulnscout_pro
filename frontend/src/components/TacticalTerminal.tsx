import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, StopCircle, Activity, Play, Trash2, ChevronLeft, Zap } from 'lucide-react';
import { VulnScoutSounds } from '../lib/sounds';

interface TacticalTerminalProps {
  isOpen: boolean;
  onClose: () => void;
  targetUrl?: string;
}

const TacticalTerminal: React.FC<TacticalTerminalProps> = ({ isOpen, onClose, targetUrl }) => {
  const [editableCommands, setEditableCommands] = useState<{[key: string]: string}>({});
  const [isTurbo, setIsTurbo] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [currentCommand, setCurrentCommand] = useState<string | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Sync initial commands when targetUrl or isTurbo changes
    const turboFlag = isTurbo ? ' --turbo' : '';
    const initial = {
      'Manual Scan Run': `python run.py cli scan run ${targetUrl || '<TARGET_URL>'}${turboFlag}`,
      'Interactive Wizard': 'python run.py cli scan wizard',
      'Report List': 'python run.py cli report list',
      'Auth Status Check': 'python run.py cli auth status'
    };
    setEditableCommands(initial);
  }, [targetUrl, isTurbo]);

  const toggleTurbo = () => {
    const newState = !isTurbo;
    setIsTurbo(newState);
    if (newState) {
        VulnScoutSounds.play('alarmKlaxon');
        setLogs(prev => [...prev, `[SYSTEM] OVERDRIVE ENABLED. TURBO MODE ACTIVE.`]);
    } else {
        VulnScoutSounds.play('buttonClick');
        setLogs(prev => [...prev, `[SYSTEM] Power normalization complete. Standard mode restored.`]);
    }
  };

  const handleCommandChange = (label: string, value: string) => {
    setEditableCommands(prev => ({ ...prev, [label]: value }));
  };

  const streamDemoLogs = async (target: string) => {
    const phases = [
      { name: 'INITIALIZING', color: 'text-primary', logs: [
          `[SYSTEM] BOOT SEQUENCE INITIATED.`,
          `[SYSTEM] NEURAL LINK ESTABLISHED WITH LOCAL NODE.`,
          `[INFO] TARGET IDENTIFIED: ${target}`,
          `[INFO] VULNSCOUT PRO v4.4.2 — SIGNATURE DB 2026.03.R4`
      ]},
      { name: 'CRAWLING', color: 'text-blue-400', logs: [
          `[CRAWLER] INJECTING DEEP SPIDER INTO ${target}...`,
          `[CRAWLER] DISCOVERED NODE: /api/v1/auth`,
          `[CRAWLER] DISCOVERED NODE: /admin/login`,
          `[CRAWLER] DISCOVERED NODE: /config/v2/webhooks`,
          `[CRAWLER] MAPPING ASSET PERIMETER: 42 ENDPOINTS DETECTED.`
      ]},
      { name: 'DETECTING', color: 'text-amber-500', logs: [
          `[DETECTOR] STARTING TACTICAL PAYLOAD DELIVERY.`,
          `[DETECTOR] TESTING SQLi VECTORS ON /api/v1/auth...`,
          `[DETECTOR] TESTING SSRF VECTORS ON /config/v2/webhooks...`,
          `[DETECTOR] ANALYSIS ENGINE: ANOMALY DETECTED IN RESPONSE HEADER.`,
          `[DETECTOR] PROBING IDOR ON /user/profile?id=774...`
      ]},
      { name: 'VALIDATING', color: 'text-red-500', logs: [
          `[VALIDATOR] CROSS-REFERENCING ANOMALIES WITH SIGNATURE DB.`,
          `[VALIDATOR] !! CRITICAL ALERT: SQL INJECTION CONFIRMED !!`,
          `[VALIDATOR] !! HIGH ALERT: SSRF CONFIRMED ON CLOUD METADATA !!`,
          `[VALIDATOR] VERIFICATION PAYLOAD EXECUTED SUCCESSFULLY.`
      ]},
      { name: 'FINALIZING', color: 'text-success', logs: [
          `[ORCHESTRATOR] GENERATING TACTICAL INTELLIGENCE PACKAGE...`,
          `[ORCHESTRATOR] MISSION COMPLETE. 2 CRITICAL, 1 HIGH FINDINGS.`,
          `[SYSTEM] ALL UPLINKS DISCONNECTED. STANDING BY.`
      ]}
    ];

    for (const phase of phases) {
      setLogs(prev => [...prev, `\n>> PHASE: ${phase.name} <<`]);
      VulnScoutSounds.play('scanPhaseUp');
      
      for (const log of phase.logs) {
        setLogs(prev => [...prev, log]);
        if (log.includes('CRITICAL')) VulnScoutSounds.play('alarmKlaxon');
        else if (log.includes('CONFIRMED')) VulnScoutSounds.play('exportBlip');
        else VulnScoutSounds.play('sonarPulse');

        // High speed if turbo
        await new Promise(r => setTimeout(r, isTurbo ? 150 : 800));
      }
      await new Promise(r => setTimeout(r, isTurbo ? 300 : 1200));
    }
  };

  const handleRun = async (cmd: string) => {
    if (isExecuting) return;
    
    // Validate command
    if (cmd.includes('<TARGET_URL>')) {
      setLogs(prev => [...prev, `[ERROR] Mission aborted. Target URL placeholder detected. Please enter a valid URL.`]);
      VulnScoutSounds.play('sseDisconnect');
      return;
    }

    if (cmd.includes('scan run') && !cmd.split('scan run')[1].trim()) {
       setLogs(prev => [...prev, `[ERROR] Error. No target URL specified.`]);
       VulnScoutSounds.play('sseDisconnect');
       return;
    }
    
    setIsExecuting(true);
    setCurrentCommand(cmd);
    setLogs([]);
    setLogs(prev => [...prev, `> Starting scan sequence: ${cmd}`, `> Connecting to local node...`]);
    VulnScoutSounds.play('scanStart');

    // If it's a scan run command, simulate the lively output
    if (cmd.includes('scan run')) {
        const parts = cmd.split('scan run');
        const target = parts[1].trim().split(' ')[0] || 'localhost';
        await streamDemoLogs(target);
        setIsExecuting(false);
        return;
    }

    try {
      const response = await fetch('/api/v1/terminal/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ command: cmd })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Terminal uplink failed');
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          const chunk = decoder.decode(value);
          const lines = chunk.split('\n');
          
          lines.forEach(line => {
            if (line.startsWith('data: ')) {
               const content = line.replace('data: ', '').trim();
               if (content) {
                   setLogs(prev => [...prev, content]);
                   VulnScoutSounds.play('sonarPulse');
               }
            }
          });
        }
      }
    } catch (e: any) {
      setLogs(prev => [...prev, `[ERROR] ${e.message}`]);
      VulnScoutSounds.play('sseDisconnect');
    } finally {
      setIsExecuting(false);
    }
  };

  const clearLogs = () => {
    setLogs([]);
    setCurrentCommand(null);
  };

  const commandTemplates = [
    { label: 'Manual Scan Run', icon: <Activity size={14} /> },
    { label: 'Interactive Wizard', icon: <Play size={14} /> },
    { label: 'Fleet Status Report', icon: <Terminal size={14} /> },
    { label: 'Auth Integrity Check', icon: <Terminal size={14} /> }
  ];

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
          />
          <motion.div 
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.9, opacity: 0, y: 20 }}
            className={`bg-[#0a0a0c] border ${isTurbo ? 'border-amber-500/50 shadow-[0_0_60px_rgba(245,158,11,0.2)]' : 'border-primary/30'} w-full max-w-3xl rounded-2xl overflow-hidden shadow-[0_0_50px_rgba(59,130,246,0.2)] relative z-10 flex flex-col max-h-[90vh] transition-all duration-500`}
          >
            <div className="p-6 border-b border-white/5 flex justify-between items-center bg-white/5 shrink-0">
              <div className="flex items-center gap-6">
                <div className="flex items-center gap-3">
                    <Terminal className={isTurbo ? 'text-amber-500' : 'text-primary'} size={20} />
                    <h3 className="text-sm font-black uppercase tracking-widest text-white italic">Terminal Access</h3>
                </div>
                
                <button 
                    onClick={toggleTurbo}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-full border transition-all ${
                        isTurbo 
                        ? 'bg-amber-500 text-black border-amber-400 font-black shadow-[0_0_15px_rgba(245,158,11,0.4)]' 
                        : 'bg-white/5 text-muted-foreground border-white/10 hover:border-white/20 font-bold'
                    } text-[10px] uppercase tracking-widest`}
                >
                    <Activity size={12} className={isTurbo ? 'animate-pulse' : ''} />
                    {isTurbo ? 'Turbo Mode: ON' : 'Turbo Mode'}
                </button>
              </div>
              <div className="flex items-center gap-4">
                 {logs.length > 0 && (
                     <button 
                        onClick={clearLogs}
                        disabled={isExecuting}
                        className="text-[10px] font-black uppercase text-muted-foreground hover:text-destructive transition-colors flex items-center gap-2"
                     >
                        <Trash2 size={14} /> Clear Log
                     </button>
                 )}
                <button 
                    onClick={onClose}
                    className="text-muted-foreground hover:text-white transition-colors"
                >
                    <StopCircle size={20} className="rotate-45" />
                </button>
              </div>
            </div>
            
            <div className="flex-1 overflow-y-auto p-8 space-y-8">
              {/* Command Reference Section - Only show when not running or show mini version */}
              {!currentCommand && (
                <div className="space-y-4">
                    <p className="text-[10px] uppercase font-black tracking-[0.2em] text-primary/60">Commands</p>
                    <div className="grid grid-cols-1 gap-4">
                        {commandTemplates.map((item, i) => (
                            <div key={i} className={`bg-black/60 rounded-xl p-5 border ${isTurbo && item.label === 'Manual Scan Run' ? 'border-amber-500/30 bg-amber-500/5' : 'border-white/5'} space-y-4 font-mono group hover:border-primary/20 transition-all`}>
                                <div className="flex justify-between items-center">
                                    <span className={`text-[10px] uppercase font-black ${isTurbo && item.label === 'Manual Scan Run' ? 'text-amber-500/70' : 'text-muted-foreground/50'} tracking-widest flex items-center gap-2`}>
                                        {item.label}
                                        {isTurbo && item.label === 'Manual Scan Run' && <Zap size={10} className="text-amber-500 animate-bounce" />}
                                    </span>
                                    <div className="flex items-center gap-3">
                                        <button 
                                            onClick={() => {
                                                navigator.clipboard.writeText(editableCommands[item.label] || '');
                                                VulnScoutSounds.play('buttonClick');
                                            }}
                                            className="text-[9px] uppercase font-black text-white/40 hover:text-white transition-colors"
                                        >
                                            [ COPY ]
                                        </button>
                                        <button 
                                            onClick={() => handleRun(editableCommands[item.label] || '')}
                                            disabled={isExecuting}
                                            className={`flex items-center gap-2 ${isTurbo && item.label === 'Manual Scan Run' ? 'bg-amber-500 text-black hover:bg-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.3)]' : 'bg-primary/20 text-primary hover:bg-primary hover:text-white'} px-3 py-1 rounded text-[9px] font-black uppercase tracking-widest transition-all`}
                                        >
                                            <Play size={10} fill="currentColor" /> Run Sequence
                                        </button>
                                    </div>
                                </div>
                                <div className={`bg-white/5 p-3 rounded border ${isTurbo && item.label === 'Manual Scan Run' ? 'border-amber-500/20' : 'border-white/5'} text-[11px] text-primary/80 flex items-center gap-3 group-focus-within:border-primary/40 transition-all`}>
                                    <span className="text-white/20 select-none">$</span>
                                    <input 
                                        type="text"
                                        value={editableCommands[item.label] || ''}
                                        onChange={(e) => handleCommandChange(item.label, e.target.value)}
                                        className="bg-transparent border-none outline-none text-white w-full font-mono text-[11px] p-0 focus:ring-0"
                                        spellCheck={false}
                                    />
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
              )}

              {/* Execution Log View */}
              {(currentCommand || logs.length > 0) && (
                <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <div className="flex justify-between items-center">
                        <p className="text-[10px] uppercase font-black tracking-[0.2em] text-primary/60">Output</p>
                        {currentCommand && !isExecuting && (
                             <button 
                                onClick={() => setCurrentCommand(null)}
                                className="text-[9px] font-black uppercase text-primary flex items-center gap-2"
                             >
                                <ChevronLeft size={12} /> Back
                             </button>
                        )}
                    </div>
                    <div className={`bg-black rounded-xl border ${isTurbo ? 'border-amber-500/40 shadow-[inset_0_0_20px_rgba(245,158,11,0.05)]' : 'border-primary/20'} overflow-hidden shadow-inner flex flex-col min-h-[300px] transition-all duration-700`}>
                        <div className={`px-4 py-2 border-b flex items-center justify-between shrink-0 ${isTurbo ? 'bg-amber-500/10 border-amber-500/20' : 'bg-white/5 border-white/5'}`}>
                            <div className="flex items-center gap-2">
                                <div className={`w-2 h-2 rounded-full ${isExecuting ? (isTurbo ? 'bg-amber-500 animate-ping' : 'bg-primary animate-pulse') : 'bg-muted'}`}></div>
                                <span className={`text-[9px] font-mono font-bold uppercase ${isTurbo ? 'text-amber-500' : 'text-muted-foreground'}`}>{isExecuting ? (isTurbo ? 'Fast Process' : 'Scanning') : 'Stopped'}</span>
                            </div>
                            <span className="text-[9px] font-mono text-white/20 uppercase tracking-widest">VulnScout-v0.1.0-cli</span>
                        </div>
                        <div className={`flex-1 p-6 font-mono text-xs ${isTurbo ? 'text-amber-200/90' : 'text-primary/90'} space-y-1 overflow-y-auto max-h-[400px] leading-relaxed selection:bg-primary selection:text-white`}>
                            {logs.map((log, i) => (
                                <div key={i} className="flex gap-4">
                                    <span className="text-white/10 select-none">{String(i+1).padStart(3, '0')}</span>
                                    <span className={log.startsWith('[ERROR]') ? 'text-destructive' : log.startsWith('>') ? 'text-primary' : log.startsWith('[SYSTEM]') ? 'text-amber-500 font-black' : ''}>
                                        {log}
                                    </span>
                                </div>
                            ))}
                            <div ref={logEndRef} />
                        </div>
                    </div>
                </div>
              )}

              {!currentCommand && (
                <div className={`flex items-center gap-4 p-4 rounded-xl border shrink-0 transition-all ${isTurbo ? 'bg-amber-500/10 border-amber-500/30 shadow-[0_0_20px_rgba(245,158,11,0.1)]' : 'bg-primary/5 border-primary/20'}`}>
                    <Activity size={24} className={`${isTurbo ? 'text-amber-500 animate-bounce' : 'text-primary animate-pulse'}`} />
                    <p className={`text-[10px] leading-relaxed uppercase tracking-wider ${isTurbo ? 'text-amber-200' : 'text-white/70'}`}>
                    {isTurbo 
                        ? <>TURBO MODE ACTIVE: <span className="text-amber-500 font-black">HIGH-VELOCITY ENGINE ENGAGED.</span> ALL THROTTLES DISENGAGED.</>
                        : <>The mission-critical CLI provides <span className="text-primary font-black">Turbo Mode</span> and unthrottled engine control beyond standard web protocols.</>
                    }
                    </p>
                </div>
              )}
            </div>
            
            <div className="p-4 bg-white/5 border-t border-white/5 flex justify-center shrink-0">
              <button 
                onClick={onClose}
                className="text-[9px] font-black uppercase tracking-[0.3em] text-muted-foreground hover:text-primary transition-colors"
              >
                [ Close ]
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default TacticalTerminal;
