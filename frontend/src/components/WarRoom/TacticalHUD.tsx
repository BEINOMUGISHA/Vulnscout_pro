import React, { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity } from 'lucide-react';
import { VulnScoutSounds } from '../../lib/sounds';

interface TacticalHUDProps {
    activeDetectors: string[];
    findingsByClass: Record<string, number>;
    isScanning: boolean;
}

const TacticalHUD: React.FC<TacticalHUDProps> = ({ activeDetectors, findingsByClass, isScanning }) => {
    const prevFindings = useRef<Record<string, number>>(findingsByClass);
    
    // Radar tick loop
    useEffect(() => {
        if (!isScanning) return;
        
        const interval = setInterval(() => {
            VulnScoutSounds.play('radarPing');
        }, 2000);
        
        return () => clearInterval(interval);
    }, [isScanning]);

    // Node detection sound
    useEffect(() => {
        Object.keys(findingsByClass).forEach(key => {
            if (findingsByClass[key] > (prevFindings.current[key] || 0)) {
                VulnScoutSounds.play('nodeDetect');
            }
        });
        prevFindings.current = findingsByClass;
    }, [findingsByClass]);
    // Standard vulnerability sub-classes we want to track intuition for
    const vulnClasses = [
        { id: 'SQLInjection', label: 'SQLI', color: '#ff3e3e' },
        { id: 'XSS', label: 'XSS', color: '#ff9d00' },
        { id: 'SSRF', label: 'SSRF', color: '#00c8ff' },
        { id: 'BrokenAuth', label: 'AUTH', color: '#a855f7' },
        { id: 'SensitiveData', label: 'DATA', color: '#22c55e' },
        { id: 'Misconfig', label: 'CONF', color: '#eab308' }
    ];

    return (
        <div className="bg-card/40 backdrop-blur-md border border-border/50 rounded-2xl p-6 shadow-xl mb-6">
            <div className="flex justify-between items-center mb-6">
                <div className="flex flex-col">
                    <span className="font-mono text-[9px] text-white/40 uppercase tracking-widest flex items-center gap-2">
                        <Activity size={10} className={isScanning ? "text-primary animate-pulse" : "text-white/20"} />
                        Discovery Intuition Engine
                    </span>
                    <span className="font-mono text-[10px] text-primary uppercase tracking-tighter">
                        Active Vulnerability Channels — Real-time Analysis
                    </span>
                </div>
                {isScanning && (
                    <div className="flex items-center gap-2">
                         <span className="font-mono text-[8px] text-success animate-pulse">STREAMING_REALTIME</span>
                    </div>
                )}
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                {vulnClasses.map((v) => {
                    const isActive = activeDetectors.some(d => d.toLowerCase().includes(v.id.toLowerCase()) || d.toLowerCase().includes(v.label.toLowerCase()));
                    const findings = findingsByClass[v.id] || findingsByClass[v.label] || 0;
                    
                    return (
                        <div key={v.id} className="relative group">
                            <div className={`p-4 rounded-xl border transition-all duration-500 overflow-hidden ${
                                isActive 
                                ? 'bg-primary/5 border-primary/30' 
                                : 'bg-white/5 border-white/5 opacity-40'
                            }`}>
                                {/* Channel Header */}
                                <div className="flex justify-between items-start mb-2">
                                    <span className={`font-mono text-[10px] font-black ${isActive ? 'text-primary' : 'text-white/40'}`}>
                                        {v.label}
                                    </span>
                                    {isActive && (
                                        <motion.div 
                                            animate={{ opacity: [1, 0, 1] }}
                                            transition={{ duration: 0.5, repeat: Infinity }}
                                            className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_8px_#00c8ff]"
                                        />
                                    )}
                                </div>

                                {/* Findings Counter */}
                                <div className="flex items-end gap-1">
                                    <span className={`text-xl font-mono font-black ${findings > 0 ? 'text-white' : 'text-white/20'}`}>
                                        {findings.toString().padStart(2, '0')}
                                    </span>
                                    <span className="text-[10px] text-white/30 font-medium mb-1">IND</span>
                                </div>

                                {/* Status Progress */}
                                <div className="mt-3 space-y-1">
                                    <div className="flex justify-between text-[8px] font-mono uppercase tracking-tighter">
                                        <span className="text-white/30">Status:</span>
                                        <span className={isActive ? 'text-primary' : 'text-white/20'}>
                                            {isActive ? 'PROBING' : 'STANDBY'}
                                        </span>
                                    </div>
                                    <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
                                        {isActive && (
                                            <motion.div 
                                                className="h-full bg-primary"
                                                animate={{ 
                                                    width: ["0%", "100%"],
                                                    opacity: [1, 0.5, 1]
                                                }}
                                                transition={{ 
                                                    width: { duration: 3, repeat: Infinity, ease: "linear" },
                                                    opacity: { duration: 1.5, repeat: Infinity }
                                                }}
                                            />
                                        )}
                                    </div>
                                </div>
                                
                                {/* Background Pulse for finding discovery */}
                                <AnimatePresence>
                                    {findings > 0 && isActive && (
                                        <motion.div 
                                            initial={{ opacity: 0, scale: 0.8 }}
                                            animate={{ opacity: [0, 0.2, 0], scale: [0.8, 1.2, 0.8] }}
                                            exit={{ opacity: 0 }}
                                            transition={{ duration: 2, repeat: Infinity }}
                                            className="absolute inset-0 bg-primary/20 pointer-events-none"
                                        />
                                    )}
                                </AnimatePresence>
                            </div>
                            
                            {/* Hover info tooltip-ish */}
                            <div className="absolute -top-1 left-1/2 -translate-x-1/2 bg-[#0b1525] border border-primary/50 rounded px-2 py-0.5 opacity-0 group-hover:opacity-100 transition-opacity z-20 pointer-events-none">
                                <span className="font-mono text-[8px] text-primary whitespace-nowrap">CH_{v.label}_ACTIVE</span>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

export default TacticalHUD;
