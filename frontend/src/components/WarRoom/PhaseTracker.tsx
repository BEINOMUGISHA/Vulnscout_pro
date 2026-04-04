import React from 'react';
import { motion } from 'framer-motion';
import { Check, Play, RefreshCw } from 'lucide-react';
import { VulnScoutSounds } from '../../lib/sounds';
import { scansApi } from '../../api/client';

export type ScanPhase = 'pending' | 'scope_check' | 'crawling' | 'detecting' | 'validating' | 'scoring' | 'complete';

interface PhaseTrackerProps {
    currentPhase: string;
    progress: number;
    scanId?: string;
    target?: string;
}

const PhaseTracker: React.FC<PhaseTrackerProps> = ({ currentPhase, progress, scanId, target }) => {
    React.useEffect(() => {
        if (!currentPhase) return;
        
        const soundMap: Record<string, string> = {
            'pending': 'phasePending',
            'scope_check': 'phaseAuthorising',
            'crawling': 'phaseCrawling',
            'detecting': 'phaseDetecting',
            'validating': 'phaseValidating',
            'scoring': 'phaseScoring',
            'complete': 'phaseComplete'
        };

        const soundName = soundMap[currentPhase.toLowerCase()];
        if (soundName) {
            VulnScoutSounds.play(soundName);
        }
    }, [currentPhase]);
    const phases: { id: ScanPhase; label: string }[] = [
        { id: 'pending', label: 'Pending' },
        { id: 'scope_check', label: 'Authorising' },
        { id: 'crawling', label: 'Crawling' },
        { id: 'detecting', label: 'Detecting' },
        { id: 'validating', label: 'Validating' },
        { id: 'scoring', label: 'Scoring' },
        { id: 'complete', label: 'Complete' }
    ];

    const getPhaseIndex = (p: string) => {
        return phases.findIndex(ph => ph.id === p.toLowerCase());
    };

    const currentIndex = getPhaseIndex(currentPhase);

    const handleForceProgress = async () => {
        if (!scanId) return;
        try {
            VulnScoutSounds.play('buttonClick'); 
            await scansApi.recover(scanId);
            console.log("Tactical recovery triggered for scan", scanId);
        } catch (error) {
            console.error("Failed to trigger recovery:", error);
        }
    };

    return (
        <div className="bg-card/40 backdrop-blur-md border border-border/50 rounded-2xl p-6 shadow-xl">
            <div className="flex justify-between items-center mb-6">
                <div className="flex flex-col">
                    <span className="font-mono text-[9px] text-white/40 uppercase tracking-widest">
                        Scan Progress
                    </span>
                    <span className="font-mono text-[10px] text-primary uppercase tracking-tighter">
                        ORCHESTRATOR — SCAN {scanId ? `#${scanId.substring(0, 8)}` : 'N/A'} — {target || 'NO TARGET'}
                    </span>
                </div>
                <div className="flex items-center gap-4">
                    {currentPhase.toLowerCase() === 'crawling' && (
                        <motion.button
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                            onClick={handleForceProgress}
                            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-500/10 border border-amber-500/30 hover:bg-amber-500/20 transition-all group"
                        >
                            <RefreshCw size={10} className="text-amber-500 animate-spin-slow group-hover:rotate-180 transition-transform duration-700" />
                            <span className="font-mono text-[9px] text-amber-500 font-bold uppercase tracking-tight">
                                Force Progress
                            </span>
                        </motion.button>
                    )}
                    <div className="text-right">
                        <span className="font-mono text-[10px] text-white font-black">{progress}%</span>
                    </div>
                </div>
            </div>

            <div className="relative flex items-center justify-between gap-2 px-2">
                {phases.map((phase, idx) => {
                    const isDone = currentIndex > idx || currentPhase === 'done';
                    const isActive = currentPhase === phase.id;
                    
                    return (
                        <React.Fragment key={phase.id}>
                            {/* Step Indicator */}
                            <div className="flex flex-col items-center gap-2 relative z-10">
                                <motion.div 
                                    initial={false}
                                    animate={{ 
                                        borderColor: isDone ? '#22c55e' : isActive ? '#00c8ff' : 'rgba(255,255,255,0.1)',
                                        boxShadow: isActive ? '0 0 15px rgba(0,200,255,0.3)' : 'none'
                                    }}
                                    className={`w-[22px] h-[22px] rounded-full border-2 bg-[#0b1525] flex items-center justify-center transition-colors`}
                                >
                                    {isDone ? (
                                        <Check size={12} className="text-success" />
                                    ) : isActive ? (
                                        <motion.div
                                            animate={{ opacity: [1, 0.4, 1] }}
                                            transition={{ duration: 1.5, repeat: Infinity }}
                                        >
                                            <Play size={10} className="text-primary fill-primary" />
                                        </motion.div>
                                    ) : (
                                        <span className="text-[10px] text-white/20 font-black">{idx + 1}</span>
                                    )}
                                </motion.div>
                                <span className={`font-mono text-[9px] uppercase tracking-wider ${
                                    isDone ? 'text-success' : isActive ? 'text-primary' : 'text-white/20'
                                }`}>
                                    {phase.label}
                                </span>
                            </div>

                            {/* Connector Line */}
                            {idx < phases.length - 1 && (
                                <div className="flex-1 h-[1px] bg-white/10 relative -top-3">
                                    <motion.div 
                                        className="absolute inset-0 bg-primary origin-left"
                                        initial={{ scaleX: 0 }}
                                        animate={{ 
                                            scaleX: isDone ? 1 : 0,
                                            backgroundColor: isDone ? '#22c55e' : '#00c8ff' 
                                        }}
                                        transition={{ duration: 0.8 }}
                                    />
                                </div>
                            )}
                        </React.Fragment>
                    );
                })}
            </div>

            <div className="mt-6">
                <div className="h-[2px] w-full bg-white/5 rounded-full overflow-hidden">
                    <motion.div 
                        className="h-full bg-primary neon-blue rounded-full"
                        animate={{ width: `${progress}%` }}
                        transition={{ duration: 1, ease: "easeOut" }}
                    />
                </div>
            </div>
        </div>
    );
};

export default PhaseTracker;
