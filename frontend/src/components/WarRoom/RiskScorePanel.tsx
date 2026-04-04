import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { VulnScoutSounds } from '../../lib/sounds';

interface RiskScorePanelProps {
    score: number;
}

const RiskScorePanel: React.FC<RiskScorePanelProps> = ({ score }) => {
    const [displayScore, setDisplayScore] = useState(0);
    const lastSoundThreshold = useRef<number>(0);

    useEffect(() => {
        const duration = 1200;
        const start = displayScore;
        const end = score;
        const startTime = performance.now();

        const animate = (currentTime: number) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const current = Math.floor(start + (end - start) * progress);
            
            setDisplayScore(current);

            // Sound triggers on thresholds
            if (current >= 75 && lastSoundThreshold.current < 75) {
                VulnScoutSounds.play('riskHigh');
                lastSoundThreshold.current = 75;
            } else if (current < 40 && lastSoundThreshold.current >= 40) {
                VulnScoutSounds.play('riskNominal');
                lastSoundThreshold.current = 0;
            }

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    }, [score]);

    const getStatus = (val: number) => {
        if (val > 80) return { label: 'CRITICAL — IMMEDIATE ACTION REQUIRED', color: 'text-red-500' };
        if (val > 60) return { label: 'HIGH — MULTIPLE VECTORS ACTIVE', color: 'text-amber-500' };
        if (val > 40) return { label: 'ELEVATED — MONITOR CLOSELY', color: 'text-yellow-500' };
        return { label: 'NOMINAL — CONTINUE MONITORING', color: 'text-success' };
    };

    const status = getStatus(displayScore);

    return (
        <div className="mt-auto pt-6 border-t border-border/50">
            <div className="flex flex-col items-center text-center">
                <span className="font-mono text-[9px] tracking-widest text-white/40 uppercase mb-2">
                    GLOBAL RISK SCORE
                </span>
                
                <div className={`text-5xl font-black mb-2 tracking-tighter ${
                    displayScore > 70 ? 'text-red-500 [text-shadow:_0_0_20px_rgba(239,68,68,0.4)]' : 
                    displayScore > 40 ? 'text-amber-500 [text-shadow:_0_0_20px_rgba(245,158,11,0.3)]' : 
                    'text-success [text-shadow:_0_0_20px_rgba(34,197,94,0.3)]'
                }`}>
                    {displayScore}
                </div>

                <div className={`text-[8px] font-mono font-bold uppercase tracking-tight mb-4 ${status.color}`}>
                    {status.label}
                </div>

                <div className="relative w-full h-[5px] bg-white/5 rounded-full overflow-hidden mb-2">
                    <div className="absolute inset-0 bg-gradient-to-r from-[#00ff88] via-[#ffaa00] to-[#ff2244]" />
                    <motion.div 
                        className="absolute top-0 bottom-0 w-1 bg-white shadow-[0_0_8px_white] z-10"
                        animate={{ left: `${displayScore}%` }}
                        transition={{ type: 'spring', damping: 20, stiffness: 60 }}
                        style={{ x: '-50%' }}
                    />
                </div>
            </div>
        </div>
    );
};

export default RiskScorePanel;
