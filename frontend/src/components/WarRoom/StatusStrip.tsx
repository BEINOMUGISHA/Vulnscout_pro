import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

const StatusStrip: React.FC = () => {
    const [messages] = useState([
        "SYSTEM_CHECK: ENCRYPTION PROTOCOLS ACTIVE",
        "SCANNER_STATUS: RECONNAISSANCE MODULE 04 STANDBY",
        "THREAT_INTEL: NEW CVE DATABASE SYNCHRONIZED",
        "API_LINK: SECURE TUNNEL ESTABLISHED ON :8000",
        "SECURITY_POSTURE: ELEVATED PERIMETER MONITORING",
        "REGION_LOCKED: UGANDA-O1 | AIRTEL_MONEY_GW ACTIVE",
        "THREAT_LEVEL: ELEVATED | ANOMALY PROBABILITY: LOW",
        "OVERDRIVE_PROTOCOL: READY FOR TURBO DEPLOYMENT"
    ]);

    const [currentIndex, setCurrentIndex] = useState(0);
    const [cpuLoad, setCpuLoad] = useState(12);

    useEffect(() => {
        const interval = setInterval(() => {
            setCurrentIndex((prev) => (prev + 1) % messages.length);
        }, 5000);
        
        const loadInterval = setInterval(() => {
            setCpuLoad(Math.floor(Math.random() * 8) + 10);
        }, 3000);

        return () => {
            clearInterval(interval);
            clearInterval(loadInterval);
        };
    }, [messages.length]);

    return (
        <div className="fixed bottom-0 left-72 right-0 h-6 bg-[#0b1525] border-t border-white/5 z-50 flex items-center px-4 overflow-hidden">
            <div className="flex items-center gap-3 w-full">
                <span className="text-[8px] font-black text-primary uppercase tracking-[0.3em] flex-shrink-0">
                    LIVE_LOG ::
                </span>
                
                <div className="relative flex-1 h-full flex items-center overflow-hidden">
                    <motion.div
                        key={currentIndex}
                        initial={{ y: 20, opacity: 0 }}
                        animate={{ y: 0, opacity: 1 }}
                        exit={{ y: -20, opacity: 0 }}
                        transition={{ duration: 0.5 }}
                        className="text-[9px] font-mono text-white/40 uppercase tracking-widest whitespace-nowrap"
                    >
                        {messages[currentIndex]}
                    </motion.div>
                </div>

                <div className="flex items-center gap-4 text-[8px] font-black uppercase tracking-widest text-white/20">
                    <div className="flex items-center gap-1.5">
                        <span className="w-1 h-1 rounded-full bg-success" />
                        DATABASE_LINK: OK
                    </div>
                    <div className="flex items-center gap-1.5">
                        <span className="w-1 h-1 rounded-full bg-success animate-pulse" />
                        CPU_LOAD: {cpuLoad}%
                    </div>
                    <span className="font-mono text-white/10 uppercase">v2.0.4-gold_master</span>
                </div>
            </div>
        </div>
    );
};

export default StatusStrip;
