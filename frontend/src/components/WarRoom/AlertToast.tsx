import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { AlertPayload } from './AlertToastProvider';
import { ShieldAlert, AlertTriangle, Info, X } from 'lucide-react';
import { VulnScoutSounds } from '../../lib/sounds';

interface AlertToastProps {
    alert: AlertPayload;
    onClose: () => void;
}

const AlertToast: React.FC<AlertToastProps> = ({ alert, onClose }) => {
    useEffect(() => {
        const timer = setTimeout(onClose, 5000);
        return () => clearTimeout(timer);
    }, [onClose]);

    const colors = {
        critical: 'border-red-500 text-red-500 shadow-red-500/20',
        warn: 'border-amber-500 text-amber-500 shadow-amber-500/20',
        info: 'border-cyan-500 text-cyan-500 shadow-cyan-500/20'
    };

    const Icons = {
        critical: ShieldAlert,
        warn: AlertTriangle,
        info: Info
    };

    const Icon = Icons[alert.type];

    return (
        <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -10, height: 0, marginBottom: 0 }}
            className={`pointer-events-auto w-full bg-black/95 backdrop-blur-md border-l-4 ${colors[alert.type]} p-3 rounded-sm shadow-xl flex gap-3 relative overflow-hidden group`}
        >
            <div className={`shrink-0 mt-0.5 ${colors[alert.type]}`}>
                <Icon size={16} />
            </div>
            <div className="flex-1 min-w-0">
                <h4 className={`font-mono text-[10px] font-black uppercase tracking-wider mb-0.5 ${colors[alert.type]}`}>
                    {alert.title}
                </h4>
                <p className="text-[11px] text-white/50 leading-tight truncate">
                    {alert.body}
                </p>
            </div>
            <button 
                onClick={() => {
                    VulnScoutSounds.play('toastDismiss');
                    onClose();
                }}
                className="opacity-0 group-hover:opacity-100 transition-opacity p-1 text-white/20 hover:text-white"
            >
                <X size={12} />
            </button>
            <motion.div 
                initial={{ scaleX: 1 }}
                animate={{ scaleX: 0 }}
                transition={{ duration: 5, ease: "linear" }}
                className={`absolute bottom-0 left-0 right-0 h-[1px] origin-left bg-current opacity-30`}
                style={{ color: 'inherit' }}
            />
        </motion.div>
    );
};

export default AlertToast;
