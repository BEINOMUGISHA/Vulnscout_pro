import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Shield, Zap, Terminal, Globe, Clock, ChevronRight } from 'lucide-react';

export interface Finding {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    vuln_type: string;
    description: string;
    remediation?: string;
    url?: string;
    timestamp?: string;
    evidence?: string;
}

interface FindingModalProps {
    finding: Finding | null;
    isOpen: boolean;
    onClose: () => void;
}

const FindingModal: React.FC<FindingModalProps> = ({ finding, isOpen, onClose }) => {
    if (!finding) return null;

    const severityColor = 
        finding.severity === 'critical' ? 'text-red-500 border-red-500/20 bg-red-500/5' :
        finding.severity === 'high' ? 'text-amber-500 border-amber-500/20 bg-amber-500/5' :
        finding.severity === 'medium' ? 'text-yellow-500 border-yellow-500/20 bg-yellow-500/5' :
        'text-cyan-500 border-cyan-500/20 bg-cyan-500/5';

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
                        initial={{ opacity: 0, scale: 0.9, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.9, y: 20 }}
                        className="relative w-full max-w-2xl bg-[#0b1525] border border-white/10 rounded-3xl overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.5)]"
                    >
                        {/* Header */}
                        <div className="p-6 border-b border-white/5 flex justify-between items-start bg-white/[0.02]">
                            <div className="space-y-1">
                                <div className="flex items-center gap-3">
                                    <span className={`px-2 py-0.5 rounded border text-[10px] font-black uppercase tracking-widest ${severityColor}`}>
                                        {finding.severity}
                                    </span>
                                    <span className="font-mono text-[10px] text-white/40 uppercase tracking-widest">
                                        FINDING_ID: {finding.id.substring(0,8).toUpperCase()}
                                    </span>
                                </div>
                                <h2 className="text-xl font-black text-white tracking-tight mt-2">{finding.title}</h2>
                            </div>
                            <button 
                                onClick={onClose}
                                className="p-2 text-white/20 hover:text-white hover:bg-white/5 rounded-xl transition-all"
                            >
                                <X size={20} />
                            </button>
                        </div>

                        {/* Content */}
                        <div className="p-6 space-y-8 max-h-[70vh] overflow-y-auto custom-scrollbar">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="p-4 bg-white/[0.02] border border-white/5 rounded-2xl">
                                    <div className="flex items-center gap-2 text-[10px] font-black text-white/40 uppercase tracking-widest mb-2">
                                        <Globe size={12} /> Target URL
                                    </div>
                                    <div className="text-xs font-mono text-cyan-400 break-all">{finding.url || 'N/A'}</div>
                                </div>
                                <div className="p-4 bg-white/[0.02] border border-white/5 rounded-2xl">
                                    <div className="flex items-center gap-2 text-[10px] font-black text-white/40 uppercase tracking-widest mb-2">
                                        <Clock size={12} /> Detected At
                                    </div>
                                    <div className="text-xs font-mono text-white/80">{finding.timestamp || 'Just now'}</div>
                                </div>
                            </div>

                            <div className="space-y-3">
                                <div className="flex items-center gap-2 text-[10px] font-black text-white/40 uppercase tracking-widest">
                                    <Shield size={12} /> Vulnerability Analysis
                                </div>
                                <p className="text-sm text-white/70 leading-relaxed italic border-l-2 border-primary/20 pl-4 bg-primary/5 py-2">
                                    {finding.description}
                                </p>
                            </div>

                            {finding.evidence && (
                                <div className="space-y-3">
                                    <div className="flex items-center gap-2 text-[10px] font-black text-white/40 uppercase tracking-widest">
                                        <Terminal size={12} /> Proof of Concept / Evidence
                                    </div>
                                    <pre className="p-4 bg-black rounded-xl border border-white/5 text-[11px] font-mono text-cyan-300 overflow-x-auto">
                                        {finding.evidence}
                                    </pre>
                                </div>
                            )}

                            {finding.remediation && (
                                <div className="space-y-3">
                                    <div className="flex items-center gap-2 text-[10px] font-black text-[#00ff88] uppercase tracking-widest">
                                        <Zap size={12} /> Remediation Protocol
                                    </div>
                                    <p className="text-sm text-white/70 leading-relaxed pl-4">
                                        {finding.remediation}
                                    </p>
                                </div>
                            )}
                        </div>

                        {/* Footer */}
                        <div className="p-4 border-t border-white/5 bg-white/[0.01] flex justify-end gap-3">
                            <button className="px-5 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest bg-white/5 hover:bg-white/10 text-white transition-all">
                                Export Evidence
                            </button>
                            <button className="px-5 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest bg-primary text-white shadow-lg neon-blue flex items-center gap-2">
                                Start Triage <ChevronRight size={14} />
                            </button>
                        </div>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
};

export default FindingModal;
