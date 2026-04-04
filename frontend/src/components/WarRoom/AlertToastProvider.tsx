import React, { createContext, useContext, useState, useCallback } from 'react';
import { AnimatePresence } from 'framer-motion';
import AlertToast from './AlertToast';
import { VulnScoutSounds } from '../../lib/sounds';

export interface AlertPayload {
    id: string;
    type: 'critical' | 'warn' | 'info';
    title: string;
    body: string;
}

interface AlertContextType {
    showAlert: (alert: Omit<AlertPayload, 'id'>) => void;
}

const AlertContext = createContext<AlertContextType | undefined>(undefined);

export const useAlerts = () => {
    const context = useContext(AlertContext);
    if (!context) throw new Error('useAlerts must be used within AlertToastProvider');
    return context;
};

export const AlertToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [alerts, setAlerts] = useState<AlertPayload[]>([]);

    const showAlert = useCallback((alert: Omit<AlertPayload, 'id'>) => {
        const id = Math.random().toString(36).substring(2, 9);
        if (alert.type === 'critical') {
            VulnScoutSounds.play('missilelock');
        }
        setAlerts(prev => [...prev, { ...alert, id }].slice(-4)); // Max 4 visible
    }, []);

    const removeAlert = useCallback((id: string) => {
        setAlerts(prev => prev.filter(a => a.id !== id));
    }, []);

    return (
        <AlertContext.Provider value={{ showAlert }}>
            {children}
            <div className="fixed top-[5rem] left-[1rem] w-[260px] flex flex-col gap-[6px] z-[100] pointer-events-none">
                <AnimatePresence mode="popLayout">
                    {alerts.map(alert => (
                        <AlertToast 
                            key={alert.id} 
                            alert={alert} 
                            onClose={() => removeAlert(alert.id)} 
                        />
                    ))}
                </AnimatePresence>
            </div>
        </AlertContext.Provider>
    );
};
