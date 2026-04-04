import React, { useState, useEffect } from 'react';

const LiveClock: React.FC = () => {
    const [time, setTime] = useState('');

    useEffect(() => {
        const pad = (n: number) => n.toString().padStart(2, '0');
        const tick = () => {
            const n = new Date();
            setTime(`${pad(n.getUTCHours())}:${pad(n.getUTCMinutes())}:${pad(n.getUTCSeconds())}Z`);
        };
        tick();
        const id = setInterval(tick, 1000);
        return () => clearInterval(id);
    }, []);

    return (
        <div className="font-mono text-[13px] text-cyan-400 tracking-widest text-shadow-[0_0_10px_rgba(0,200,255,0.4)]">
            {time}
        </div>
    );
};

export default LiveClock;
