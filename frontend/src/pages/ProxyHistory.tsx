import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Play, Pause, Trash2, ArrowRightCircle, Search, Shield, Server, Activity } from 'lucide-react';
import { proxyApi } from '../api/client';
import { useNavigate } from 'react-router-dom';
import { VulnScoutSounds } from '../lib/sounds';
import ProxyOpsTerminal from '../components/ProxyOpsTerminal';
import { supabase } from '../lib/supabase';

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

const ProxyHistory: React.FC = () => {
  const [events, setEvents] = useState<ProxyEvent[]>([]);
  const [interceptEnabled, setInterceptEnabled] = useState(false);
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting');
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'request' | 'response'>('request');
  const [filterText, setFilterText] = useState('');
  const [viewMode, setViewMode] = useState<'standard' | 'ops'>('standard');
  
  const wsRef = useRef<WebSocket | null>(null);
  const navigate = useNavigate();

  const connectWs = useCallback(async () => {
    // Note: Protocol needs to match the environment (ws vs wss). 
    const wsUrl = window.location.origin.replace('http', 'ws') + '/api/v1/proxy/ws';
    const baseUrl = (import.meta as any).env?.DEV ? 'ws://localhost:8000/api/v1/proxy/ws' : wsUrl;
    
    // FETCH TOKEN FROM SUPABASE SESSION (Fixing the "No auth token found" warning)
    const { data: { session } } = await supabase.auth.getSession();
    const token = session?.access_token || localStorage.getItem('token'); 
    
    if (!token) {
      console.warn("WebSocket Uplink: No authentication session found. Connection deferred.");
      setWsStatus('disconnected');
      return;
    }

    const finalUrl = `${baseUrl}?token=${token}`;

    const ws = new WebSocket(finalUrl);
    wsRef.current = ws;

    ws.onopen = () => setWsStatus('connected');
    ws.onclose = () => {
      setWsStatus('disconnected');
      // Reconnect with 3s debounce to prevent churn
      setTimeout(() => { if (!wsRef.current || wsRef.current.readyState === WebSocket.CLOSED) connectWs(); }, 3000);
    };
    
    ws.onmessage = (msg) => {
      try {
        const data: ProxyEvent = JSON.parse(msg.data);
        if (data.type === 'state') {
          setInterceptEnabled(!!data.intercept_mode);
        } else {
          setEvents(prev => [data, ...prev].slice(0, 1000));
        }
      } catch (e) {
        console.error("WS Parse Error", e);
      }
    };
  }, []);

  useEffect(() => {
    // Fetch initial status
    proxyApi.getStatus().then(res => {
        setInterceptEnabled(res.data.intercept_mode);
    }).catch(console.error);

    connectWs();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [connectWs]);

  const toggleIntercept = async () => {
    VulnScoutSounds.play('buttonClick');
    const newState = !interceptEnabled;
    try {
      await proxyApi.setMode(newState);
      setInterceptEnabled(newState);
    } catch (e) {
      console.error("Failed to set intercept mode", e);
    }
  };

  const forwardRequest = async (id: string) => {
    VulnScoutSounds.play('buttonClick');
    try {
      await proxyApi.forward(id);
      // Let the WS response come through to naturally mark it as resolved
    } catch (e) {
      console.error("Forward failed", e);
    }
  };

  const dropRequest = async (id: string) => {
    VulnScoutSounds.play('buttonClick');
    try {
      await proxyApi.drop(id);
      // Remove from frontend state optimistically
      setEvents(prev => prev.filter(e => e.id !== id));
      if (selectedEventId === id) setSelectedEventId(null);
    } catch (e) {
      console.error("Drop failed", e);
    }
  };

  const sendToRepeater = (event: ProxyEvent) => {
      // In a real app we'd use a Context or Redux store to share this.
      // For simplicity we pass state via React Router
      navigate('/repeater', { state: { requestData: event } });
  };

  const selectedEvent = events.find(e => e.id === selectedEventId);

  // Group requests/responses
  const groupedTasks: Record<string, {req?: ProxyEvent, res?: ProxyEvent}> = {};
  events.forEach(e => {
      if (e.type === 'request') {
          if (!groupedTasks[e.id]) groupedTasks[e.id] = {};
          groupedTasks[e.id].req = e;
      }
      if (e.type === 'response') {
          if (!groupedTasks[e.id]) groupedTasks[e.id] = {};
          groupedTasks[e.id].res = e;
      }
  });

  return (
    <div className="flex flex-col h-[85vh] cyber-grid">
      <div className="flex justify-between items-center mb-6">
        <div>
           <h1 className="text-3xl font-black flex items-center gap-3 tracking-tighter">
             <Server className="text-primary w-8 h-8" /> HTTP PROXY
           </h1>
           <p className="text-muted-foreground font-mono text-xs uppercase tracking-widest flex items-center gap-2 mt-1">
              <span className={`w-2 h-2 rounded-full ${wsStatus === 'connected' ? 'bg-success animate-pulse' : 'bg-destructive'}`}></span>
              {wsStatus === 'connected' ? 'Live Capture Active' : 'Uplink Offline'}
           </p>
        </div>
        
        <div className="flex items-center gap-4 bg-card p-2 rounded-xl border border-border/50">
           <div className="flex bg-black/40 p-1 rounded-lg border border-white/5">
              <button 
                onClick={() => { setViewMode('standard'); VulnScoutSounds.play('buttonClick'); }}
                className={`px-3 py-1 rounded text-[9px] font-black uppercase tracking-widest transition-all ${viewMode === 'standard' ? 'bg-primary text-white shadow-[0_0_10px_rgba(0,200,255,0.3)]' : 'text-white/40 hover:text-white'}`}
              >Standard</button>
              <button 
                onClick={() => { setViewMode('ops'); VulnScoutSounds.play('buttonClick'); }}
                className={`px-3 py-1 rounded text-[9px] font-black uppercase tracking-widest transition-all ${viewMode === 'ops' ? 'bg-primary text-white shadow-[0_0_10px_rgba(0,200,255,0.3)]' : 'text-white/40 hover:text-white'}`}
              >Ops / Terminal</button>
           </div>
           <div className="w-px h-6 bg-border"></div>
           <button 
             onClick={toggleIntercept}
             className={`flex items-center gap-2 px-6 py-2 rounded-lg font-black uppercase text-xs tracking-widest transition-all ${
                 interceptEnabled 
                 ? 'bg-warning text-warning-foreground neon-red' 
                 : 'bg-muted text-muted-foreground hover:bg-white/10'
             }`}
           >
             {interceptEnabled ? <Pause size={14} /> : <Play size={14} />}
             Intercept is {interceptEnabled ? 'ON' : 'OFF'}
           </button>
           <div className="w-px h-6 bg-border"></div>
           <button 
             onClick={() => {
                 VulnScoutSounds.play('toastDismiss');
                 setEvents([]);
             }} 
             className="p-2 text-muted-foreground hover:text-destructive transition-colors" 
             title="Clear History"
           >
              <Trash2 size={16} />
           </button>
        </div>
      </div>

      <div className="flex-1 min-h-0">
        {viewMode === 'ops' ? (
          <div className="h-full animate-in fade-in zoom-in-95 duration-500">
            <ProxyOpsTerminal 
              events={events}
              interceptEnabled={interceptEnabled}
              onForward={forwardRequest}
              onDrop={dropRequest}
              onClear={() => setEvents([])}
            />
          </div>
        ) : (
          <div className="h-full grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-0">
            {/* History Table Pool */}
            <div className="bg-card border border-border rounded-2xl flex flex-col overflow-hidden glass shadow-2xl relative">
              <div className="p-4 border-b border-white/5 bg-white/5 flex justify-between items-center">
                 <h3 className="font-black text-xs tracking-[0.2em] text-muted-foreground uppercase flex items-center gap-2">
                     <Activity size={14} className="text-primary"/> Traffic Log
                 </h3>
                 <div className="relative text-muted-foreground">
                     <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2" />
                     <input 
                        type="text" 
                        placeholder="FILTER..." 
                        value={filterText}
                        onChange={(e) => setFilterText(e.target.value)}
                        className="bg-white/5 border border-border rounded border-none text-[10px] uppercase font-mono px-6 py-1 w-40 placeholder:text-muted-foreground outline-none focus:ring-1 ring-primary/50" 
                     />
                 </div>
              </div>
              <div className="flex-1 overflow-auto p-0">
                {Object.keys(groupedTasks).length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center space-y-4 opacity-50">
                        <Shield size={48} className="text-muted-foreground" />
                        <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">Awaiting Network Traffic...</p>
                    </div>
                ) : (
                  <table className="w-full text-left border-collapse">
                    <thead className="sticky top-0 bg-[#0f172a] shadow-md z-10 border-b border-border">
                      <tr>
                        <th className="p-3 text-[10px] font-black text-muted-foreground uppercase tracking-widest w-16">#</th>
                        <th className="p-3 text-[10px] font-black text-muted-foreground uppercase tracking-widest">Method</th>
                        <th className="p-3 text-[10px] font-black text-muted-foreground uppercase tracking-widest">URL</th>
                        <th className="p-3 text-[10px] font-black text-muted-foreground uppercase tracking-widest">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/20">
                      {Object.values(groupedTasks)
                        .filter(pair => !filterText || pair.req?.url?.toLowerCase().includes(filterText.toLowerCase()))
                        .map((pair, idx) => {
                        const req = pair.req;
                        const res = pair.res;
                        if (!req) return null; // Wait for request
                        const isSelected = selectedEventId === req.id;
                        const isPending = interceptEnabled && !res;
                        
                        return (
                            <tr 
                                key={req.id} 
                                onClick={() => setSelectedEventId(req.id)}
                                className={`cursor-pointer transition-colors ${
                                    isSelected ? 'bg-primary/10 border-l-2 border-primary' 
                                    : isPending ? 'bg-warning/10 hover:bg-warning/20' 
                                    : 'hover:bg-white/[0.02] border-l-2 border-transparent'
                                }`}
                            >
                                <td className="p-3 text-[10px] font-mono text-muted-foreground">{idx + 1}</td>
                                <td className="p-3">
                                    <span className={`text-[10px] font-black tracking-widest px-2 py-0.5 rounded ${
                                        req.method === 'GET' ? 'text-[#3b82f6] bg-[#3b82f6]/10' :
                                        req.method === 'POST' ? 'text-[#22c55e] bg-[#22c55e]/10' :
                                        'text-warning bg-warning/10'
                                    }`}>{req.method}</span>
                                </td>
                                <td className="p-3">
                                    <div className="text-xs font-mono truncate max-w-[250px] text-white" title={req.url}>
                                        {req.url}
                                    </div>
                                </td>
                                <td className="p-3 text-[10px] font-mono font-bold">
                                    {isPending ? (
                                        <span className="text-warning animate-pulse flex items-center gap-1">PAUSED</span>
                                    ) : res ? (
                                        <span className={res.status && res.status >= 400 ? 'text-destructive' : 'text-success'}>
                                            {res.status}
                                        </span>
                                    ) : (
                                        <span className="text-muted-foreground">—</span>
                                    )}
                                </td>
                            </tr>
                        )
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            {/* Inspector Pane */}
            <div className="bg-card border border-border rounded-2xl flex flex-col overflow-hidden glass shadow-2xl">
               <div className="p-4 border-b border-white/5 bg-white/5 flex gap-2">
                   <button 
                      onClick={() => {
                          VulnScoutSounds.play('buttonClick');
                          setActiveTab('request');
                      }}
                      className={`text-[10px] font-black px-4 py-1.5 rounded uppercase tracking-widest transition-colors ${
                          activeTab === 'request' ? 'bg-primary/20 text-primary' : 'text-muted-foreground hover:bg-white/5'
                      }`}
                   >Request</button>
                   <button 
                      onClick={() => {
                          VulnScoutSounds.play('buttonClick');
                          setActiveTab('response');
                      }}
                      className={`text-[10px] font-black px-4 py-1.5 rounded uppercase tracking-widest transition-colors ${
                          activeTab === 'response' ? 'bg-primary/20 text-primary' : 'text-muted-foreground hover:bg-white/5'
                      }`}
                   >Response</button>
               </div>
               
               <div className="flex-1 p-4 overflow-auto min-h-0 bg-[#0a0f1a]">
                   {selectedEvent ? (
                       <div className="space-y-4">
                           {/* Control Bar for Intercepted */}
                           {interceptEnabled && !groupedTasks[selectedEvent.id]?.res && (
                               <div className="mb-4 flex gap-4">
                                   <button 
                                     onClick={() => forwardRequest(selectedEvent.id)}
                                     className="flex items-center gap-2 bg-success text-black hover:bg-success/90 px-4 py-2 rounded text-[10px] font-black uppercase tracking-widest transition-all neon-green"
                                   >
                                       <Play size={12} /> Forward
                                   </button>
                                   <button 
                                     onClick={() => dropRequest(selectedEvent.id)}
                                     className="flex items-center gap-2 bg-destructive/20 text-destructive hover:bg-destructive/40 px-4 py-2 rounded text-[10px] font-black uppercase tracking-widest transition-all"
                                   >
                                       <Trash2 size={12} /> Drop
                                   </button>
                               </div>
                           )}

                           <div className="font-mono text-xs whitespace-pre-wrap break-all text-blue-400 leading-relaxed">
                               {activeTab === 'request' ? (
                                   <>
                                       <span className="text-[#22c55e]">{selectedEvent.method}</span> {selectedEvent.url} HTTP/1.1{'\n'}
                                       {selectedEvent.headers && Object.entries(selectedEvent.headers).map(([k, v]) => (
                                           <div key={k}><span className="text-gray-400">{k}:</span> <span className="text-gray-200">{v}</span></div>
                                       ))}
                                       {'\n'}
                                       <span className="text-yellow-400">{selectedEvent.body}</span>
                                   </>
                               ) : (
                                   groupedTasks[selectedEvent.id]?.res ? (
                                       <>
                                           <span className={groupedTasks[selectedEvent.id]?.res?.status && groupedTasks[selectedEvent.id]!.res!.status! >= 400 ? 'text-destructive' : 'text-success'}>
                                               HTTP/1.1 {groupedTasks[selectedEvent.id]?.res?.status}
                                           </span>{'\n'}
                                           {groupedTasks[selectedEvent.id]?.res?.headers && Object.entries(groupedTasks[selectedEvent.id]!.res!.headers!).map(([k, v]) => (
                                               <div key={k}><span className="text-gray-400">{k}:</span> <span className="text-gray-200">{v}</span></div>
                                           ))}
                                           {'\n'}
                                           <span className="text-yellow-400">{groupedTasks[selectedEvent.id]?.res?.body}</span>
                                       </>
                                   ) : (
                                       <span className="text-muted-foreground italic">No response received yet...</span>
                                   )
                               )}
                           </div>
                       </div>
                   ) : (
                       <div className="h-full flex items-center justify-center text-muted-foreground text-[10px] font-mono uppercase tracking-widest">
                           Select a line from the proxy history.
                       </div>
                   )}
               </div>

               {selectedEvent && (
                  <div className="p-4 border-t border-white/5 bg-[#0f172a] flex justify-end">
                      <button 
                        onClick={() => sendToRepeater(selectedEvent)}
                        className="flex items-center gap-2 text-primary hover:text-white border border-primary/30 hover:bg-primary/20 px-4 py-2 rounded shadow-sm text-[10px] font-black uppercase tracking-widest transition-all"
                      >
                          Send to Repeater <ArrowRightCircle size={14} />
                      </button>
                  </div>
               )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProxyHistory;
