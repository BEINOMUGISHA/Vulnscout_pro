import React, { useState, useEffect } from 'react';
import { Send, Code, Network, AlertCircle, Terminal, Globe } from 'lucide-react';
import { useLocation } from 'react-router-dom';
import api, { proxyApi } from '../api/client';
import { VulnScoutSounds } from '../lib/sounds';

const Repeater: React.FC = () => {
  const location = useLocation();
  const initData = location.state?.requestData;

  const [method, setMethod] = useState(initData?.method || 'GET');
  const [url, setUrl] = useState(initData?.url || 'https://');
  const [headersRaw, setHeadersRaw] = useState(
      initData?.headers 
      ? Object.entries(initData.headers).map(([k,v]) => `${k}: ${v}`).join('\n')
      : 'User-Agent: VulnScout-Pro/1.0\nAccept: */*'
  );
  const [body, setBody] = useState(initData?.body || '');
  
  const [responseRaw, setResponseRaw] = useState('');
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);
  const [payloadCategories, setPayloadCategories] = useState<Record<string, any[]>>({});
  const [timeElapsed, setTimeElapsed] = useState<number | null>(null);
  const [responseSize, setResponseSize] = useState<number | null>(null);

  // Load payload library
  useEffect(() => {
     proxyApi.getPayloads().then((res: any) => {
         if (res.data && res.data.categories) {
             setPayloadCategories(res.data.categories);
         }
     }).catch(console.error);
  }, []);


  // Sync state if navigation changes
  useEffect(() => {
     if (location.state?.requestData) {
         const data = location.state.requestData;
         setMethod(data.method || 'GET');
         setUrl(data.url || 'https://');
         setHeadersRaw(
             data.headers 
             ? Object.entries(data.headers).map(([k,v]) => `${k}: ${v}`).join('\n')
             : ''
         );
         setBody(data.body || '');
         setResponseRaw('');
         setResponseStatus(null);
     }
  }, [location.state]);

  const handleSend = async () => {
      setLoading(true);
      setResponseRaw('');
      setResponseStatus(null);
      setTimeElapsed(null);
      setResponseSize(null);
      
      const startTime = performance.now();
      
      try {
          // Send request payload to backend repeater dispatcher to avoid CORS
          const res = await api.post('/proxy/repeater', {
              method,
              url,
              headers: headersRaw.split('\n').reduce((acc, line) => {
                  const idx = line.indexOf(':');
                  if (idx > 0) {
                      acc[line.substring(0, idx).trim()] = line.substring(idx + 1).trim();
                  }
                  return acc;
              }, {} as Record<string, string>),
              body
          });
          
          setResponseStatus(res.data.status);
          const formattedHeaders = Object.entries(res.data.headers).map(([k,v]) => `${k}: ${v}`).join('\n');
          const finalResponse = `HTTP/1.1 ${res.data.status}\n${formattedHeaders}\n\n${res.data.body}`;
          setResponseRaw(finalResponse);
          
          setTimeElapsed(Math.round(performance.now() - startTime));
          setResponseSize(new Blob([finalResponse]).size); // simple byte size estimate
          
      } catch (err: any) {
          setResponseStatus(err.response?.status || 500);
          setResponseRaw(err.response?.data?.detail || err.message || 'Transmission failed.');
          setTimeElapsed(Math.round(performance.now() - startTime));
      } finally {
          setLoading(false);
      }
  };

  return (
    <div className="flex flex-col h-[85vh] cyber-grid">
      <div className="flex justify-between items-center mb-6">
        <div>
           <h1 className="text-4xl font-black flex items-center gap-3 tracking-tighter text-white">
             <div className="p-2 bg-primary/10 border border-primary/30 rounded-lg shadow-[0_0_15px_rgba(0,200,255,0.2)]">
               <Code className="text-primary w-6 h-6" />
             </div>
             REPEATER <span className="text-primary italic">CONSOLE</span>
           </h1>
           <p className="text-muted-foreground font-mono text-[10px] uppercase tracking-widest mt-2 flex items-center gap-2">
             <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
             Manual Payload Injection & Execution Environment [SEC-LEVEL: 4]
           </p>
        </div>
        
        <div className="flex gap-4 relative">
          <div className="relative">
              <button
                  onClick={() => {
                      VulnScoutSounds.play('buttonClick');
                      setShowDropdown(!showDropdown);
                  }}
                  className="group flex items-center gap-2 px-6 py-3 rounded-xl font-black uppercase tracking-widest transition-all bg-white/5 text-white hover:bg-white/10 border border-white/10 hover:border-primary/50"
              >
                  <Code size={16} className="text-primary group-hover:scale-110 transition-transform" /> Payloads
              </button>
              
              {showDropdown && (
                  <div className="absolute top-full mt-2 w-72 bg-[#070b14] border border-border/50 rounded-xl shadow-2xl z-50 overflow-hidden">
                      <div className="max-h-96 overflow-y-auto custom-scrollbar">
                          {Object.entries(payloadCategories).map(([category, items]) => (
                              <div key={category} className="mb-2">
                                  <div className="px-3 py-1.5 bg-white/5 text-[9px] font-black text-muted-foreground uppercase tracking-widest border-y border-white/5">
                                      {category}
                                  </div>
                                  {items.map((item, idx) => (
                                      <button 
                                          key={idx}
                                          onClick={() => {
                                              // Determine if we inject into body or headers based on content
                                              if (item.payload.startsWith('{') || item.payload.startsWith('<') || item.payload.startsWith('*')) {
                                                  setBody(item.payload);
                                              } else if (item.payload.includes(':')) {
                                                  setHeadersRaw(prev => prev ? `${prev}\n${item.payload}` : item.payload);
                                              } else {
                                                  setBody(item.payload);
                                              }
                                              setShowDropdown(false);
                                              VulnScoutSounds.play('buttonClick');
                                          }}
                                          className="w-full text-left px-4 py-2 hover:bg-white/5 transition-colors group/item"
                                      >
                                          <div className="text-[11px] font-bold text-white group-hover/item:text-primary transition-colors">{item.name}</div>
                                          <div className="text-[9px] text-muted-foreground mt-0.5" title={item.description}>
                                              {item.description.substring(0, 50)}{item.description.length > 50 ? '...' : ''}
                                          </div>
                                      </button>
                                  ))}
                              </div>
                          ))}
                          {Object.keys(payloadCategories).length === 0 && (
                              <div className="px-4 py-3 text-xs text-muted-foreground text-center italic">Failed to load payloads.</div>
                          )}
                      </div>
                  </div>
              )}
          </div>
          
          <button 
              onClick={() => {
                  VulnScoutSounds.play('buttonClick');
                  handleSend();
              }}
              disabled={loading}
              className={`flex items-center gap-2 px-8 py-3 rounded-xl font-black uppercase tracking-widest transition-all shadow-xl ${
                  loading ? 'bg-muted text-muted-foreground cursor-not-allowed' : 'bg-primary text-white hover:bg-primary/90 neon-blue hover:scale-[1.02]'
              }`}
          >
              {loading ? <Network size={16} className="animate-spin" /> : <Send size={16} />}
              {loading ? 'Transmitting...' : 'FIRE PAYLOAD'}
          </button>
        </div>
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-0">
        
        {/* Request Pane */}
        <div className="bg-card border border-border/50 rounded-2xl flex flex-col overflow-hidden shadow-2xl relative group">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="p-4 border-b border-white/5 bg-white/[0.02] flex items-center gap-4 justify-between">
              <div className="flex flex-1 items-center gap-4">
                  <div className="flex items-center gap-2 text-[10px] font-black text-white/40 uppercase tracking-[0.2em]">
                     <Terminal size={12} className="text-primary" /> Request
                  </div>
                  <div className="flex-1 flex gap-2 max-w-xl">
                    <select 
                        value={method} 
                        onChange={(e) => setMethod(e.target.value)}
                        className="bg-black/40 border border-white/10 rounded-lg text-[10px] font-black uppercase text-white px-3 py-1.5 outline-none hover:border-primary/30 transition-colors"
                    >
                        {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].map(m => (
                            <option key={m} value={m}>{m}</option>
                        ))}
                    </select>
                    
                    <input 
                        type="text" 
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        className="flex-1 bg-black/40 border border-white/10 rounded-lg text-[11px] font-mono text-cyan-400 px-4 py-1.5 outline-none focus:border-primary/50 transition-all"
                        placeholder="https://target.ug/api/v1/..."
                    />
                  </div>
              </div>
              
              <div className="flex items-center gap-2">
                  <button 
                      onClick={() => {
                          setMethod('GET');
                          setUrl('https://');
                          setHeadersRaw('User-Agent: VulnScout-Pro/1.0\nAccept: */*');
                          setBody('');
                          setResponseRaw('');
                          setResponseStatus(null);
                          setTimeElapsed(null);
                          setResponseSize(null);
                      }}
                      className="text-[9px] font-black uppercase tracking-widest text-muted-foreground hover:text-white px-3 py-1.5 border border-white/10 rounded-lg hover:border-white/30 transition-all"
                  >
                      Clear
                  </button>
                  <button 
                      onClick={() => navigator.clipboard.writeText(`${method} ${url}\n${headersRaw}\n\n${body}`)}
                      className="text-[9px] font-black uppercase tracking-widest text-primary/70 hover:text-primary px-3 py-1.5 border border-primary/20 rounded-lg hover:border-primary/50 hover:bg-primary/10 transition-all"
                  >
                      Copy
                  </button>
              </div>
          </div>
          <div className="flex-1 flex flex-col p-4 bg-[#070b14] gap-4">
              <div className="flex-[2] flex flex-col">
                  <span className="text-[9px] font-black uppercase tracking-[0.2em] text-white/30 mb-2">Structure.Headers</span>
                  <textarea 
                      value={headersRaw}
                      onChange={(e) => setHeadersRaw(e.target.value)}
                      className="flex-1 bg-black/20 border border-white/5 rounded-xl p-4 text-[11px] font-mono text-blue-400/80 outline-none focus:border-primary/30 resize-none leading-relaxed custom-scrollbar"
                      spellCheck="false"
                  />
              </div>
              <div className="flex-[3] flex flex-col">
                  <span className="text-[9px] font-black uppercase tracking-[0.2em] text-white/30 mb-2 flex justify-between">
                      <span>Structure.Body <span className="text-amber-500/50 ml-2 font-normal">(Injection Point)</span></span>
                  </span>
                  <textarea 
                      value={body}
                      onChange={(e) => setBody(e.target.value)}
                      className="flex-1 bg-black/20 border border-white/5 rounded-xl p-4 text-[11px] font-mono text-amber-400/80 outline-none focus:border-primary/30 resize-none leading-relaxed custom-scrollbar"
                      spellCheck="false"
                  />
              </div>
          </div>
        </div>

        {/* Response Pane */}
        <div className="bg-card border border-border/50 rounded-2xl flex flex-col overflow-hidden shadow-2xl relative group">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-success/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="p-4 border-b border-white/5 bg-white/[0.02] flex justify-between items-center h-[61px]">
              <div className="flex items-center gap-2 text-[10px] font-black text-white/40 uppercase tracking-[0.2em]">
                 <Globe size={12} className="text-success" /> Response
              </div>
              <div className="flex items-center gap-4">
                  {responseStatus && (
                      <div className="flex items-center gap-3">
                          {responseSize !== null && (
                              <span className="text-[10px] font-mono text-muted-foreground mr-2">
                                  {responseSize > 1024 ? `${(responseSize / 1024).toFixed(1)} KB` : `${responseSize} B`}
                              </span>
                          )}
                          {timeElapsed !== null && (
                              <span className={`text-[10px] font-mono mr-2 ${timeElapsed > 1000 ? 'text-amber-500' : 'text-primary/70'}`}>
                                  {timeElapsed}ms
                              </span>
                          )}
                          <span className={`text-[10px] font-black px-3 py-1 rounded-lg border flex items-center gap-2 ${
                              responseStatus >= 400 ? 'text-red-500 border-red-500/20 bg-red-500/5' : 'text-success border-success/20 bg-success/5'
                          }`}>
                              <div className={`w-1 h-1 rounded-full animate-pulse ${responseStatus >= 400 ? 'bg-red-500' : 'bg-success'}`} />
                              HTTP {responseStatus}
                          </span>
                      </div>
                  )}
                  {responseRaw && (
                      <button 
                          onClick={() => navigator.clipboard.writeText(responseRaw)}
                          className="text-[9px] font-black uppercase tracking-widest text-primary/70 hover:text-primary px-3 py-1.5 border border-primary/20 rounded-lg hover:border-primary/50 hover:bg-primary/10 transition-all ml-2"
                      >
                          Copy
                      </button>
                  )}
              </div>
          </div>
          <div className="flex-1 p-4 bg-[#070b14] overflow-auto custom-scrollbar">
              {responseRaw ? (
                  <pre className="text-[11px] font-mono text-white/60 whitespace-pre-wrap break-all leading-relaxed">
                      {responseRaw}
                  </pre>
              ) : (
                  <div className="h-full flex flex-col items-center justify-center space-y-4 opacity-50">
                      <div className="w-16 h-16 rounded-3xl border border-white/5 bg-white/[0.02] flex items-center justify-center">
                        <AlertCircle size={28} className="text-white/20" />
                      </div>
                      <p className="font-mono text-[9px] uppercase tracking-[0.3em] text-white/20 text-center max-w-[200px]">
                          Awaiting server response handshake...
                      </p>
                  </div>
              )}
          </div>
        </div>

      </div>
    </div>
  );
};

export default Repeater;
