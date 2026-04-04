import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api, { scansApi } from '../api/client';
import { 
  ChevronRight, RefreshCw, StopCircle, Download, FileText, 
  Terminal, Activity, ShieldCheck, AlertCircle, ArrowLeft,
  Cpu, Globe, Zap
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { VulnScoutSounds } from '../lib/sounds';

import TacticalTerminal from '../components/TacticalTerminal';
import CVSSRadialChart from '../components/CVSSRadialChart';

interface ScanEvent {
  timestamp: string;
  phase: string;
  message: string;
  level: string;
  data?: any;
}

const ScanDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'findings' | 'logs'>('findings');
  const [showTerminal, setShowTerminal] = useState(false);
  const [progress, setProgress] = useState(1);
  
  const eventSourceRef = useRef<EventSource | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  const handleDownloadLogs = (e: React.MouseEvent) => {
    if (id === 'live') {
      e.preventDefault();
      VulnScoutSounds.play('exportBlip');
      const header = `================================================================================\n` +
                     `VULNSCOUT PRO ORCHESTRATOR MISSION LOGS — [RESTRICTED ACCESS]\n` +
                     `Generated: ${new Date().toISOString()}\n` +
                     `Target: ${scan?.target_url || 'api.v1.target.node'}\n` +
                     `Status: ${scan?.status.toUpperCase()}\n` +
                     `Intelligence Pack: VSP-744-INTEL\n` +
                     `================================================================================\n\n`;
      const logText = header + events.map(ev => `[${new Date(ev.timestamp).toLocaleTimeString()}] [${ev.phase.padEnd(10)}] ${ev.message}`).join('\n');
      const blob = new Blob([logText], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnscout_logs_${Date.now()}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else {
      VulnScoutSounds.play('exportBlip');
    }
  };

  const handleDownloadJSON = (e: React.MouseEvent) => {
    if (id === 'live') {
      e.preventDefault();
      VulnScoutSounds.play('exportBlip');
      const exportData = { 
        metadata: {
          scan_id: `vsp-${Date.now()}`,
          engine: 'VulnScout Pro (v4.4.2)',
          signature_db: '2026.03.R4',
          target_url: scan?.target_url,
          intel_classification: 'Level-5 High Visibility'
        },
        executive_summary: {
          total_findings: findings.length,
          critical_alerts: findings.filter(f => f.severity === 'critical').length,
          status: 'Operational Review Required'
        },
        findings: findings.map(f => ({
          title: f.title,
          severity: f.severity.toUpperCase(),
          cvss_vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`,
          cvss_score: f.cvss_score,
          evidence_log: f.evidence,
          remediation: f.remediation,
          impact_analysis: f.impact
        })), 
        raw_events: events 
      };
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnscout_intel_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else {
      VulnScoutSounds.play('exportBlip');
    }
  };

  const handleDownloadCSV = (e: React.MouseEvent) => {
    if (id === 'live') {
      e.preventDefault();
      VulnScoutSounds.play('exportBlip');
      const headers = ['Vulnerability', 'Severity', 'Confidence', 'Path', 'CVSS Score', 'Impact', 'Remediation'].join(',');
      const rows = findings.map(f => [
        `"${f.title || ''}"`,
        f.severity.toUpperCase(),
        `${(f.confidence * 100).toFixed(1)}%`,
        `"${f.path || ''}"`,
        f.cvss_score,
        `"${f.impact || ''}"`,
        `"${f.remediation || ''}"`
      ].join(','));
      
      const csvContent = [headers, ...rows].join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnscout_matrix_${Date.now()}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else {
      VulnScoutSounds.play('exportBlip');
    }
  };

  const loadData = async () => {
    if (!id || id === 'undefined') {
      navigate('/scans');
      return;
    }
    if (id === 'live') {
      setScan({
        id: 'live',
        target_url: 'https://api.v1.target.node',
        status: 'running',
        current_phase: 'scope',
        metrics: {
          crawl: { pages_crawled: 0 },
          detection: { total_requests_sent: 0 },
          performance: { avg_response_time_ms: 104 }
        }
      });
      setFindings([]);
      setEvents([{ timestamp: new Date().toISOString(), phase: 'SYSTEM', message: 'Orchestrator Initiated... Establishing secure link to target nodes.', level: 'info' }]);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const [scanRes, findingsRes] = await Promise.all([
        scansApi.get(id),
        api.get(`/scans/${id}/findings`)
      ]);
      setScan(scanRes.data);
      setFindings(findingsRes.data.items || []);
      if (scanRes.data.events) {
        setEvents(scanRes.data.events);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();

    if (id === 'live') {
      let startTime = Date.now();
      let duration = 55000;
      let timer: any;
      let findingsCount = 0;
      
      const randArr = (arr: any[]) => arr[Math.floor(Math.random() * arr.length)];
      const randInt = (min: number, max: number) => Math.floor(Math.random() * (max - min) + min);
      
      // Sonar Pulse Loop for Live Scan
      const sonarInterval = setInterval(() => {
        if (Date.now() - startTime < duration) {
          VulnScoutSounds.play('sonarPulse');
        }
      }, 4000);

      const findingGenerators = [
        () => {
          const ep = randArr(["/login/auth", "/admin/login", "/api/v1/auth", "/user/authn"]);
          const prm = randArr(["username", "email", "login_id"]);
          return { 
            title: "SQL Injection \u2014 Auth Bypass", 
            severity: 'critical', 
            confidence: randInt(92, 99)/100, 
            payload: "' OR '1'='1--", 
            path: ep, 
            cvss_score: (randInt(90, 100)/10).toFixed(1),
            impact: "Total compromise of back-end database. Unauthorized administrative session generation detected.",
            remediation: "Implement parameterized queries and ensure strict validation of input parameters in authentication controllers.",
            evidence: `[Request]\nPOST ${ep} HTTP/1.1\nHost: target.node\nContent-Type: application/json\n\n{"${prm}": "admin' OR '1'='1--", "password": "any"}\n\n[Response]\nHTTP/1.1 200 OK\n\n{\n  "status": "success",\n  "token": "eyJhbG... (Session Generated)"\n}` 
          };
        },
        () => {
          const ep = randArr(["/api/v2/webhooks", "/proxy/fetch", "/api/v1/health/ping", "/images/download"]);
          return { 
            title: "SSRF \u2014 Open Metadata Fetch", 
            severity: 'critical', 
            confidence: randInt(88, 98)/100, 
            payload: "http://169.254.169.254/latest/meta-data/", 
            path: ep, 
            cvss_score: (randInt(85, 95)/10).toFixed(1),
            impact: "Exposure of sensitive cloud metadata including IAM credentials and instance identity tokens.",
            remediation: "Whitelist outbound IP/domain ranges and implement a secure proxy with strict ACLs for internal requests.",
            evidence: `[Request]\nPOST ${ep} HTTP/1.1\n\n{"url": "http://169.254.169.254/latest/meta-data/"}\n\n[Response]\nHTTP/1.1 200 OK\n\nami-id\ninstance-id\npublic-ipv4` 
          };
        },
        () => {
          const ep = randArr(["/api/v1/users/admin_config", "/user/profile", "/api/v3/payments", "/admin/sys/settings"]);
          const prm = randArr(["user_id", "account", "id", "cust_ref"]);
          const val = randInt(1, 9999);
          return { 
            title: "IDOR \u2014 Sensitive Data Leak", 
            severity: 'high', 
            confidence: randInt(80, 95)/100, 
            payload: `${prm}=${val}`, 
            path: ep, 
            cvss_score: (randInt(75, 88)/10).toFixed(1),
            impact: "Unauthorized access to PII and internal cross-tenant configurations.",
            remediation: "Enforce object-level authorization checks and transition to non-predictable UUIDs for resource identifiers.",
            evidence: `[Request] = Manipulated\nGET ${ep}?${prm}=${val} HTTP/1.1\nAuthorization: Bearer <low_privilege_token>\n\n[Response] = Data Leaked\nHTTP/1.1 200 OK\n\n{\n  "id": ${val},\n  "role": "ADMIN",\n  "internal_guid": "Z-${val}"\n}` 
          };
        },
        () => {
          const ep = randArr(["/search", "/profile/edit", "/posts/view", "/catalog/items"]);
          return { 
            title: "XSS Reflected \u2014 Sanitized Vector", 
            severity: 'informational', 
            confidence: randInt(20, 45)/100, 
            payload: "\"><svg/onload=alert(1)>", 
            path: ep, 
            cvss_score: 0.0,
            impact: "Attempted client-side code execution. Neutralized by current WAF profile.",
            remediation: "Continue monitoring endpoint for advanced bypass techniques. Update content security policy (CSP).",
            evidence: `[Audit Engine]\nInjected: <svg/onload=alert(1)>\n\n[Response Output Analysis]\nFiltered/Escaped by WAF:\n<div>&lt;svg/onload=alert(1)&gt;</div>\n\n[Conclusion]\nXSS failed. Flagged False Positive.` 
          };
        },
        () => {
          const ep = randArr(["/", "/api", "/assets/app.js", "/robots.txt"]);
          return { 
            title: "Misconfiguration \u2014 Missing Security Headers", 
            severity: 'medium', 
            confidence: 0.99, 
            payload: "N/A", 
            path: ep, 
            cvss_score: (randInt(40, 55)/10).toFixed(1),
            impact: "Sub-optimal browser-level security facilitates clickjacking and protocol downgrade attacks.",
            remediation: "Configure HSTS, CSP, and X-Content-Type-Options headers at the ingress controller level.",
            evidence: `[Vulnerability Signature Analysis]\nHTTP/1.1 200 OK\nServer: nginx/1.22.1\nConnection: keep-alive\n\n[Missing Headers Detected]\n- Strict-Transport-Security (HSTS)\n- Content-Security-Policy (CSP)\n- X-Frame-Options` 
          };
        },
        () => {
          const ep = randArr(["/api/v1/admin/debug", "/api/v1/export/pdf", "/system/ping"]);
          return { 
            title: "Command Injection \u2014 Shell Exec", 
            severity: 'critical', 
            confidence: randInt(95, 99)/100, 
            payload: "; id", 
            path: ep, 
            cvss_score: (randInt(95, 100)/10).toFixed(1),
            impact: "Remote Code Execution (RCE) on backend infrastructure. User 'root' context obtained.",
            remediation: "Replace shell execution logic with library-based system calls and sanitize all shell-bound parameters.",
            evidence: `[Request]\nPOST ${ep} HTTP/1.1\n\n{"target": "127.0.0.1; id"}\n\n[Response]\nHTTP/1.1 200 OK\n\nuid=0(root) gid=0(root) groups=0(root)` 
          };
        },
        () => {
          const ep = randArr(["/v1/oauth/authorize", "/webhook/stripe", "/login"]);
          const prm = randArr(["redirect_uri", "next", "callback"]);
          return { 
            title: "Open Redirect \u2014 Domain Whitelist bypass", 
            severity: 'high', 
            confidence: randInt(85, 95)/100, 
            payload: `${prm}=https://evil.target.node`, 
            path: ep, 
            cvss_score: (randInt(60, 75)/10).toFixed(1),
            impact: "Redirection of users to arbitrary malicious domains. Facilitates phishing and credential theft.",
            remediation: "Implement a robust URL whitelist and validate redirect targets against a safe domain registry.",
            evidence: `[Request]\nGET ${ep}?${prm}=https://evil.target.node HTTP/1.1\n\n[Response]\nHTTP/1.1 302 Found\nLocation: https://evil.target.node` 
          };
        }
      ];

      // Shuffle and select a dynamic subset per scan to ensure unique live findings
      const maxFindings = randInt(3, 7);
      const generatedPayloads = [...findingGenerators].sort(() => 0.5 - Math.random()).slice(0, maxFindings).map((gen, idx) => ({...gen(), id: idx}));

      const tick = () => {
        const elapsed = Date.now() - startTime;
        let percent = (elapsed / duration) * 100;
        if (percent >= 100) percent = 100;
        
        setProgress(percent);
        let p = 'scope';
        if (percent >= 98) p = 'complete';
        else if (percent >= 95) p = 'scoring';
        else if (percent >= 90) p = 'validating';
        else if (percent >= 40) p = 'detecting';
        else if (percent >= 5) p = 'crawling';
        
        setScan((prev: any) => {
          if (!prev) return prev;
          if (prev.current_phase !== p && p !== 'complete') VulnScoutSounds.play('phaseUp');
          
          let pages = prev.metrics?.crawl?.pages_crawled || 0;
          let reqs = prev.metrics?.detection?.total_requests_sent || 0;
          if (p === 'crawling' && Math.random() > 0.5) pages += Math.floor(Math.random() * 3);
          if (p === 'detecting') reqs += Math.floor(Math.random() * 8);

          return { 
            ...prev, 
            status: percent >= 100 ? 'complete' : 'running', 
            current_phase: percent >= 100 ? 'complete' : p,
            metrics: { ...prev.metrics, crawl: { pages_crawled: pages }, detection: { total_requests_sent: reqs } }
          };
        });

        // Distribute random findings across the execution lifetime (from 25% to 90%)
        const findingsUnlockProgress = Math.max(0, percent - 25) / 65; 
        const targetFindingsCount = Math.floor(findingsUnlockProgress * generatedPayloads.length);

        if (targetFindingsCount > findingsCount && targetFindingsCount <= generatedPayloads.length) {
            const newFindings = generatedPayloads.slice(0, targetFindingsCount);
            setFindings([...newFindings]);
            findingsCount = targetFindingsCount;
            
            const newlyAdded = newFindings[newFindings.length - 1];
            VulnScoutSounds.play('phaseUp');
            
            const lvl = newlyAdded.severity === 'informational' ? 'info' : (newlyAdded.severity === 'critical' ? 'error' : 'warning');
            const prefix = newlyAdded.severity === 'informational' ? '[FP]' : '[HIT]';
            
            setEvents(prev => [...prev.slice(-30), { 
                timestamp: new Date().toISOString(), 
                phase: p.toUpperCase(), 
                message: `${prefix} ${newlyAdded.title} on ${newlyAdded.path} (CVSS ${newlyAdded.cvss_score})`, 
                level: lvl 
            }]);
        }

        if (Math.random() > 0.8 && percent < 100) {
           const logMsg = ['[WAF] Rate limiting detected, pacing back off...', '[VULN] Injecting blind payload set...', '[ORCH] Scaling worker nodes...', '[OOB] Awaiting DNS callback...'][Math.floor(Math.random() * 4)];
           setEvents(prev => [...prev.slice(-30), { timestamp: new Date().toISOString(), phase: p.toUpperCase(), message: logMsg, level: 'info' }]);
        }

        if (percent >= 100) {
           VulnScoutSounds.play('missionComplete');
           clearTimeout(timer);
           clearInterval(sonarInterval);
        } else {
           timer = setTimeout(tick, 300);
        }
      };
      
      VulnScoutSounds.play('sseConnect');
      timer = setTimeout(tick, 300);
      return () => {
        clearTimeout(timer);
        clearInterval(sonarInterval);
      };
    }

    if (id) {
      const token = localStorage.getItem('token');
      const url = `/api/v1/scans/${id}/status?stream=true&token=${token}`;
      
      eventSourceRef.current = new EventSource(url);
      
      eventSourceRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        // Sound for phase transition
        setScan((prev: any) => {
            if (prev && data.current_phase && prev.current_phase !== data.current_phase) {
                VulnScoutSounds.play('phaseUp');
            }
            return { ...prev, ...data };
        });

        if (data.progress !== undefined) {
          setProgress(data.progress);
        }
        
        // Append new events if provided
        if (data.event) {
          setEvents(prev => [...prev, data.event]);
        }
        
        // Reload findings if finding_count increases
        if (data.new_findings > 0) {
           api.get(`/scans/${id}/findings`).then(res => setFindings(res.data.items || []));
        }
      };

      eventSourceRef.current.onopen = () => {
          VulnScoutSounds.play('sseConnect');
      };

      eventSourceRef.current.addEventListener('complete', () => {
        if (eventSourceRef.current) eventSourceRef.current.close();
        VulnScoutSounds.play('missionComplete');
        loadData();
      });

      eventSourceRef.current.onerror = () => {
        console.error("SSE connection error");
        VulnScoutSounds.play('sseDisconnect');
      };
    }

    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
    };
  }, [id]);

  // Sonar Pulse Loop for Real Scans (Backend SSE)
  useEffect(() => {
    let sonarTimer: any;
    if (scan?.status === 'running' && id !== 'live') {
      // Play initial pulse immediately
      VulnScoutSounds.play('sonarPulse');
      sonarTimer = setInterval(() => {
        VulnScoutSounds.play('sonarPulse');
      }, 4000);
    }
    return () => clearInterval(sonarTimer);
  }, [scan?.status, id]);

  useEffect(() => {
    if (activeTab === 'logs') {
      logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events, activeTab]);

  const handleStop = async () => {
    if (!confirm("Confirm scan termination? All unsaved state will be lost.")) return;
    VulnScoutSounds.play('buttonClick');
    try {
      await scansApi.cancel(id!);
      setScan((prev: any) => ({ ...prev, status: 'cancelled' }));
    } catch (e) {
      alert("Failed to terminate scan");
    }
  };

  const handlePoll = () => {
      VulnScoutSounds.play('buttonClick');
      loadData();
  };

  if (loading && !scan) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center space-y-4">
        <div className="w-12 h-12 border-4 border-primary/20 border-t-primary rounded-full animate-spin"></div>
        <p className="text-muted-foreground font-mono uppercase text-xs tracking-widest">Initialising Secure Link...</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center space-y-4">
        <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-xl text-destructive text-sm font-mono uppercase">
          Scan Trace Terminated or Invalid ID
        </div>
        <button 
          onClick={() => navigate('/scans')}
          className="text-xs font-black uppercase tracking-widest text-primary hover:underline"
        >
          Return to Fleet Command
        </button>
      </div>
    );
  }

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-8 min-h-screen pb-20 relative"
    >
      {/* Tactical Overlay */}
      <div className="scanline" />
      <TacticalTerminal 
        isOpen={showTerminal} 
        onClose={() => setShowTerminal(false)} 
        targetUrl={scan?.target?.url || scan?.target_url || id}
      />
      
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-6 relative z-10 pt-4">
        <div className="space-y-2">
          <button 
            onClick={() => {
                VulnScoutSounds.play('buttonClick');
                navigate('/scans');
            }}
            className="group flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground hover:text-primary transition-all"
          >
            <div className="p-1 rounded bg-muted/50 group-hover:bg-primary/20 group-hover:text-primary transition-colors">
              <ArrowLeft size={12} />
            </div>
            <span>Return to Fleet Command</span>
          </button>
          
        <div className="flex items-center gap-6">
          <div className="relative group">
            <div className="absolute inset-0 bg-primary/20 blur-[20px] rounded-full scale-150 animate-pulse"></div>
            <Activity className="text-primary h-14 w-14 relative z-10" />
          </div>
          <div>
            <h1 className="text-6xl font-black tracking-tighter italic uppercase bg-gradient-to-r from-primary via-blue-400 to-accent bg-clip-text text-transparent flex items-center gap-4">
              Mission Console
              <span className="text-xs font-mono text-muted-foreground/40 not-italic tracking-[0.5em] ml-4 bg-white/5 px-4 py-1 rounded-full border border-white/5">NODE-ALPHA-7</span>
            </h1>
            <div className="flex items-center gap-4 text-muted-foreground font-mono text-xs uppercase tracking-[0.3em] mt-2">
              <Globe size={16} className="text-primary animate-pulse"/> 
              <span className="text-white font-bold">{scan?.target?.url || scan?.target_url || id}</span>
              <span className="text-white/10">|</span>
              <span className="px-3 py-0.5 bg-primary/10 text-primary border border-primary/20 rounded text-[9px] font-black">STRIKE VECTOR ACTIVE</span>
            </div>
          </div>
        </div>
      </div>
        
        <div className="flex gap-3 w-full sm:w-auto">
          <button 
            onClick={() => {
              VulnScoutSounds.play('buttonClick');
              setShowTerminal(true);
            }} 
            className="flex-1 sm:flex-none flex items-center justify-center gap-3 bg-primary/10 text-primary hover:bg-primary hover:text-white border border-primary/20 hover:border-primary px-6 py-3 rounded-xl transition-all font-black text-xs uppercase tracking-widest neon-blue"
          >
            <Terminal size={18} /> System Terminal
          </button>
          {scan.status === 'running' && (
            <button 
              onClick={handleStop} 
              className="flex-1 sm:flex-none flex items-center justify-center gap-3 bg-destructive/5 text-destructive hover:bg-destructive hover:text-white border border-destructive/20 hover:border-destructive px-6 py-3 rounded-xl transition-all font-black text-xs uppercase tracking-widest neon-red"
            >
              <StopCircle size={18} /> Emergency Halt
            </button>
          )}
          <button 
            onClick={handlePoll} 
            className="flex-1 sm:flex-none flex items-center justify-center gap-3 bg-secondary/50 text-foreground hover:bg-primary/20 hover:text-primary border border-border px-6 py-3 rounded-xl transition-all font-black text-xs uppercase tracking-widest"
          >
            <RefreshCw size={18} className={scan.status === 'running' ? 'animate-spin' : ''} /> Force Sync
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_400px] gap-10 items-start relative z-10">
        
        <div className="space-y-10">
          {/* High-Performance Status Core - Maximized Visibility */}
          <div className="glass p-12 rounded-[40px] border-white/10 relative overflow-hidden group shadow-3xl bg-black/20">
            <div className="absolute top-0 left-0 w-2 h-full bg-primary shadow-[0_0_20px_#3b82f6]"></div>
            <div className="absolute top-0 right-0 w-[300px] h-full bg-gradient-to-l from-primary/5 to-transparent"></div>
            
            <div className="flex justify-between items-center mb-12">
              <div className="space-y-3">
                <span className="text-[11px] font-black uppercase tracking-[0.5em] text-primary/70 italic flex items-center gap-3">
                  <div className="w-8 h-[1px] bg-primary/40"></div> Orchestration Helix
                </span>
                <h2 className="text-6xl font-black text-white font-mono tracking-tighter select-all italic leading-none">
                  {scan.current_phase?.toUpperCase() || 'INITIALISING'}
                </h2>
              </div>
              <div className={`flex items-center gap-4 px-10 py-4 rounded-2xl text-xs font-black uppercase tracking-[0.3em] border-2 shadow-2xl transform transition-all hover:scale-105 ${
                scan.status === 'running' ? 'bg-primary/10 text-primary border-primary/40 neon-blue animate-pulse' : 
                scan.status === 'complete' ? 'bg-success/10 text-success border-success/40 neon-green' : 
                'bg-muted text-muted-foreground border-border'
              }`}>
                {scan.status === 'running' && <div className="w-3 h-3 rounded-full bg-primary shadow-[0_0_20px_#3b82f6] animate-ping"></div>}
                {scan.status === 'running' ? 'OPERATIONAL' : scan.status.toUpperCase()}
              </div>
            </div>

            <div className="relative pt-6 space-y-8">
              <div className="flex justify-between text-[10px] font-black uppercase tracking-[0.25em] text-muted-foreground px-2 mb-2 italic">
                {['Scope', 'Crawling', 'Detecting', 'Validating', 'Scoring', 'Complete'].map((p, i) => {
                  const isActive = scan.current_phase?.toLowerCase() === p.toLowerCase() || (scan.current_phase === 'initialising' && p === 'Scope');
                  const isDone = (scan.status === 'complete') || (progress > [5, 40, 90, 95, 98, 99][i]);
                  return (
                    <span key={p} className={`flex-1 text-center transition-all duration-500 scale-100 ${isActive ? 'text-primary scale-110 drop-shadow-[0_0_15px_rgba(59,130,246,0.9)]' : isDone ? 'text-success/70 hover:text-success' : 'opacity-20 hover:opacity-40'}`}>
                      {p}
                    </span>
                  );
                })}
              </div>
              
              <div className="flex gap-4 h-5">
                {[
                  { max: 5, start: 0, color: 'bg-primary' },
                  { max: 40, start: 5, color: 'bg-primary' },
                  { max: 90, start: 40, color: 'bg-blue-400' },
                  { max: 95, start: 90, color: 'bg-accent' },
                  { max: 98, start: 95, color: 'bg-success' }
                ].map((phase, i) => {
                  let pWidth = 0;
                  if (scan.status === 'complete') pWidth = 100;
                  else if (progress >= phase.max) pWidth = 100;
                  else if (progress > phase.start) pWidth = ((progress - phase.start) / (phase.max - phase.start)) * 100;
                  
                  return (
                    <div key={i} className="flex-1 bg-black/60 border border-white/10 rounded-full overflow-hidden relative shadow-inner">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${pWidth}%` }}
                        className={`absolute top-0 left-0 h-full ${phase.color} shadow-[0_0_15px_currentColor] opacity-100 transition-all duration-700 ease-out`}
                      >
                        <div className="absolute inset-0 bg-white/20 animate-pulse"></div>
                      </motion.div>
                    </div>
                  );
                })}
              </div>

              <div className="flex justify-between items-end mt-4 px-2">
                <div className="flex flex-col">
                   <span className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">Telemetry Sync</span>
                   <span className="text-[10px] font-mono text-white/40">{scan.status === 'running' ? 'LIVE' : 'IDLE'}</span>
                </div>
                <div className="text-center">
                  <span className="text-5xl font-black text-primary font-mono tracking-tighter drop-shadow-[0_0_15px_rgba(59,130,246,0.4)]">
                    {scan.status === 'complete' ? '100.0' : typeof progress === 'number' ? progress.toFixed(1) : parseFloat(progress).toFixed(1)}%
                  </span>
                </div>
                <div className="flex flex-col items-end">
                   <span className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">Orchestrator Link</span>
                   <span className="text-[10px] font-mono text-success">ESTABLISHED</span>
                </div>
              </div>
            </div>
          </div>

          {/* Activity Logs & Findings Tabs */}
          <div className="glass rounded-2xl border-border overflow-hidden min-h-[500px] flex flex-col">
            <div className="flex border-b border-border bg-white/5">
              <button 
                onClick={() => setActiveTab('findings')}
                className={`flex-1 flex items-center justify-center gap-2 py-4 text-xs font-bold uppercase tracking-widest transition-all ${activeTab === 'findings' ? 'bg-primary/10 text-primary border-b-2 border-primary' : 'text-muted-foreground hover:text-white'}`}
              >
                <AlertCircle size={16} /> Findings Intelligence ({findings.length})
              </button>
              <button 
                onClick={() => setActiveTab('logs')}
                className={`flex-1 flex items-center justify-center gap-2 py-4 text-xs font-bold uppercase tracking-widest transition-all ${activeTab === 'logs' ? 'bg-primary/10 text-primary border-b-2 border-primary' : 'text-muted-foreground hover:text-white'}`}
              >
                <Terminal size={16} /> Audit Event Log
              </button>
            </div>

            <div className="flex-1 overflow-auto bg-black/40">
              <AnimatePresence mode="wait">
                {activeTab === 'findings' ? (
                  <motion.div 
                    key="findings"
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 10 }}
                    className="divide-y divide-border/30"
                  >
                    {findings.length === 0 ? (
                      <div className="p-20 text-center space-y-4">
                        <ShieldCheck className="mx-auto text-muted-foreground/20" size={64} />
                        <p className="text-sm font-mono text-muted-foreground uppercase tracking-wider">No vulnerabilities detected in current scope.</p>
                      </div>
                    ) : (
                      findings.map((f) => (
                        <details key={f.id} className="group transition-all">
                          <summary className={`px-6 py-5 cursor-pointer hover:bg-white/[0.03] flex items-center gap-5 transition-all outline-none ${f.severity === 'critical' ? 'bg-destructive/5' : ''}`}>
                            <div className={`w-2 h-10 rounded-full ${
                              f.severity === 'critical' ? 'bg-destructive neon-red shadow-[0_0_10px_rgba(239,68,68,0.5)]' : 
                              f.severity === 'high' ? 'bg-warning' : 
                              f.severity === 'medium' ? 'bg-primary' : 'bg-muted-foreground/50'
                            }`}></div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded border ${
                                  f.severity === 'critical' ? 'bg-destructive/20 text-destructive border-destructive/30' : 
                                  'bg-muted text-muted-foreground border-border'
                                }`}>
                                  {f.severity}
                                </span>
                                <span className="text-[10px] font-mono text-muted-foreground">CONFIDENCE: {Math.round((f.confidence || 0.95)*100)}% Match</span>
                              </div>
                              <h3 className="font-bold text-sm tracking-tight truncate group-hover:text-primary transition-colors">{f.vuln_label || f.title}</h3>
                            </div>
                            <ChevronRight className="w-5 h-5 text-muted-foreground/50 group-open:rotate-90 transition-transform" />
                          </summary>
                          <div className="px-8 pb-8 pt-2 text-sm text-muted-foreground bg-black/20 space-y-6 border-t border-white/5">
                             <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                               <div className="space-y-1">
                                 <span className="text-[10px] font-black uppercase text-muted-foreground/60 tracking-widest">Target Surface</span>
                                 <p className="font-mono text-xs bg-muted/30 p-2 rounded border border-border/30 truncate">{f.url || f.path}</p>
                               </div>
                               <div className="space-y-1">
                                 <span className="text-[10px] font-black uppercase text-muted-foreground/60 tracking-widest">Injected Vector</span>
                                 <p className="font-mono text-xs bg-muted/30 p-2 rounded border border-border/30 truncate">{f.payload || f.parameter || 'Dynamic'}</p>
                               </div>
                             </div>

                             <div className="space-y-2">
                               <span className="text-[10px] font-black uppercase text-red-400/60 tracking-widest">Exploitation Impact</span>
                               <div className="p-3 bg-red-500/5 border border-red-500/20 rounded-lg text-xs leading-relaxed text-red-200/70 italic">
                                 {f.impact || "Analysis indicates potential for unauthorized data exfiltration or session hijacking if left unmitigated."}
                               </div>
                             </div>
                             
                             <div className="p-4 rounded-lg bg-primary/5 border border-primary/10">
                               <h4 className="font-bold text-xs text-primary mb-2 flex items-center gap-2 uppercase tracking-widest">
                                 <Zap size={14} /> Strategic Remediation
                               </h4>
                               <p className="text-xs leading-relaxed">
                                 {f.remediation || f.remediation_guide?.summary || "Enforce server-side input sanitization and implement a robust Content Security Policy (CSP)."}
                               </p>
                             </div>

                             {f.evidence && (
                               <div className="space-y-2">
                                 <span className="text-[10px] font-black uppercase text-muted-foreground/60 tracking-widest">Tactical Audit Evidence</span>
                                 <pre className="p-4 bg-black/60 border border-white/10 rounded-lg overflow-x-auto text-[11px] font-mono text-primary-foreground/90 whitespace-pre-wrap max-h-60 overflow-y-auto">
                                   {f.evidence}
                                 </pre>
                               </div>
                             )}
                          </div>
                        </details>
                      ))
                    )}
                  </motion.div>
                ) : (
                  <motion.div 
                    key="logs"
                    initial={{ opacity: 0, x: 10 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -10 }}
                    className="p-6 font-mono text-[11px] leading-relaxed"
                  >
                    <div className="space-y-1.5 min-h-[400px]">
                      {events.map((e, idx) => (
                        <div key={idx} className="flex gap-4 group">
                          <span className="text-muted-foreground/40 shrink-0">[{new Date(e.timestamp).toLocaleTimeString()}]</span>
                          <span className={`${e.level === 'error' ? 'text-destructive font-black' : e.level === 'warning' ? 'text-warning' : 'text-primary/70'} uppercase shrink-0`}>
                            {e.phase}
                          </span>
                          <span className="text-muted-foreground group-hover:text-white transition-colors">{e.message}</span>
                        </div>
                      ))}
                      <div ref={logEndRef} />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </div>

        <div className="space-y-8 h-fit lg:sticky lg:top-8">
          {/* CVSS SPECTRUM VISUALIZATION */}
          <CVSSRadialChart 
            data={{
               critical: findings.filter(f => f.severity === 'critical').length,
               high: findings.filter(f => f.severity === 'high').length,
               medium: findings.filter(f => f.severity === 'medium').length,
               low: findings.filter(f => f.severity === 'low').length,
               informational: findings.filter(f => f.severity === 'informational').length
            }}
            total={findings.length}
            averageScore={findings.length > 0 ? (findings.reduce((acc, f) => acc + parseFloat(f.cvss_score || '0'), 0) / findings.length) : 0}
          />

          {/* Real-time Telemetry Grid */}
          <div className="glass p-8 rounded-3xl border-border/40 space-y-8 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 blur-3xl rounded-full"></div>
            
            <h3 className="text-[10px] font-black uppercase tracking-[0.3em] text-primary/60 flex items-center gap-3 border-b border-white/5 pb-6">
              <Activity size={18} className="text-primary animate-pulse"/> Scan Data
            </h3>
            
            <div className="grid grid-cols-1 gap-4">
              <div className="bg-black/40 p-5 rounded-2xl border border-white/5 hover:border-primary/20 transition-all group">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-[9px] uppercase font-black text-muted-foreground tracking-widest">Target Assets Discovered</span>
                  <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse"></div>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-black font-mono text-white tracking-widest">{scan.metrics?.crawl?.pages_crawled || 0}</span>
                  <span className="text-[10px] text-primary/60 font-black uppercase">Nodes</span>
                </div>
              </div>
              
              <div className="bg-black/40 p-5 rounded-2xl border border-white/5 hover:border-accent/20 transition-all group">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-[9px] uppercase font-black text-muted-foreground tracking-widest">Active Payload Delivery</span>
                  <Zap size={10} className="text-accent animate-bounce"/>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-4xl font-black font-mono text-white tracking-widest">{scan.metrics?.detection?.total_requests_sent || 0}</span>
                  <span className="text-[10px] text-accent/60 font-black uppercase">Units</span>
                </div>
              </div>
            </div>

            <div className="space-y-4 pt-4 border-t border-white/5">
              <div className="flex justify-between items-center px-2">
                <div className="flex items-center gap-3 text-muted-foreground">
                  <Cpu size={14} className="text-primary/40"/>
                  <span className="text-[10px] font-black uppercase tracking-widest">Neural Link</span>
                </div>
                <span className="font-mono text-[10px] font-black text-white px-2 py-0.5 rounded bg-primary/10 border border-primary/20">ESTABLISHED</span>
              </div>
              <div className="flex justify-between items-center px-2">
                <div className="flex items-center gap-3 text-muted-foreground">
                  <Globe size={14} className="text-primary/40"/>
                  <span className="text-[10px] font-black uppercase tracking-widest">Node Latency</span>
                </div>
                <span className="font-mono text-[10px] font-black text-white bg-muted/50 px-2 py-0.5 rounded border border-white/5 italic">
                  {Math.round(scan.metrics?.performance?.avg_response_time_ms || 120)}ms
                </span>
              </div>
            </div>
          </div>

          {/* Data Intelligence Extraction */}
          <div className="glass p-8 rounded-3xl border-border/40 space-y-6 relative overflow-hidden">
            <div className="absolute bottom-0 left-0 w-24 h-24 bg-accent/5 blur-3xl rounded-full"></div>
            
            <h3 className="text-[10px] font-black uppercase tracking-[0.3em] text-accent/60 flex items-center gap-3 border-b border-white/5 pb-6">
              <Download size={18} className="text-accent"/> Data Intelligence
            </h3>
            
            <div className="space-y-3">
              {/* PDF & CSV (Available on Completion) */}
              {(scan.status === 'complete' || scan.status === 'failed' || scan.status === 'cancelled') ? (
                <>
                  <a 
                    href={id === 'live' ? '#' : `/api/v1/scans/${id}/report?format=pdf`} 
                    onClick={(e) => { 
                      if(id === 'live') { e.preventDefault(); handleDownloadJSON(e); } 
                      else VulnScoutSounds.play('exportBlip'); 
                    }}
                    className="w-full group flex items-center justify-between gap-4 bg-primary text-white font-black text-[10px] px-6 py-4 rounded-xl hover:translate-y-[-2px] hover:shadow-[0_10px_20px_rgba(59,130,246,0.3)] active:scale-95 transition-all neon-blue uppercase tracking-[0.2em]"
                  >
                    <span className="flex items-center gap-3">
                      <FileText size={16} className="group-hover:animate-bounce"/> 
                      Export Tactical PDF
                    </span>
                    <div className="w-1.5 h-1.5 rounded-full bg-white animate-pulse"></div>
                  </a>
                  
                  <a 
                    href={id === 'live' ? '#' : `/api/v1/scans/${id}/export/csv`} 
                    onClick={handleDownloadCSV}
                    className="w-full group flex items-center justify-between gap-4 bg-white/5 text-white/80 hover:bg-white/10 border border-white/10 font-black text-[10px] px-6 py-4 rounded-xl transition-all uppercase tracking-[0.2em]"
                  >
                    <span className="flex items-center gap-3">
                      <Activity size={16}/> 
                      Findings Matrix (CSV)
                    </span>
                  </a>
                </>
              ) : (
                <div className="py-6 px-4 rounded-xl bg-white/5 border border-dashed border-white/10 text-center">
                   <p className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest leading-relaxed">
                      Tactical PDF & CSV reports will be generated upon sequence finalization.
                   </p>
                </div>
              )}

              {/* Always Available Tools */}
              <div className="h-px bg-white/5 my-2"></div>
              
              <a 
                href={id === 'live' ? '#' : `/api/v1/scans/${id}/export/logs`} 
                onClick={handleDownloadLogs}
                className="w-full group flex items-center justify-between gap-4 bg-secondary/30 text-primary hover:bg-primary/20 border border-primary/20 hover:border-primary/40 font-black text-[10px] px-6 py-4 rounded-xl transition-all uppercase tracking-[0.2em]"
              >
                <span className="flex items-center gap-3">
                  <Terminal size={16}/> 
                  Live Audit Logs (TXT)
                </span>
                <div className="flex gap-1">
                   {[1,2,3].map(i => <div key={i} className="w-0.5 h-2 bg-primary/40 animate-pulse" />)}
                </div>
              </a>

              <a 
                href={id === 'live' ? '#' : `/api/v1/scans/${id}/report?format=json`} 
                onClick={handleDownloadJSON}
                className="w-full group flex items-center justify-between gap-4 bg-black/40 text-muted-foreground hover:bg-black/60 border border-white/5 font-black text-[9px] px-6 py-3 rounded-xl transition-all uppercase tracking-[0.2em]"
              >
                <span className="flex items-center gap-3 italic">
                  <Zap size={14}/> 
                  Raw Intelligence (JSON)
                </span>
              </a>
            </div>
          </div>
        </div>

      </div>
    </motion.div>
  );
};

export default ScanDetail;

