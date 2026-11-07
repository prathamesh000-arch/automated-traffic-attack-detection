import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip,
  CartesianGrid, AreaChart, Area
} from 'recharts';
import { ShieldCheck, Activity, Users, Gauge, AlertTriangle, Ban, RefreshCw } from 'lucide-react';

const API = 'http://127.0.0.1:5000';
const socket = io(API, { transports: ['websocket', 'polling'] });

export default function Dashboard() {
  const [live, setLive] = useState(null);
  const [history, setHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [token, setToken] = useState('');
  const [ip, setIp] = useState('');
  const [blocked, setBlocked] = useState([]);
  const [message, setMessage] = useState('Connecting to monitoring service…');

  useEffect(() => {
    fetch(`${API}/api/traffic/current`).then(r=>r.json()).then(setLive).catch(()=>setMessage('Backend not connected'));
    fetch(`${API}/api/alerts`).then(r=>r.json()).then(setAlerts).catch(()=>{});
    socket.on('connect', () => setMessage('Live monitoring connected'));
    socket.on('disconnect', () => setMessage('Live connection disconnected'));
    socket.on('traffic', d => {
      setLive(d);
      setHistory(old => [...old, {
        time: new Date(d.timestamp).toLocaleTimeString(),
        rps: Number(d.requests_per_sec.toFixed(2)),
        ips: d.unique_ips,
        bytes: Number(d.bytes_per_sec.toFixed(0))
      }].slice(-60));
    });
    socket.on('alert', a => setAlerts(old => [a, ...old].slice(0, 50)));
    return () => { socket.off('traffic'); socket.off('alert'); socket.off('connect'); socket.off('disconnect'); };
  }, []);

  async function admin(path, body) {
    setMessage('Sending administrator request…');
    try {
      const res = await fetch(`${API}/api/admin/${path}`, {
        method: path === 'blocked' ? 'GET' : 'POST',
        headers: {'Content-Type':'application/json', 'X-Admin-Token':token},
        body: path === 'blocked' ? undefined : JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Request failed');
      setMessage(JSON.stringify(data));
      if (path === 'block' || path === 'unblock' || path === 'blocked') {
        const r = await fetch(`${API}/api/admin/blocked`, {headers:{'X-Admin-Token':token}});
        if (r.ok) setBlocked(await r.json());
      }
    } catch (e) { setMessage(e.message); }
  }

  const cls = live?.classification || 'Waiting';
  const clsClass = cls === 'DDoS' ? 'danger' : cls === 'Flash Crowd' ? 'warn' : 'safe';
  return <div className="shell">
    <header>
      <div className="brand"><div className="logo"><ShieldCheck/></div><div><h1>TrafficGuard</h1><p>Automated DDoS & Flash Crowd Monitoring</p></div></div>
      <div className="live"><span className="dot"/> {message}</div>
    </header>
    <main>
      <section className="hero">
        <div><span className="eyebrow">REAL-TIME SECURITY MONITOR</span><h2>Web Traffic Overview</h2><p>Observe traffic patterns, classification and mitigation events.</p></div>
        <div className={`status ${clsClass}`}><span className="status-dot"/>{cls}</div>
      </section>
      <section className="metrics">
        <Metric icon={<Activity/>} label="Requests / sec" value={live?.requests_per_sec?.toFixed?.(1) ?? '—'}/>
        <Metric icon={<Users/>} label="Unique source IPs" value={live?.unique_ips ?? '—'}/>
        <Metric icon={<Gauge/>} label="Bytes / sec" value={live?.bytes_per_sec ? Math.round(live.bytes_per_sec).toLocaleString() : '—'}/>
        <Metric icon={<AlertTriangle/>} label="HTTP error rate" value={live?.error_rate != null ? `${(live.error_rate*100).toFixed(1)}%` : '—'}/>
      </section>
      <section className="charts">
        <div className="panel"><div className="panel-head"><div><h3>Request rate</h3><p>Live requests per second · latest 60 updates</p></div><Activity/></div>
          <div className="chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={history}><defs><linearGradient id="fillRps" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#4f8cff" stopOpacity={0.28}/><stop offset="100%" stopColor="#4f8cff" stopOpacity={0}/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" stroke="#202d42"/><XAxis dataKey="time" tick={{fill:'#8291a8',fontSize:11}}/><YAxis tick={{fill:'#8291a8',fontSize:11}}/><Tooltip contentStyle={{background:'#111c2e',border:'1px solid #2a3a54',borderRadius:10}}/><Area type="monotone" dataKey="rps" stroke="#4f8cff" fill="url(#fillRps)" strokeWidth={2}/></AreaChart></ResponsiveContainer></div>
        </div>
        <div className="panel"><div className="panel-head"><div><h3>Traffic volume</h3><p>Observed request bytes per second</p></div><Activity/></div>
          <div className="chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={history}><CartesianGrid strokeDasharray="3 3" stroke="#202d42"/><XAxis dataKey="time" tick={{fill:'#8291a8',fontSize:11}}/><YAxis tick={{fill:'#8291a8',fontSize:11}}/><Tooltip contentStyle={{background:'#111c2e',border:'1px solid #2a3a54',borderRadius:10}}/><Line type="monotone" dataKey="bytes" stroke="#28c7a3" strokeWidth={2} dot={false}/></LineChart></ResponsiveContainer></div>
        </div>
      </section>
      <section className="lower">
        <div className="panel"><div className="panel-head"><div><h3>Detection result</h3><p>Latest traffic-window analysis</p></div><ShieldCheck/></div>
          <div className="result"><div className={`result-icon ${clsClass}`}><ShieldCheck/></div><div><strong>{cls}</strong><p>Model confidence: {live?.confidence ? `${(live.confidence*100).toFixed(1)}%` : 'Not available'}</p></div></div>
          <div className="detail-grid"><span>Average inter-request interval</span><b>{live?.avg_inter_request_ms?.toFixed?.(1) ?? '—'} ms</b><span>Requests in current window</span><b>{live?.total_requests ?? '—'}</b><span>Recommended action</span><b>{cls === 'DDoS' ? 'Temporary source block (if high-rate)' : cls === 'Flash Crowd' ? 'Gentle per-IP rate limit' : 'Allow traffic'}</b></div>
          <p className="note">Flash Crowd is a heuristic indicator in this version, not a class learned from CIC-DDoS2019.</p>
        </div>
        <div className="panel"><div className="panel-head"><div><h3>Detection alerts</h3><p>Recent security events</p></div><AlertTriangle/></div>
          <div className="alerts">{alerts.length ? alerts.slice(0,8).map(a=><div className="alert-row" key={a.id}><span className={`alert-mark ${a.severity}`}/><div><b>{a.type.replaceAll('_',' ')}</b><p>{a.message}</p><small>{new Date(a.time).toLocaleTimeString()}</small></div></div>) : <p className="empty">No alerts yet. Traffic events will appear here.</p>}</div>
        </div>
      </section>
      <section className="panel admin"><div className="panel-head"><div><h3>Administrator controls</h3><p>Token-protected temporary IP blocking</p></div><Ban/></div>
        <div className="admin-form"><input type="password" placeholder="Admin token" value={token} onChange={e=>setToken(e.target.value)}/><input placeholder="IPv4 / IPv6 address" value={ip} onChange={e=>setIp(e.target.value)}/><button onClick={()=>admin('block',{ip,seconds:300})}>Block for 5 min</button><button className="secondary" onClick={()=>admin('unblock',{ip})}>Unblock</button><button className="secondary" onClick={()=>admin('blocked')}>Refresh list <RefreshCw size={14}/></button></div>
        <p className="admin-message">{message}</p>
        <div className="blocked-list">{blocked.map(b=><span key={b.ip}>{b.ip} · {b.expires_in}s left</span>)}</div>
      </section>
      <footer>Prototype for controlled local testing. Do not expose directly to the public internet.</footer>
    </main>
  </div>;
}

function Metric({icon,label,value}) {
  return <div className="metric"><div className="metric-icon">{icon}</div><div><p>{label}</p><strong>{value}</strong></div></div>;
}
