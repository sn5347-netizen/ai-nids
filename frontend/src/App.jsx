import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Cpu,
  Radio,
  Zap,
  Play,
  Square,
  AlertTriangle,
  RefreshCw,
  Terminal,
  Server,
  Layers,
  ArrowRight,
  Flame
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell
} from 'recharts';

const PROTO_COLORS = {
  TCP: '#3b82f6',
  UDP: '#10b981',
  ICMP: '#f59e0b',
  DNS: '#8b5cf6',
  HTTP: '#06b6d4',
  HTTPS: '#6366f1',
  OTHER: '#64748b'
};

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  LOW: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
};

export default function App() {
  const [connected, setConnected] = useState(false);
  const [metrics, setMetrics] = useState({
    total_packets_analyzed: 0,
    total_alerts: 0,
    active_threat_level: 'NOMINAL',
    average_risk_score: 0,
    attack_breakdown: {},
    protocol_distribution: {},
    recent_alerts: [],
    recent_packets: []
  });

  const [alerts, setAlerts] = useState([]);
  const [packets, setPackets] = useState([]);
  const [snifferRunning, setSnifferRunning] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const wsRef = useRef(null);

  // Connect WebSocket
  useEffect(() => {
    let reconnectTimer;

    function connect() {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${window.location.hostname}:8000/ws/traffic`;

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'INITIAL_METRICS') {
            setMetrics(payload.data);
            if (payload.data.recent_alerts) setAlerts(payload.data.recent_alerts);
            if (payload.data.recent_packets) setPackets(payload.data.recent_packets);
          } else if (payload.type === 'ALERT') {
            setAlerts((prev) => [payload.data, ...prev.slice(0, 49)]);
            fetchStats();
          } else if (payload.type === 'PACKET') {
            setPackets((prev) => [payload.data, ...prev.slice(0, 39)]);
            setMetrics((m) => ({
              ...m,
              total_packets_analyzed: m.total_packets_analyzed + 1
            }));
          }
        } catch (e) {
          console.error('WS error:', e);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        reconnectTimer = setTimeout(connect, 2500);
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    connect();
    fetchStats();
    fetchSnifferStatus();

    const interval = setInterval(fetchStats, 3000);

    return () => {
      clearTimeout(reconnectTimer);
      clearInterval(interval);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const fetchStats = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/stats');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
        if (data.recent_alerts && alerts.length === 0) setAlerts(data.recent_alerts);
      }
    } catch (e) {}
  };

  const fetchSnifferStatus = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/sniffer/status');
      if (res.ok) {
        const data = await res.json();
        setSnifferRunning(data.is_running);
      }
    } catch (e) {}
  };

  const handleSimulate = async (type) => {
    setSimulating(true);
    try {
      await fetch('http://127.0.0.1:8000/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: type })
      });
    } catch (e) {
      console.error(e);
    } finally {
      setTimeout(() => setSimulating(false), 800);
    }
  };

  const toggleSniffer = async () => {
    try {
      const endpoint = snifferRunning ? '/api/sniffer/stop' : '/api/sniffer/start';
      await fetch(`http://127.0.0.1:8000${endpoint}`, { method: 'POST' });
      fetchSnifferStatus();
    } catch (e) {
      console.error(e);
    }
  };

  // Prepare chart data
  const protoChartData = Object.entries(metrics.protocol_distribution || {}).map(([name, value]) => ({
    name,
    value
  }));

  const attackChartData = Object.entries(metrics.attack_breakdown || {}).map(([name, count]) => ({
    name: name.length > 18 ? name.slice(0, 18) + '...' : name,
    count
  }));

  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity === 'ALL') return true;
    return a.severity === filterSeverity;
  });

  const getThreatBadge = (level) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500 animate-pulse';
      case 'ELEVATED':
        return 'bg-orange-500/20 text-orange-400 border-orange-500';
      case 'GUARDED':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500';
      default:
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500';
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-[#0d1322]/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 shadow-lg shadow-cyan-500/20">
            <Radio className="w-6 h-6 text-white animate-spin-slow" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                CyberShield <span className="text-cyan-400 font-mono text-sm uppercase px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800">AI-NIDS</span>
              </h1>
            </div>
            <p className="text-xs text-slate-400">Autonomous Network Intrusion Detection & Threat Scoring System</p>
          </div>
        </div>

        {/* Global Controls & Status */}
        <div className="flex items-center space-x-4">
          {/* Live WebSocket status */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs">
            <span className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-emerald-400 shadow-sm shadow-emerald-400 animate-ping' : 'bg-red-500'}`} />
            <span className="text-slate-300 font-mono">{connected ? 'LIVE TELEMETRY' : 'OFFLINE'}</span>
          </div>

          {/* Threat Level */}
          <div className={`px-3 py-1.5 rounded-lg border text-xs font-bold tracking-wider uppercase flex items-center gap-1.5 ${getThreatBadge(metrics.active_threat_level)}`}>
            <Flame className="w-4 h-4" />
            <span>THREAT: {metrics.active_threat_level}</span>
          </div>

          {/* Sniffer Button */}
          <button
            onClick={toggleSniffer}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all ${
              snifferRunning
                ? 'bg-rose-600/20 border border-rose-500/40 text-rose-300 hover:bg-rose-600/30'
                : 'bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30'
            }`}
          >
            {snifferRunning ? <Square className="w-3.5 h-3.5 fill-current" /> : <Play className="w-3.5 h-3.5 fill-current" />}
            {snifferRunning ? 'Stop Live Sniffer' : 'Start Live Sniffer'}
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 p-6 space-y-6 max-w-7xl mx-auto w-full">
        {/* KPI Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#0f172a]/70 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs uppercase font-medium text-slate-400">Total Packets Inspected</p>
                <h3 className="text-3xl font-bold font-mono text-white mt-1">
                  {metrics.total_packets_analyzed.toLocaleString()}
                </h3>
              </div>
              <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400">
                <Activity className="w-5 h-5" />
              </div>
            </div>
            <div className="mt-3 text-xs text-slate-400 flex items-center gap-1 font-mono">
              <span className="text-emerald-400">● Real-time stream</span>
            </div>
          </div>

          <div className="bg-[#0f172a]/70 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs uppercase font-medium text-slate-400">Threat Alerts Triggered</p>
                <h3 className="text-3xl font-bold font-mono text-rose-400 mt-1">
                  {metrics.total_alerts.toLocaleString()}
                </h3>
              </div>
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400">
                <ShieldAlert className="w-5 h-5" />
              </div>
            </div>
            <div className="mt-3 text-xs text-slate-400 font-mono">
              Threshold: &gt; 55.0 Risk Score
            </div>
          </div>

          <div className="bg-[#0f172a]/70 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs uppercase font-medium text-slate-400">Average Risk Score</p>
                <h3 className="text-3xl font-bold font-mono text-amber-400 mt-1">
                  {metrics.average_risk_score} <span className="text-sm font-normal text-slate-500">/ 100</span>
                </h3>
              </div>
              <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-400">
                <Zap className="w-5 h-5" />
              </div>
            </div>
            <div className="mt-3 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  metrics.average_risk_score > 70 ? 'bg-red-500' : metrics.average_risk_score > 40 ? 'bg-amber-500' : 'bg-emerald-500'
                }`}
                style={{ width: `${Math.min(metrics.average_risk_score, 100)}%` }}
              />
            </div>
          </div>

          <div className="bg-[#0f172a]/70 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs uppercase font-medium text-slate-400">ML Engine Status</p>
                <h3 className="text-xl font-bold text-cyan-400 mt-1">
                  Isolation Forest
                </h3>
              </div>
              <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-cyan-400">
                <Cpu className="w-5 h-5" />
              </div>
            </div>
            <div className="mt-3 text-xs text-slate-400 flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>Unsupervised Outlier Active</span>
            </div>
          </div>
        </div>

        {/* Attack Simulation Test Panel */}
        <div className="bg-gradient-to-r from-slate-900 to-[#0e172a] border border-cyan-900/40 rounded-xl p-5 shadow-lg">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Live Intrusion & Threat Simulator
              </h2>
              <p className="text-xs text-slate-400">
                Trigger attack vectors to evaluate real-time heuristic rules, machine learning detection, and risk scoring.
              </p>
            </div>
            {simulating && (
              <span className="text-xs font-mono text-cyan-400 animate-pulse flex items-center gap-1.5">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Ingesting attack pulses...
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <button
              onClick={() => handleSimulate('port_scan')}
              disabled={simulating}
              className="px-4 py-3 bg-red-950/40 hover:bg-red-900/50 border border-red-800/60 rounded-lg text-left transition group cursor-pointer disabled:opacity-50"
            >
              <div className="text-xs font-bold text-red-300 flex items-center justify-between">
                <span>Port Scan (SYN)</span>
                <span className="text-red-400 group-hover:translate-x-1 transition-transform">→</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Multi-port sequential probe</p>
            </button>

            <button
              onClick={() => handleSimulate('dos')}
              disabled={simulating}
              className="px-4 py-3 bg-orange-950/40 hover:bg-orange-900/50 border border-orange-800/60 rounded-lg text-left transition group cursor-pointer disabled:opacity-50"
            >
              <div className="text-xs font-bold text-orange-300 flex items-center justify-between">
                <span>DoS Flood</span>
                <span className="text-orange-400 group-hover:translate-x-1 transition-transform">→</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">High-rate volumetric burst</p>
            </button>

            <button
              onClick={() => handleSimulate('anomaly')}
              disabled={simulating}
              className="px-4 py-3 bg-purple-950/40 hover:bg-purple-900/50 border border-purple-800/60 rounded-lg text-left transition group cursor-pointer disabled:opacity-50"
            >
              <div className="text-xs font-bold text-purple-300 flex items-center justify-between">
                <span>ML Anomaly</span>
                <span className="text-purple-400 group-hover:translate-x-1 transition-transform">→</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Outlier payload / Flag anomaly</p>
            </button>

            <button
              onClick={() => handleSimulate('normal')}
              disabled={simulating}
              className="px-4 py-3 bg-emerald-950/40 hover:bg-emerald-900/50 border border-emerald-800/60 rounded-lg text-left transition group cursor-pointer disabled:opacity-50"
            >
              <div className="text-xs font-bold text-emerald-300 flex items-center justify-between">
                <span>Normal Traffic</span>
                <span className="text-emerald-400 group-hover:translate-x-1 transition-transform">→</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Legitimate Web & DNS flows</p>
            </button>
          </div>
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Attack Breakdown Chart */}
          <div className="bg-[#0f172a]/70 border border-slate-800 rounded-xl p-5 lg:col-span-2">
            <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Detected Threat Breakdown
            </h3>
            <div className="h-56">
              {attackChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={attackChartData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} angle={-15} textAnchor="end" />
                    <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                    />
                    <Bar dataKey="count" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
                  No active attacks recorded yet. Trigger a simulation above!
                </div>
              )}
            </div>
          </div>

          {/* Protocol Distribution */}
          <div className="bg-[#0f172a]/70 border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Protocol Distribution
            </h3>
            <div className="h-56 flex flex-col items-center justify-center">
              {protoChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={protoChartData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={75}
                      paddingAngle={3}
                    >
                      {protoChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PROTO_COLORS[entry.name] || '#64748b'} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-xs text-slate-500 font-mono">Waiting for packet flows...</p>
              )}
            </div>
          </div>
        </div>

        {/* Live Alerts Feed Table */}
        <div className="bg-[#0f172a]/70 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex flex-wrap justify-between items-center gap-3">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-semibold text-white">Live Threat Detection Feed</h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 font-mono">
                {filteredAlerts.length} Events
              </span>
            </div>

            {/* Filter Buttons */}
            <div className="flex items-center space-x-1.5 text-xs">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-2.5 py-1 rounded-md transition ${
                    filterSeverity === sev ? 'bg-cyan-600 text-white font-semibold' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto max-h-80 overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 sticky top-0 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Timestamp</th>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">Threat Type</th>
                  <th className="py-2.5 px-4">Risk Score</th>
                  <th className="py-2.5 px-4">Source IP</th>
                  <th className="py-2.5 px-4">Destination</th>
                  <th className="py-2.5 px-4">Forensic Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredAlerts.length > 0 ? (
                  filteredAlerts.map((alert, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/40 transition">
                      <td className="py-2.5 px-4 text-slate-400">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${SEVERITY_COLORS[alert.severity] || 'text-slate-400'}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-semibold text-rose-300">{alert.attack_type}</td>
                      <td className="py-2.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-white">{alert.risk_score}</span>
                          <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h-full ${alert.risk_score > 75 ? 'bg-red-500' : 'bg-amber-500'}`}
                              style={{ width: `${alert.risk_score}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 px-4 text-cyan-300">{alert.src_ip}</td>
                      <td className="py-2.5 px-4 text-slate-300">
                        {alert.dst_ip}:{alert.dst_port}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 max-w-xs truncate">{alert.details}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="py-6 text-center text-slate-500">
                      No security alerts matching current filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Live Network Packet Inspector */}
        <div className="bg-[#0f172a]/70 border border-slate-800 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex justify-between items-center">
            <div className="flex items-center space-x-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Live Packet Inspection Stream</h3>
            </div>
            <span className="text-[11px] font-mono text-emerald-400 animate-pulse">● Ingesting Packets</span>
          </div>

          <div className="overflow-x-auto max-h-64 overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 sticky top-0 border-b border-slate-800">
                <tr>
                  <th className="py-2 px-4">Protocol</th>
                  <th className="py-2 px-4">Source IP : Port</th>
                  <th className="py-2 px-4">Destination IP : Port</th>
                  <th className="py-2 px-4">Length</th>
                  <th className="py-2 px-4">TCP Flags</th>
                  <th className="py-2 px-4">Risk</th>
                  <th className="py-2 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {packets.slice(0, 15).map((pkt, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="py-2 px-4">
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] font-bold"
                        style={{
                          backgroundColor: `${PROTO_COLORS[pkt.protocol] || '#64748b'}25`,
                          color: PROTO_COLORS[pkt.protocol] || '#64748b'
                        }}
                      >
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-4 text-slate-300">
                      {pkt.src_ip}{pkt.src_port ? `:${pkt.src_port}` : ''}
                    </td>
                    <td className="py-2 px-4 text-slate-300">
                      {pkt.dst_ip}{pkt.dst_port ? `:${pkt.dst_port}` : ''}
                    </td>
                    <td className="py-2 px-4 text-slate-400">{pkt.length} B</td>
                    <td className="py-2 px-4 text-slate-400">{pkt.tcp_flags || '-'}</td>
                    <td className="py-2 px-4 font-semibold text-white">{pkt.risk_score}</td>
                    <td className="py-2 px-4">
                      {pkt.is_anomaly ? (
                        <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 text-[10px] font-bold">
                          ANOMALY
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px]">
                          CLEAN
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}
