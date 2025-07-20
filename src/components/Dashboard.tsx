import React, { useState, useEffect } from 'react';
import { Activity, Shield, Target, Database, AlertTriangle, CheckCircle, Users, Clock, TrendingUp, Zap } from 'lucide-react';

const Dashboard = () => {
  const [stats, setStats] = useState({
    activeSessions: 3,
    exploitsAvailable: 1247,
    targetsIdentified: 42,
    payloadsGenerated: 18,
    vulnerabilitiesFound: 8,
    successfulExploits: 5
  });

  const [recentActivities, setRecentActivities] = useState([
    { time: '14:32:15', action: 'New session established', target: '192.168.1.105', status: 'success' },
    { time: '14:28:42', action: 'CVE-2021-44228 exploit executed', target: '10.0.0.50', status: 'success' },
    { time: '14:25:18', action: 'Port scan completed', target: '192.168.1.0/24', status: 'info' },
    { time: '14:22:03', action: 'Payload encoded successfully', target: 'windows/x64/meterpreter', status: 'success' },
    { time: '14:18:56', action: 'Vulnerability scan failed', target: '10.0.0.75', status: 'error' },
  ]);

  const [vulnerabilities, setVulnerabilities] = useState([
    { cve: 'CVE-2023-23397', severity: 'Critical', target: '192.168.1.105', status: 'Exploitable', confidence: 95 },
    { cve: 'CVE-2022-26134', severity: 'Critical', target: '10.0.0.50', status: 'Exploited', confidence: 98 },
    { cve: 'CVE-2021-44228', severity: 'Critical', target: '10.0.0.75', status: 'Patched', confidence: 90 },
    { cve: 'CVE-2023-21608', severity: 'High', target: '192.168.1.120', status: 'Exploitable', confidence: 85 },
  ]);

  const [activeSessions, setActiveSessions] = useState([
    { id: 'sess_001', type: 'meterpreter', target: '192.168.1.105', user: 'SYSTEM', os: 'Windows 10', established: '2 hours ago' },
    { id: 'sess_002', type: 'shell', target: '10.0.0.50', user: 'www-data', os: 'Ubuntu 20.04', established: '45 minutes ago' },
    { id: 'sess_003', type: 'shell', target: '192.168.1.120', user: 'root', os: 'CentOS 7', established: '12 minutes ago' },
  ]);

  useEffect(() => {
    // Simulate real-time updates
    const interval = setInterval(() => {
      setStats(prev => ({
        ...prev,
        activeSessions: prev.activeSessions + Math.floor(Math.random() * 2) - Math.floor(Math.random() * 2),
        targetsIdentified: prev.targetsIdentified + Math.floor(Math.random() * 3),
      }));
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status) => {
    switch (status) {
      case 'success': return 'text-green-400';
      case 'error': return 'text-red-400';
      case 'info': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'text-red-400 bg-red-500/20';
      case 'High': return 'text-orange-400 bg-orange-500/20';
      case 'Medium': return 'text-yellow-400 bg-yellow-500/20';
      case 'Low': return 'text-green-400 bg-green-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getVulnStatusColor = (status) => {
    switch (status) {
      case 'Exploitable': return 'text-red-400';
      case 'Exploited': return 'text-green-400';
      case 'Patched': return 'text-gray-400';
      default: return 'text-yellow-400';
    }
  };

  const statCards = [
    { label: 'Active Sessions', value: stats.activeSessions, icon: Activity, color: 'text-green-400', bg: 'bg-green-500/20' },
    { label: 'Exploits Available', value: stats.exploitsAvailable, icon: Shield, color: 'text-blue-400', bg: 'bg-blue-500/20' },
    { label: 'Targets Identified', value: stats.targetsIdentified, icon: Target, color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
    { label: 'Payloads Generated', value: stats.payloadsGenerated, icon: Database, color: 'text-purple-400', bg: 'bg-purple-500/20' },
    { label: 'Vulnerabilities Found', value: stats.vulnerabilitiesFound, icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-500/20' },
    { label: 'Successful Exploits', value: stats.successfulExploits, icon: Zap, color: 'text-orange-400', bg: 'bg-orange-500/20' },
  ];

  return (
    <div className="p-6 space-y-6 h-full overflow-auto">
      {/* Header */}
      <div className="border-b border-gray-700 pb-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-green-400">Dashboard</h1>
            <p className="text-gray-400 mt-1">Real-time overview of your penetration testing activities</p>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-right">
              <div className="text-sm text-gray-400">Last Update</div>
              <div className="text-green-400 font-mono">{new Date().toLocaleTimeString()}</div>
            </div>
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {statCards.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div
              key={index}
              className="bg-gray-800 border border-gray-700 rounded-lg p-6 hover:border-green-500/50 transition-all duration-200"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm font-medium">{stat.label}</p>
                  <p className={`text-2xl font-bold ${stat.color} mt-1`}>
                    {typeof stat.value === 'number' ? stat.value.toLocaleString() : stat.value}
                  </p>
                </div>
                <div className={`p-3 rounded-lg ${stat.bg}`}>
                  <Icon className={`w-6 h-6 ${stat.color}`} />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Recent Activities */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg">
          <div className="p-6 border-b border-gray-700">
            <div className="flex items-center space-x-2">
              <Clock className="w-5 h-5 text-green-400" />
              <h2 className="text-lg font-semibold text-green-400">Recent Activities</h2>
            </div>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {recentActivities.map((activity, index) => (
                <div key={index} className="flex items-start space-x-3 p-3 rounded-lg bg-gray-900/50 hover:bg-gray-900 transition-colors">
                  <div className="flex-shrink-0">
                    <div className={`w-2 h-2 rounded-full mt-2 ${
                      activity.status === 'success' ? 'bg-green-400' :
                      activity.status === 'error' ? 'bg-red-400' : 'bg-blue-400'
                    }`}></div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <p className="text-sm text-gray-300">{activity.action}</p>
                      <span className="text-xs text-gray-500 font-mono">{activity.time}</span>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">Target: {activity.target}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Critical Vulnerabilities */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg">
          <div className="p-6 border-b border-gray-700">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <h2 className="text-lg font-semibold text-red-400">Critical Vulnerabilities</h2>
              </div>
              <span className="text-xs text-gray-400 bg-gray-700 px-2 py-1 rounded">
                {vulnerabilities.filter(v => v.severity === 'Critical').length} Critical
              </span>
            </div>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {vulnerabilities.map((vuln, index) => (
                <div key={index} className="p-4 rounded-lg bg-gray-900/50 border border-gray-700 hover:border-gray-600 transition-colors">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-sm text-blue-400">{vuln.cve}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-gray-300">{vuln.target}</p>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className={`text-xs ${getVulnStatusColor(vuln.status)}`}>
                          {vuln.status}
                        </span>
                        <span className="text-xs text-gray-500">
                          {vuln.confidence}% confidence
                        </span>
                      </div>
                    </div>
                    {vuln.status === 'Exploitable' && (
                      <button className="text-xs bg-red-500/20 text-red-400 px-3 py-1 rounded hover:bg-red-500/30 transition-colors">
                        Exploit
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Active Sessions */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg">
        <div className="p-6 border-b border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Users className="w-5 h-5 text-green-400" />
              <h2 className="text-lg font-semibold text-green-400">Active Sessions</h2>
            </div>
            <span className="text-xs text-gray-400 bg-gray-700 px-2 py-1 rounded">
              {activeSessions.length} Active
            </span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left p-4 text-sm font-medium text-gray-400">Session ID</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Type</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Target</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">User</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">OS</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Established</th>
                <th className="text-left p-4 text-sm font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {activeSessions.map((session, index) => (
                <tr key={index} className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors">
                  <td className="p-4">
                    <span className="font-mono text-sm text-blue-400">{session.id}</span>
                  </td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      session.type === 'meterpreter' ? 'bg-purple-500/20 text-purple-400' : 'bg-green-500/20 text-green-400'
                    }`}>
                      {session.type}
                    </span>
                  </td>
                  <td className="p-4 text-sm text-gray-300">{session.target}</td>
                  <td className="p-4 text-sm text-yellow-400">{session.user}</td>
                  <td className="p-4 text-sm text-gray-300">{session.os}</td>
                  <td className="p-4 text-sm text-gray-400">{session.established}</td>
                  <td className="p-4">
                    <button className="text-xs bg-green-500/20 text-green-400 px-3 py-1 rounded hover:bg-green-500/30 transition-colors">
                      Interact
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;