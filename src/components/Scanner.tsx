import React, { useState, useEffect } from 'react';
import { Target, Play, Pause, RotateCcw, Search, Filter, AlertTriangle, CheckCircle, Clock, Zap } from 'lucide-react';

const Scanner = () => {
  const [scanConfig, setScanConfig] = useState({
    targets: '192.168.1.0/24',
    ports: '22,80,443,445,3389',
    scanType: 'tcp_syn',
    threads: 100,
    timeout: 1000,
    aggressive: false,
    serviceDetection: true,
    osDetection: false,
    scriptScanning: false
  });

  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState([]);
  const [discoveries, setDiscoveries] = useState([
    {
      ip: '192.168.1.105',
      hostname: 'WIN-DESKTOP01',
      status: 'up',
      os: 'Windows 10',
      ports: [
        { port: 445, service: 'microsoft-ds', state: 'open', version: 'Microsoft Windows 10 SMB' },
        { port: 3389, service: 'ms-wbt-server', state: 'open', version: 'Microsoft Terminal Services' },
        { port: 135, service: 'msrpc', state: 'open', version: 'Microsoft Windows RPC' }
      ],
      vulnerabilities: ['CVE-2017-0144', 'CVE-2019-0708'],
      scanTime: new Date(Date.now() - 3600000)
    },
    {
      ip: '10.0.0.50',
      hostname: 'web-server',
      status: 'up',
      os: 'Linux (Ubuntu)',
      ports: [
        { port: 22, service: 'ssh', state: 'open', version: 'OpenSSH 8.2' },
        { port: 80, service: 'http', state: 'open', version: 'Apache httpd 2.4.41' },
        { port: 443, service: 'https', state: 'open', version: 'Apache httpd 2.4.41' }
      ],
      vulnerabilities: ['CVE-2021-44228'],
      scanTime: new Date(Date.now() - 1800000)
    },
    {
      ip: '192.168.1.120',
      hostname: 'db-server',
      status: 'up',
      os: 'Linux (CentOS)',
      ports: [
        { port: 22, service: 'ssh', state: 'open', version: 'OpenSSH 7.4' },
        { port: 3306, service: 'mysql', state: 'open', version: 'MySQL 5.7.37' }
      ],
      vulnerabilities: [],
      scanTime: new Date(Date.now() - 900000)
    }
  ]);

  const [selectedTarget, setSelectedTarget] = useState(null);
  const [activeTab, setActiveTab] = useState('results');

  const scanTypes = [
    { value: 'tcp_syn', label: 'TCP SYN Scan', description: 'Fast stealth scan' },
    { value: 'tcp_connect', label: 'TCP Connect Scan', description: 'Full connection scan' },
    { value: 'udp', label: 'UDP Scan', description: 'UDP port scan' },
    { value: 'comprehensive', label: 'Comprehensive', description: 'All scan types' }
  ];

  const startScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    setScanResults([]);
    
    // Simulate progressive scanning
    const interval = setInterval(() => {
      setScanProgress(prev => {
        const newProgress = prev + Math.random() * 10;
        if (newProgress >= 100) {
          clearInterval(interval);
          setIsScanning(false);
          
          // Add some mock results
          const mockResults = [
            {
              ip: '192.168.1.201',
              hostname: 'new-target',
              status: 'up',
              os: 'Windows Server 2019',
              ports: [
                { port: 80, service: 'http', state: 'open', version: 'IIS 10.0' },
                { port: 445, service: 'microsoft-ds', state: 'open', version: 'SMBv3' }
              ],
              vulnerabilities: ['CVE-2022-26134'],
              scanTime: new Date()
            }
          ];
          
          setDiscoveries(prev => [...prev, ...mockResults]);
          return 100;
        }
        return newProgress;
      });
    }, 200);
  };

  const stopScan = () => {
    setIsScanning(false);
    setScanProgress(0);
  };

  const getServiceColor = (service) => {
    const colors = {
      'http': 'text-blue-400',
      'https': 'text-green-400',
      'ssh': 'text-purple-400',
      'ftp': 'text-yellow-400',
      'smtp': 'text-orange-400',
      'mysql': 'text-red-400',
      'postgresql': 'text-indigo-400'
    };
    return colors[service] || 'text-gray-400';
  };

  const getVulnerabilityCount = (vulns) => {
    if (!vulns || vulns.length === 0) return { count: 0, color: 'text-green-400' };
    if (vulns.length <= 2) return { count: vulns.length, color: 'text-yellow-400' };
    return { count: vulns.length, color: 'text-red-400' };
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="border-b border-gray-700 pb-4">
        <h1 className="text-2xl font-bold text-green-400">Network Scanner</h1>
        <p className="text-gray-400 mt-1">Discover and enumerate network targets with advanced scanning techniques</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Scan Configuration */}
        <div className="xl:col-span-1 space-y-6">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="flex items-center space-x-2 mb-6">
              <Target className="w-5 h-5 text-green-400" />
              <h2 className="text-lg font-semibold text-green-400">Scan Configuration</h2>
            </div>

            <div className="space-y-4">
              {/* Target Input */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">Target(s)</label>
                <input
                  type="text"
                  value={scanConfig.targets}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, targets: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 font-mono text-sm focus:border-green-500 focus:outline-none"
                  placeholder="192.168.1.0/24, 10.0.0.1-100"
                />
                <p className="text-xs text-gray-500 mt-1">IP ranges, CIDR notation, or comma-separated IPs</p>
              </div>

              {/* Port Range */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">Port Range</label>
                <input
                  type="text"
                  value={scanConfig.ports}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, ports: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 font-mono text-sm focus:border-green-500 focus:outline-none"
                  placeholder="1-65535, 22,80,443"
                />
              </div>

              {/* Scan Type */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">Scan Type</label>
                <select
                  value={scanConfig.scanType}
                  onChange={(e) => setScanConfig(prev => ({ ...prev, scanType: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                >
                  {scanTypes.map((type) => (
                    <option key={type.value} value={type.value}>
                      {type.label} - {type.description}
                    </option>
                  ))}
                </select>
              </div>

              {/* Performance Settings */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Threads</label>
                  <input
                    type="number"
                    value={scanConfig.threads}
                    onChange={(e) => setScanConfig(prev => ({ ...prev, threads: parseInt(e.target.value) }))}
                    min="1"
                    max="1000"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Timeout (ms)</label>
                  <input
                    type="number"
                    value={scanConfig.timeout}
                    onChange={(e) => setScanConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) }))}
                    min="100"
                    max="10000"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                  />
                </div>
              </div>

              {/* Advanced Options */}
              <div className="space-y-3">
                <label className="block text-sm font-medium text-gray-400">Advanced Options</label>
                
                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={scanConfig.serviceDetection}
                    onChange={(e) => setScanConfig(prev => ({ ...prev, serviceDetection: e.target.checked }))}
                    className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
                  />
                  <span className="text-gray-300 text-sm">Service Detection</span>
                </label>

                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={scanConfig.osDetection}
                    onChange={(e) => setScanConfig(prev => ({ ...prev, osDetection: e.target.checked }))}
                    className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
                  />
                  <span className="text-gray-300 text-sm">OS Detection</span>
                </label>

                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={scanConfig.scriptScanning}
                    onChange={(e) => setScanConfig(prev => ({ ...prev, scriptScanning: e.target.checked }))}
                    className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
                  />
                  <span className="text-gray-300 text-sm">Script Scanning</span>
                </label>

                <label className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={scanConfig.aggressive}
                    onChange={(e) => setScanConfig(prev => ({ ...prev, aggressive: e.target.checked }))}
                    className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
                  />
                  <span className="text-gray-300 text-sm">Aggressive Scanning</span>
                </label>
              </div>
            </div>

            {/* Scan Controls */}
            <div className="mt-6 pt-6 border-t border-gray-700">
              {!isScanning ? (
                <button
                  onClick={startScan}
                  className="w-full flex items-center justify-center space-x-2 px-4 py-3 bg-green-500/20 text-green-400 border border-green-500/50 rounded-lg hover:bg-green-500/30 transition-colors"
                >
                  <Play className="w-5 h-5" />
                  <span>Start Scan</span>
                </button>
              ) : (
                <div className="space-y-3">
                  <div className="w-full bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-green-400 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${scanProgress}%` }}
                    ></div>
                  </div>
                  <div className="flex justify-between text-sm text-gray-400">
                    <span>Scanning... {Math.round(scanProgress)}%</span>
                    <button
                      onClick={stopScan}
                      className="text-red-400 hover:text-red-300"
                    >
                      Stop
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Quick Stats */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-green-400 mb-4">Scan Statistics</h3>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-400">Hosts Discovered:</span>
                <span className="text-green-400 font-semibold">{discoveries.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Open Ports:</span>
                <span className="text-blue-400 font-semibold">
                  {discoveries.reduce((total, host) => total + host.ports.length, 0)}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Vulnerabilities:</span>
                <span className="text-red-400 font-semibold">
                  {discoveries.reduce((total, host) => total + (host.vulnerabilities?.length || 0), 0)}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Last Scan:</span>
                <span className="text-gray-300 text-sm">
                  {discoveries.length > 0 ? 'Just now' : 'Never'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Results Panel */}
        <div className="xl:col-span-2">
          <div className="bg-gray-800 border border-gray-700 rounded-lg h-[calc(100vh-250px)]">
            {/* Results Header */}
            <div className="p-6 border-b border-gray-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Search className="w-5 h-5 text-blue-400" />
                  <h2 className="text-lg font-semibold text-blue-400">Scan Results</h2>
                </div>
                <div className="flex items-center space-x-2">
                  <button className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded">
                    <Filter className="w-4 h-4" />
                  </button>
                  <button className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded">
                    <RotateCcw className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>

            {/* Results Content */}
            <div className="flex-1 overflow-auto">
              {discoveries.length > 0 ? (
                <div className="p-6 space-y-4">
                  {discoveries.map((host, index) => {
                    const vulnInfo = getVulnerabilityCount(host.vulnerabilities);
                    
                    return (
                      <div
                        key={index}
                        className="bg-gray-900 border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition-colors"
                      >
                        {/* Host Header */}
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center space-x-3">
                            <div className="w-3 h-3 bg-green-400 rounded-full"></div>
                            <div>
                              <h3 className="font-semibold text-green-400">{host.ip}</h3>
                              <p className="text-sm text-gray-400">{host.hostname} • {host.os}</p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className={`text-sm ${vulnInfo.color}`}>
                              {vulnInfo.count} vulnerabilities
                            </span>
                            <Clock className="w-4 h-4 text-gray-500" />
                            <span className="text-xs text-gray-500">
                              {host.scanTime.toLocaleTimeString()}
                            </span>
                          </div>
                        </div>

                        {/* Ports */}
                        <div className="mb-3">
                          <h4 className="text-sm font-medium text-gray-400 mb-2">Open Ports</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {host.ports.map((port, portIndex) => (
                              <div
                                key={portIndex}
                                className="flex items-center justify-between p-2 bg-gray-800 rounded border border-gray-600"
                              >
                                <div className="flex items-center space-x-2">
                                  <span className="font-mono text-sm text-blue-400">{port.port}</span>
                                  <span className={`text-sm ${getServiceColor(port.service)}`}>
                                    {port.service}
                                  </span>
                                </div>
                                <span className="text-xs text-gray-500">
                                  {port.version?.substring(0, 20)}...
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Vulnerabilities */}
                        {host.vulnerabilities && host.vulnerabilities.length > 0 && (
                          <div>
                            <h4 className="text-sm font-medium text-gray-400 mb-2">Vulnerabilities</h4>
                            <div className="flex flex-wrap gap-2">
                              {host.vulnerabilities.map((cve, cveIndex) => (
                                <span
                                  key={cveIndex}
                                  className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/50 rounded text-xs font-mono"
                                >
                                  {cve}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center">
                    <Target className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-gray-400">No Scan Results</h3>
                    <p className="text-gray-500 mt-2">Configure your scan settings and click "Start Scan"</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Scanner;