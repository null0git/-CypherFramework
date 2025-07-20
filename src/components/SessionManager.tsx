import React, { useState, useEffect } from 'react';
import { Users, Terminal, Activity, Settings, X, Play, Pause, RotateCcw, Download } from 'lucide-react';

const SessionManager = () => {
  const [sessions, setSessions] = useState([
    {
      id: 'sess_001',
      type: 'meterpreter',
      target: '192.168.1.105',
      user: 'SYSTEM',
      os: 'Windows 10 Pro',
      established: new Date(Date.now() - 7200000),
      lastActivity: new Date(Date.now() - 300000),
      status: 'active',
      commands: 147,
      platform: 'windows',
      architecture: 'x64',
      privilege: 'high',
      pid: 1337
    },
    {
      id: 'sess_002',
      type: 'shell',
      target: '10.0.0.50',
      user: 'www-data',
      os: 'Ubuntu 20.04.6 LTS',
      established: new Date(Date.now() - 2700000),
      lastActivity: new Date(Date.now() - 120000),
      status: 'active',
      commands: 89,
      platform: 'linux',
      architecture: 'x64',
      privilege: 'low',
      pid: 2456
    },
    {
      id: 'sess_003',
      type: 'shell',
      target: '192.168.1.120',
      user: 'root',
      os: 'CentOS Linux 7',
      established: new Date(Date.now() - 720000),
      lastActivity: new Date(Date.now() - 60000),
      status: 'active',
      commands: 23,
      platform: 'linux',
      architecture: 'x64',
      privilege: 'high',
      pid: 3789
    },
    {
      id: 'sess_004',
      type: 'meterpreter',
      target: '10.0.0.75',
      user: 'Administrator',
      os: 'Windows Server 2019',
      established: new Date(Date.now() - 1800000),
      lastActivity: new Date(Date.now() - 1200000),
      status: 'stale',
      commands: 56,
      platform: 'windows',
      architecture: 'x64',
      privilege: 'high',
      pid: 4512
    }
  ]);

  const [selectedSession, setSelectedSession] = useState(null);
  const [terminalInput, setTerminalInput] = useState('');
  const [terminalHistory, setTerminalHistory] = useState([]);
  const [isExecuting, setIsExecuting] = useState(false);

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'text-green-400 bg-green-500/20';
      case 'stale': return 'text-yellow-400 bg-yellow-500/20';
      case 'dead': return 'text-red-400 bg-red-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getTypeColor = (type) => {
    switch (type) {
      case 'meterpreter': return 'text-purple-400 bg-purple-500/20';
      case 'shell': return 'text-green-400 bg-green-500/20';
      case 'vnc': return 'text-blue-400 bg-blue-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getPrivilegeColor = (privilege) => {
    switch (privilege) {
      case 'high': return 'text-red-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const formatTimeAgo = (date) => {
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.floor(diffHours / 24)}d ago`;
  };

  const handleSessionSelect = (session) => {
    setSelectedSession(session);
    // Load session history (mock data)
    setTerminalHistory([
      { type: 'output', content: `Session ${session.id} established`, timestamp: session.established },
      { type: 'output', content: `Connected to ${session.target} as ${session.user}`, timestamp: session.established },
      { type: 'command', content: 'sysinfo', timestamp: new Date(session.established.getTime() + 60000) },
      { type: 'output', content: `Computer: ${session.target}\nOS: ${session.os}\nArchitecture: ${session.architecture}`, timestamp: new Date(session.established.getTime() + 61000) }
    ]);
  };

  const executeCommand = async () => {
    if (!terminalInput.trim() || isExecuting) return;
    
    setIsExecuting(true);
    const command = terminalInput.trim();
    const timestamp = new Date();
    
    // Add command to history
    setTerminalHistory(prev => [...prev, { type: 'command', content: command, timestamp }]);
    setTerminalInput('');
    
    // Simulate command execution
    setTimeout(() => {
      let output = '';
      
      // Mock command responses
      switch (command.toLowerCase()) {
        case 'whoami':
          output = selectedSession.user;
          break;
        case 'pwd':
          output = selectedSession.platform === 'windows' ? 'C:\\Windows\\System32' : '/home/user';
          break;
        case 'ls':
        case 'dir':
          output = selectedSession.platform === 'windows' 
            ? 'Desktop\nDocuments\nDownloads\nPictures\nVideos'
            : 'bin  etc  home  usr  var  tmp';
          break;
        case 'ps':
          output = 'PID    PPID   NAME\n1234   1      explorer.exe\n5678   1234   notepad.exe\n9012   1      chrome.exe';
          break;
        case 'netstat':
          output = 'Active connections:\nTCP  0.0.0.0:80     LISTENING\nTCP  0.0.0.0:443    LISTENING\nTCP  192.168.1.1:22 ESTABLISHED';
          break;
        case 'sysinfo':
          output = `Computer: ${selectedSession.target}\nOS: ${selectedSession.os}\nArchitecture: ${selectedSession.architecture}\nUser: ${selectedSession.user}\nPrivileges: ${selectedSession.privilege}`;
          break;
        default:
          output = `Command executed: ${command}`;
      }
      
      setTerminalHistory(prev => [...prev, { type: 'output', content: output, timestamp: new Date() }]);
      
      // Update session's last activity and command count
      setSessions(prev => prev.map(session => 
        session.id === selectedSession.id 
          ? { ...session, lastActivity: new Date(), commands: session.commands + 1 }
          : session
      ));
      
      setIsExecuting(false);
    }, 1000 + Math.random() * 1500);
  };

  const killSession = (sessionId) => {
    setSessions(prev => prev.map(session => 
      session.id === sessionId ? { ...session, status: 'dead' } : session
    ));
    if (selectedSession?.id === sessionId) {
      setSelectedSession(null);
    }
  };

  const refreshSession = (sessionId) => {
    setSessions(prev => prev.map(session => 
      session.id === sessionId 
        ? { ...session, status: 'active', lastActivity: new Date() }
        : session
    ));
  };

  return (
    <div className="p-6 space-y-6 h-full">
      {/* Header */}
      <div className="border-b border-gray-700 pb-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-green-400">Session Manager</h1>
            <p className="text-gray-400 mt-1">Manage and interact with active exploitation sessions</p>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-right">
              <div className="text-sm text-gray-400">Active Sessions</div>
              <div className="text-green-400 font-bold text-xl">
                {sessions.filter(s => s.status === 'active').length}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 h-[calc(100vh-200px)]">
        {/* Sessions List */}
        <div className="xl:col-span-1 bg-gray-800 border border-gray-700 rounded-lg flex flex-col">
          <div className="p-6 border-b border-gray-700">
            <div className="flex items-center space-x-2">
              <Users className="w-5 h-5 text-green-400" />
              <h2 className="text-lg font-semibold text-green-400">Active Sessions</h2>
            </div>
          </div>
          
          <div className="flex-1 overflow-auto">
            <div className="p-4 space-y-3">
              {sessions.map((session) => (
                <div
                  key={session.id}
                  onClick={() => handleSessionSelect(session)}
                  className={`p-4 rounded-lg border transition-all cursor-pointer ${
                    selectedSession?.id === session.id
                      ? 'border-green-500 bg-green-500/10'
                      : 'border-gray-600 bg-gray-900 hover:border-gray-500'
                  }`}
                >
                  {/* Session Header */}
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-sm text-blue-400">{session.id}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getTypeColor(session.type)}`}>
                        {session.type}
                      </span>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(session.status)}`}>
                      {session.status}
                    </span>
                  </div>

                  {/* Session Details */}
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Target:</span>
                      <span className="text-gray-300 font-mono">{session.target}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">User:</span>
                      <span className={`font-medium ${getPrivilegeColor(session.privilege)}`}>
                        {session.user}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">OS:</span>
                      <span className="text-gray-300">{session.os.split(' ').slice(0, 2).join(' ')}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Last Active:</span>
                      <span className="text-gray-300">{formatTimeAgo(session.lastActivity)}</span>
                    </div>
                  </div>

                  {/* Session Actions */}
                  <div className="flex items-center justify-between mt-3 pt-3 border-t border-gray-700">
                    <span className="text-xs text-gray-500">{session.commands} commands</span>
                    <div className="flex space-x-1">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          refreshSession(session.id);
                        }}
                        className="p-1 text-blue-400 hover:bg-blue-500/20 rounded"
                        title="Refresh"
                      >
                        <RotateCcw className="w-3 h-3" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          killSession(session.id);
                        }}
                        className="p-1 text-red-400 hover:bg-red-500/20 rounded"
                        title="Kill Session"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Terminal Interface */}
        <div className="xl:col-span-2 bg-gray-800 border border-gray-700 rounded-lg flex flex-col">
          {selectedSession ? (
            <>
              {/* Terminal Header */}
              <div className="p-4 border-b border-gray-700">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <Terminal className="w-5 h-5 text-green-400" />
                    <div>
                      <h3 className="font-semibold text-green-400">
                        {selectedSession.type} @ {selectedSession.target}
                      </h3>
                      <p className="text-xs text-gray-400">
                        {selectedSession.user} • {selectedSession.os} • {selectedSession.architecture}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(selectedSession.status)}`}>
                      {selectedSession.status}
                    </span>
                    <button className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded">
                      <Settings className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>

              {/* Terminal Output */}
              <div className="flex-1 overflow-auto bg-black p-4 font-mono text-sm">
                <div className="space-y-2">
                  {terminalHistory.map((entry, index) => (
                    <div key={index} className="flex">
                      {entry.type === 'command' ? (
                        <div className="flex w-full">
                          <span className="text-green-400 mr-2">
                            {selectedSession.type}@{selectedSession.target}:~$
                          </span>
                          <span className="text-white">{entry.content}</span>
                        </div>
                      ) : (
                        <div className="text-gray-300 whitespace-pre-wrap">{entry.content}</div>
                      )}
                    </div>
                  ))}
                  {isExecuting && (
                    <div className="flex items-center space-x-2 text-yellow-400">
                      <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
                      <span>Executing command...</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Terminal Input */}
              <div className="border-t border-gray-700 p-4 bg-black">
                <form onSubmit={(e) => { e.preventDefault(); executeCommand(); }} className="flex items-center space-x-2">
                  <span className="text-green-400 font-mono text-sm">
                    {selectedSession.type}@{selectedSession.target}:~$
                  </span>
                  <input
                    type="text"
                    value={terminalInput}
                    onChange={(e) => setTerminalInput(e.target.value)}
                    className="flex-1 bg-transparent text-white font-mono text-sm focus:outline-none"
                    placeholder="Enter command..."
                    disabled={isExecuting}
                  />
                  <button
                    type="submit"
                    disabled={isExecuting || !terminalInput.trim()}
                    className="p-2 text-green-400 hover:bg-green-500/20 rounded disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Play className="w-4 h-4" />
                  </button>
                </form>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <Terminal className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-gray-400">No Session Selected</h3>
                <p className="text-gray-500 mt-2">Select a session from the list to interact with it</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SessionManager;