import React, { useState, useEffect } from 'react';
import { Shield, Terminal as TerminalIcon, Target, Database, Settings, Activity, Users, FileText } from 'lucide-react';
import Settings from './components/Settings';
import Dashboard from './components/Dashboard';
import ExploitManager from './components/ExploitManager';
import PayloadBuilder from './components/PayloadBuilder';
import SessionManager from './components/SessionManager';
import Scanner from './components/Scanner';
import Terminal from './components/Terminal';

function App() {
  const [activeModule, setActiveModule] = useState('dashboard');
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Simulate WebSocket connection
    setTimeout(() => setIsConnected(true), 1000);
  }, []);

  const modules = [
    { id: 'dashboard', name: 'Dashboard', icon: Activity },
    { id: 'scanner', name: 'Scanner', icon: Target },
    { id: 'exploits', name: 'Exploits', icon: Shield },
    { id: 'payloads', name: 'Payloads', icon: Database },
    { id: 'sessions', name: 'Sessions', icon: Users },
    { id: 'terminal', name: 'Terminal', icon: TerminalIcon },
    { id: 'reports', name: 'Reports', icon: FileText },
    { id: 'settings', name: 'Settings', icon: Settings },
  ];

  const renderActiveModule = () => {
    switch (activeModule) {
      case 'dashboard':
        return <Dashboard />;
      case 'scanner':
        return <Scanner />;
      case 'exploits':
        return <ExploitManager />;
      case 'payloads':
        return <PayloadBuilder />;
      case 'sessions':
        return <SessionManager />;
      case 'terminal':
        return <Terminal />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-green-400 font-mono">
      {/* Header */}
      <header className="bg-gray-800 border-b border-green-500/30 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-green-400" />
            <div>
              <h1 className="text-xl font-bold text-green-400">CypherFramework</h1>
              <p className="text-xs text-gray-400">Professional Penetration Testing Platform</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}></div>
              <span className="text-xs text-gray-400">
                {isConnected ? 'Connected' : 'Connecting...'}
              </span>
            </div>
            <div className="text-xs text-gray-400">
              v1.0.0 | {new Date().toLocaleTimeString()}
            </div>
          </div>
        </div>
      </header>

      <div className="flex h-[calc(100vh-80px)]">
        {/* Sidebar */}
        <nav className="w-64 bg-gray-800 border-r border-green-500/30 p-4">
          <div className="space-y-2">
            {modules.map((module) => {
              const Icon = module.icon;
              return (
                <button
                  key={module.id}
                  onClick={() => setActiveModule(module.id)}
                  className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200 ${
                    activeModule === module.id
                      ? 'bg-green-500/20 text-green-400 border border-green-500/40'
                      : 'text-gray-400 hover:bg-gray-700 hover:text-green-400'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{module.name}</span>
                </button>
              );
            })}
          </div>

          {/* Quick Stats */}
          <div className="mt-8 p-4 bg-gray-900 rounded-lg border border-gray-700">
            <h3 className="text-sm font-bold text-green-400 mb-3">Quick Stats</h3>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-400">Active Sessions:</span>
                <span className="text-green-400">3</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Available Exploits:</span>
                <span className="text-green-400">1,247</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Targets Scanned:</span>
                <span className="text-green-400">42</span>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1 overflow-auto">
          {renderActiveModule()}
        </main>
      </div>
    </div>
  );
}

export default App;