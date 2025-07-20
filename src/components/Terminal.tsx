import React, { useState, useEffect, useRef } from 'react';
import { Terminal as TerminalIcon, Play, RotateCcw, Download, Settings, Maximize2 } from 'lucide-react';

const Terminal = () => {
  const [command, setCommand] = useState('');
  const [history, setHistory] = useState([
    { type: 'output', content: 'CypherFramework Terminal v1.0.0', timestamp: new Date() },
    { type: 'output', content: 'Type "help" for available commands', timestamp: new Date() },
    { type: 'output', content: '', timestamp: new Date() }
  ]);
  const [commandHistory, setCommandHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [isExecuting, setIsExecuting] = useState(false);
  const [currentPath, setCurrentPath] = useState('/cypher');
  const terminalRef = useRef(null);

  const availableCommands = {
    help: 'Show available commands',
    clear: 'Clear terminal screen',
    show: 'Show information (modules, sessions, targets, vulns)',
    use: 'Select a module to use',
    set: 'Set module option value',
    run: 'Execute current module',
    search: 'Search for modules',
    sessions: 'List and interact with sessions',
    exploit: 'Quick exploit execution',
    scan: 'Quick network scan',
    payload: 'Generate payload',
    whoami: 'Show current user context',
    pwd: 'Show current directory',
    ls: 'List files and directories',
    cd: 'Change directory'
  };

  const mockModules = [
    'auxiliary/scanner/tcp_port_scanner',
    'exploit/windows/smb/ms17_010_eternalblue',
    'exploit/multi/http/log4shell_rce',
    'exploit/linux/http/apache_mod_cgi_bash_env',
    'payload/windows/x64/meterpreter/reverse_tcp',
    'post/windows/gather/hashdump',
    'post/multi/gather/env'
  ];

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [history]);

  const addToHistory = (type, content) => {
    setHistory(prev => [...prev, { type, content, timestamp: new Date() }]);
  };

  const executeCommand = async (cmd) => {
    if (!cmd.trim()) return;

    setIsExecuting(true);
    addToHistory('command', cmd);
    
    // Add to command history
    setCommandHistory(prev => [...prev, cmd]);
    setHistoryIndex(-1);

    // Parse command
    const parts = cmd.trim().split(' ');
    const command = parts[0].toLowerCase();
    const args = parts.slice(1);

    // Simulate command execution delay
    await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));

    let output = '';

    switch (command) {
      case 'help':
        output = 'Available Commands:\n\n';
        Object.entries(availableCommands).forEach(([cmd, desc]) => {
          output += `  ${cmd.padEnd(12)} - ${desc}\n`;
        });
        break;

      case 'clear':
        setHistory([
          { type: 'output', content: 'CypherFramework Terminal v1.0.0', timestamp: new Date() },
          { type: 'output', content: 'Type "help" for available commands', timestamp: new Date() },
          { type: 'output', content: '', timestamp: new Date() }
        ]);
        setIsExecuting(false);
        return;

      case 'show':
        if (args[0] === 'modules') {
          output = 'Loaded Modules:\n\n';
          mockModules.forEach(module => {
            output += `  ${module}\n`;
          });
        } else if (args[0] === 'sessions') {
          output = 'Active Sessions:\n\n';
          output += 'ID        Type         Target         User      Status\n';
          output += '--        ----         ------         ----      ------\n';
          output += 'sess_001  meterpreter  192.168.1.105  SYSTEM    active\n';
          output += 'sess_002  shell        10.0.0.50      www-data  active\n';
        } else if (args[0] === 'targets') {
          output = 'Discovered Targets:\n\n';
          output += 'IP Address      Hostname        OS              Ports\n';
          output += '----------      --------        --              -----\n';
          output += '192.168.1.105   WIN-DESKTOP01   Windows 10      445,3389,135\n';
          output += '10.0.0.50       web-server      Ubuntu 20.04    22,80,443\n';
          output += '192.168.1.120   db-server       CentOS 7        22,3306\n';
        } else {
          output = 'Usage: show <modules|sessions|targets|vulns>';
        }
        break;

      case 'use':
        if (args.length === 0) {
          output = 'Usage: use <module_name>';
        } else {
          const module = args.join(' ');
          if (mockModules.some(m => m.includes(module))) {
            output = `Using module: ${module}\n\nModule options:\n  RHOSTS  =>  (required)\n  RPORT   =>  445\n  LHOST   =>  192.168.1.100\n  LPORT   =>  4444`;
          } else {
            output = `Module not found: ${module}`;
          }
        }
        break;

      case 'set':
        if (args.length < 2) {
          output = 'Usage: set <option> <value>';
        } else {
          output = `${args[0]} => ${args.slice(1).join(' ')}`;
        }
        break;

      case 'run':
        output = 'Executing module...\n\n';
        output += '[*] Starting exploit against 192.168.1.105:445\n';
        output += '[+] Connection established\n';
        output += '[+] Exploit completed successfully\n';
        output += '[*] Session sess_003 created';
        break;

      case 'search':
        if (args.length === 0) {
          output = 'Usage: search <term>';
        } else {
          const term = args.join(' ').toLowerCase();
          const matches = mockModules.filter(m => m.toLowerCase().includes(term));
          if (matches.length > 0) {
            output = `Search results for "${term}":\n\n`;
            matches.forEach(match => {
              output += `  ${match}\n`;
            });
          } else {
            output = `No modules found matching "${term}"`;
          }
        }
        break;

      case 'sessions':
        if (args[0] === '-i' && args[1]) {
          output = `Interacting with session ${args[1]}\n`;
          output += 'Type "exit" to return to main console\n';
          output += `\n${args[1]}> `;
        } else {
          output = 'Active Sessions:\n\n';
          output += 'sess_001  meterpreter  192.168.1.105  SYSTEM    active\n';
          output += 'sess_002  shell        10.0.0.50      www-data  active\n';
          output += '\nUsage: sessions [-i session_id]';
        }
        break;

      case 'scan':
        if (args.length === 0) {
          output = 'Usage: scan <target>';
        } else {
          output = `Scanning ${args[0]}...\n\n`;
          output += 'PORT     STATE SERVICE\n';
          output += '22/tcp   open  ssh\n';
          output += '80/tcp   open  http\n';
          output += '443/tcp  open  https\n';
          output += '445/tcp  open  microsoft-ds\n';
        }
        break;

      case 'payload':
        output = 'Generating payload...\n\n';
        output += 'Payload: windows/x64/meterpreter/reverse_tcp\n';
        output += 'LHOST: 192.168.1.100\n';
        output += 'LPORT: 4444\n';
        output += 'Size: 7168 bytes\n';
        output += 'Payload generated successfully';
        break;

      case 'whoami':
        output = 'cypher@framework:/cypher$ root';
        break;

      case 'pwd':
        output = currentPath;
        break;

      case 'ls':
        output = 'modules/  sessions/  payloads/  logs/  reports/';
        break;

      case 'cd':
        if (args.length === 0) {
          setCurrentPath('/cypher');
          output = '';
        } else {
          const newPath = args[0] === '..' ? '/cypher' : `${currentPath}/${args[0]}`;
          setCurrentPath(newPath);
          output = '';
        }
        break;

      default:
        output = `Unknown command: ${command}\nType "help" for available commands`;
    }

    if (output) {
      addToHistory('output', output);
    }
    
    setIsExecuting(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (command.trim() && !isExecuting) {
        executeCommand(command);
        setCommand('');
      }
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const newIndex = historyIndex === -1 ? commandHistory.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setCommand(commandHistory[newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex !== -1) {
        const newIndex = historyIndex + 1;
        if (newIndex >= commandHistory.length) {
          setHistoryIndex(-1);
          setCommand('');
        } else {
          setHistoryIndex(newIndex);
          setCommand(commandHistory[newIndex]);
        }
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      // Simple autocomplete
      const availableCommands = Object.keys(availableCommands);
      const matches = availableCommands.filter(cmd => cmd.startsWith(command.toLowerCase()));
      if (matches.length === 1) {
        setCommand(matches[0]);
      }
    }
  };

  const clearTerminal = () => {
    setHistory([
      { type: 'output', content: 'CypherFramework Terminal v1.0.0', timestamp: new Date() },
      { type: 'output', content: 'Type "help" for available commands', timestamp: new Date() },
      { type: 'output', content: '', timestamp: new Date() }
    ]);
  };

  const downloadHistory = () => {
    const content = history.map(entry => {
      if (entry.type === 'command') {
        return `cypher@framework:${currentPath}$ ${entry.content}`;
      } else {
        return entry.content;
      }
    }).join('\n');
    
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cypher_terminal_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-green-400">Terminal</h1>
          <p className="text-gray-400 mt-1">Interactive command-line interface for framework operations</p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={clearTerminal}
            className="flex items-center space-x-2 px-3 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
            <span>Clear</span>
          </button>
          <button
            onClick={downloadHistory}
            className="flex items-center space-x-2 px-3 py-2 bg-blue-500/20 text-blue-400 border border-blue-500/50 rounded-lg hover:bg-blue-500/30 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
          <button className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg">
            <Settings className="w-4 h-4" />
          </button>
          <button className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg">
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Terminal */}
      <div className="flex-1 bg-black border border-gray-700 rounded-lg overflow-hidden flex flex-col">
        {/* Terminal Output */}
        <div
          ref={terminalRef}
          className="flex-1 overflow-auto p-4 font-mono text-sm scrollbar-thin scrollbar-thumb-gray-600 scrollbar-track-gray-800"
        >
          {history.map((entry, index) => (
            <div key={index} className="mb-1">
              {entry.type === 'command' ? (
                <div className="flex">
                  <span className="text-green-400 mr-2 select-none">
                    cypher@framework:{currentPath}$
                  </span>
                  <span className="text-white">{entry.content}</span>
                </div>
              ) : (
                <div className="text-gray-300 whitespace-pre-wrap">
                  {entry.content}
                </div>
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

        {/* Terminal Input */}
        <div className="border-t border-gray-700 p-4 bg-gray-900">
          <div className="flex items-center">
            <span className="text-green-400 mr-2 select-none font-mono">
              cypher@framework:{currentPath}$
            </span>
            <input
              type="text"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1 bg-transparent text-white font-mono focus:outline-none"
              placeholder="Enter command..."
              disabled={isExecuting}
              autoFocus
            />
            {isExecuting && (
              <div className="ml-2">
                <div className="w-4 h-4 border-2 border-green-400 border-t-transparent rounded-full animate-spin"></div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Quick Commands */}
      <div className="mt-4 flex flex-wrap gap-2">
        {['help', 'show modules', 'show sessions', 'scan 192.168.1.0/24', 'clear'].map((cmd) => (
          <button
            key={cmd}
            onClick={() => {
              setCommand(cmd);
              setTimeout(() => {
                executeCommand(cmd);
                setCommand('');
              }, 100);
            }}
            disabled={isExecuting}
            className="px-3 py-1 bg-gray-700 text-gray-300 rounded text-sm hover:bg-gray-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-mono"
          >
            {cmd}
          </button>
        ))}
      </div>
    </div>
  );
};

export default Terminal;