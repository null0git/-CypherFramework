import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Save, RotateCcw, Shield, Database, Network, Bell, User, Lock } from 'lucide-react';

const Settings = () => {
  const [settings, setSettings] = useState({
    // Framework Settings
    framework: {
      auto_update: true,
      check_interval: 24,
      max_sessions: 10,
      session_timeout: 3600,
      log_level: 'INFO',
      enable_logging: true
    },
    
    // Security Settings
    security: {
      require_auth: false,
      enable_ssl: false,
      ssl_cert_path: '',
      ssl_key_path: '',
      api_key: '',
      allowed_ips: '127.0.0.1,192.168.1.0/24'
    },
    
    // Database Settings
    database: {
      type: 'sqlite',
      path: 'database/cypher.db',
      auto_backup: true,
      backup_interval: 168, // hours
      max_backups: 5
    },
    
    // Network Settings
    network: {
      web_host: '127.0.0.1',
      web_port: 8000,
      api_host: '127.0.0.1',
      api_port: 8001,
      enable_cors: true,
      cors_origins: 'http://localhost:3000'
    },
    
    // Notification Settings
    notifications: {
      enable_notifications: true,
      email_notifications: false,
      webhook_url: '',
      notify_on_exploit: true,
      notify_on_session: true,
      notify_on_error: true
    },
    
    // Module Settings
    modules: {
      auto_load: true,
      custom_paths: '',
      enable_custom_modules: true,
      verify_signatures: false
    }
  });

  const [activeTab, setActiveTab] = useState('framework');
  const [hasChanges, setHasChanges] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  const tabs = [
    { id: 'framework', name: 'Framework', icon: SettingsIcon },
    { id: 'security', name: 'Security', icon: Shield },
    { id: 'database', name: 'Database', icon: Database },
    { id: 'network', name: 'Network', icon: Network },
    { id: 'notifications', name: 'Notifications', icon: Bell },
    { id: 'modules', name: 'Modules', icon: User }
  ];

  useEffect(() => {
    // Load settings from backend
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const response = await fetch('/api/settings');
      if (response.ok) {
        const data = await response.json();
        setSettings(data);
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  };

  const handleSettingChange = (category, key, value) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value
      }
    }));
    setHasChanges(true);
  };

  const saveSettings = async () => {
    setIsSaving(true);
    
    try {
      const response = await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(settings)
      });
      
      if (response.ok) {
        setHasChanges(false);
        alert('Settings saved successfully!');
      } else {
        alert('Failed to save settings');
      }
    } catch (error) {
      console.error('Error saving settings:', error);
      alert('Error saving settings');
    }
    
    setIsSaving(false);
  };

  const resetSettings = () => {
    if (confirm('Are you sure you want to reset all settings to defaults?')) {
      loadSettings();
      setHasChanges(false);
    }
  };

  const renderFrameworkSettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-green-400 mb-4">Framework Configuration</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Auto Update CVE Database</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.framework.auto_update}
                onChange={(e) => handleSettingChange('framework', 'auto_update', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Enable automatic updates</span>
            </label>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Update Check Interval (hours)</label>
            <input
              type="number"
              value={settings.framework.check_interval}
              onChange={(e) => handleSettingChange('framework', 'check_interval', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              min="1"
              max="168"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Maximum Sessions</label>
            <input
              type="number"
              value={settings.framework.max_sessions}
              onChange={(e) => handleSettingChange('framework', 'max_sessions', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              min="1"
              max="100"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Session Timeout (seconds)</label>
            <input
              type="number"
              value={settings.framework.session_timeout}
              onChange={(e) => handleSettingChange('framework', 'session_timeout', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              min="60"
              max="86400"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Log Level</label>
            <select
              value={settings.framework.log_level}
              onChange={(e) => handleSettingChange('framework', 'log_level', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
            >
              <option value="DEBUG">DEBUG</option>
              <option value="INFO">INFO</option>
              <option value="WARNING">WARNING</option>
              <option value="ERROR">ERROR</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Enable Logging</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.framework.enable_logging}
                onChange={(e) => handleSettingChange('framework', 'enable_logging', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Log framework activities</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );

  const renderSecuritySettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-green-400 mb-4">Security Configuration</h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Require Authentication</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.security.require_auth}
                onChange={(e) => handleSettingChange('security', 'require_auth', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Enable API authentication</span>
            </label>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">API Key</label>
            <input
              type="password"
              value={settings.security.api_key}
              onChange={(e) => handleSettingChange('security', 'api_key', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              placeholder="Enter API key"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Allowed IP Addresses</label>
            <textarea
              value={settings.security.allowed_ips}
              onChange={(e) => handleSettingChange('security', 'allowed_ips', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              rows="3"
              placeholder="127.0.0.1,192.168.1.0/24"
            />
            <p className="text-xs text-gray-500 mt-1">Comma-separated list of allowed IPs/subnets</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Enable SSL/TLS</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.security.enable_ssl}
                onChange={(e) => handleSettingChange('security', 'enable_ssl', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Use HTTPS for web interface</span>
            </label>
          </div>
          
          {settings.security.enable_ssl && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">SSL Certificate Path</label>
                <input
                  type="text"
                  value={settings.security.ssl_cert_path}
                  onChange={(e) => handleSettingChange('security', 'ssl_cert_path', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                  placeholder="/path/to/cert.pem"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">SSL Private Key Path</label>
                <input
                  type="text"
                  value={settings.security.ssl_key_path}
                  onChange={(e) => handleSettingChange('security', 'ssl_key_path', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                  placeholder="/path/to/key.pem"
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  const renderDatabaseSettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-green-400 mb-4">Database Configuration</h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Database Type</label>
            <select
              value={settings.database.type}
              onChange={(e) => handleSettingChange('database', 'type', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
            >
              <option value="sqlite">SQLite</option>
              <option value="postgresql">PostgreSQL</option>
              <option value="mysql">MySQL</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Database Path/Connection String</label>
            <input
              type="text"
              value={settings.database.path}
              onChange={(e) => handleSettingChange('database', 'path', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              placeholder="database/cypher.db"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Auto Backup</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.database.auto_backup}
                onChange={(e) => handleSettingChange('database', 'auto_backup', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Enable automatic database backups</span>
            </label>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">Backup Interval (hours)</label>
              <input
                type="number"
                value={settings.database.backup_interval}
                onChange={(e) => handleSettingChange('database', 'backup_interval', parseInt(e.target.value))}
                className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                min="1"
                max="8760"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">Maximum Backups</label>
              <input
                type="number"
                value={settings.database.max_backups}
                onChange={(e) => handleSettingChange('database', 'max_backups', parseInt(e.target.value))}
                className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
                min="1"
                max="100"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderNetworkSettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-green-400 mb-4">Network Configuration</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Web Interface Host</label>
            <input
              type="text"
              value={settings.network.web_host}
              onChange={(e) => handleSettingChange('network', 'web_host', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              placeholder="127.0.0.1"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Web Interface Port</label>
            <input
              type="number"
              value={settings.network.web_port}
              onChange={(e) => handleSettingChange('network', 'web_port', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              min="1"
              max="65535"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">API Host</label>
            <input
              type="text"
              value={settings.network.api_host}
              onChange={(e) => handleSettingChange('network', 'api_host', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              placeholder="127.0.0.1"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">API Port</label>
            <input
              type="number"
              value={settings.network.api_port}
              onChange={(e) => handleSettingChange('network', 'api_port', parseInt(e.target.value))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              min="1"
              max="65535"
            />
          </div>
        </div>
        
        <div className="mt-4">
          <label className="block text-sm font-medium text-gray-400 mb-2">Enable CORS</label>
          <label className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={settings.network.enable_cors}
              onChange={(e) => handleSettingChange('network', 'enable_cors', e.target.checked)}
              className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
            />
            <span className="text-gray-300">Allow cross-origin requests</span>
          </label>
        </div>
        
        {settings.network.enable_cors && (
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">CORS Origins</label>
            <input
              type="text"
              value={settings.network.cors_origins}
              onChange={(e) => handleSettingChange('network', 'cors_origins', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              placeholder="http://localhost:3000"
            />
          </div>
        )}
      </div>
    </div>
  );

  const renderNotificationSettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-green-400 mb-4">Notification Configuration</h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Enable Notifications</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.notifications.enable_notifications}
                onChange={(e) => handleSettingChange('notifications', 'enable_notifications', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Enable system notifications</span>
            </label>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Webhook URL</label>
            <input
              type="url"
              value={settings.notifications.webhook_url}
              onChange={(e) => handleSettingChange('notifications', 'webhook_url', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              placeholder="https://hooks.slack.com/..."
            />
          </div>
          
          <div className="space-y-2">
            <label className="block text-sm font-medium text-gray-400">Notification Types</label>
            
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.notifications.notify_on_exploit}
                onChange={(e) => handleSettingChange('notifications', 'notify_on_exploit', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Notify on successful exploits</span>
            </label>
            
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.notifications.notify_on_session}
                onChange={(e) => handleSettingChange('notifications', 'notify_on_session', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Notify on new sessions</span>
            </label>
            
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.notifications.notify_on_error}
                onChange={(e) => handleSettingChange('notifications', 'notify_on_error', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Notify on errors</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );

  const renderModuleSettings = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-green-400 mb-4">Module Configuration</h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Auto Load Modules</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.modules.auto_load}
                onChange={(e) => handleSettingChange('modules', 'auto_load', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Automatically load modules on startup</span>
            </label>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Enable Custom Modules</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.modules.enable_custom_modules}
                onChange={(e) => handleSettingChange('modules', 'enable_custom_modules', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Allow loading of custom modules</span>
            </label>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Custom Module Paths</label>
            <textarea
              value={settings.modules.custom_paths}
              onChange={(e) => handleSettingChange('modules', 'custom_paths', e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-lg text-gray-300 focus:border-green-500 focus:outline-none"
              rows="3"
              placeholder="/path/to/custom/modules&#10;/another/path"
            />
            <p className="text-xs text-gray-500 mt-1">One path per line</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">Verify Module Signatures</label>
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={settings.modules.verify_signatures}
                onChange={(e) => handleSettingChange('modules', 'verify_signatures', e.target.checked)}
                className="w-4 h-4 text-green-400 bg-gray-900 border-gray-600 rounded focus:ring-green-400"
              />
              <span className="text-gray-300">Verify digital signatures of modules</span>
            </label>
          </div>
        </div>
      </div>
    </div>
  );

  const renderActiveTab = () => {
    switch (activeTab) {
      case 'framework': return renderFrameworkSettings();
      case 'security': return renderSecuritySettings();
      case 'database': return renderDatabaseSettings();
      case 'network': return renderNetworkSettings();
      case 'notifications': return renderNotificationSettings();
      case 'modules': return renderModuleSettings();
      default: return renderFrameworkSettings();
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="border-b border-gray-700 pb-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-green-400">Settings</h1>
            <p className="text-gray-400 mt-1">Configure CypherFramework settings and preferences</p>
          </div>
          <div className="flex items-center space-x-3">
            {hasChanges && (
              <span className="text-yellow-400 text-sm">Unsaved changes</span>
            )}
            <button
              onClick={resetSettings}
              className="flex items-center space-x-2 px-3 py-2 bg-gray-700 text-gray-300 rounded-lg hover:bg-gray-600 transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Reset</span>
            </button>
            <button
              onClick={saveSettings}
              disabled={!hasChanges || isSaving}
              className="flex items-center space-x-2 px-4 py-2 bg-green-500/20 text-green-400 border border-green-500/50 rounded-lg hover:bg-green-500/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSaving ? (
                <>
                  <div className="w-4 h-4 border-2 border-green-400 border-t-transparent rounded-full animate-spin"></div>
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  <span>Save Changes</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* Settings Navigation */}
        <div className="xl:col-span-1">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <h2 className="text-lg font-semibold text-green-400 mb-4">Categories</h2>
            <nav className="space-y-2">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-colors ${
                      activeTab === tab.id
                        ? 'bg-green-500/20 text-green-400 border border-green-500/40'
                        : 'text-gray-400 hover:bg-gray-700 hover:text-green-400'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{tab.name}</span>
                  </button>
                );
              })}
            </nav>
          </div>
        </div>

        {/* Settings Content */}
        <div className="xl:col-span-3">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            {renderActiveTab()}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;