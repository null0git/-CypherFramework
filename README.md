# CypherFramework ![status](https://img.shields.io/badge/status-in--development-orange)

**Professional Ethical Hacking & Penetration Testing Framework**

⚠️ **IMPORTANT DISCLAIMER**: This framework is designed exclusively for authorized penetration testing and educational purposes. Unauthorized use against systems you do not own or lack explicit permission to test is illegal and unethical.

## Overview

CypherFramework is a modern, high-performance exploitation framework inspired by Metasploit but built with contemporary technologies and advanced techniques. It provides security professionals with comprehensive tools for authorized penetration testing.

## Features

### 🔹 Core Capabilities
- **CVE-Based Exploits**: Comprehensive database of verified exploits
- **Advanced Payload Generation**: Multi-platform payload builder with encoding
- **Session Management**: Real-time session control and interaction
- **Network Scanning**: High-speed discovery and enumeration
- **Post-Exploitation**: Privilege escalation, credential dumping, lateral movement
- **AI-Assisted Recommendations**: Smart exploit matching based on target fingerprints

### 🔹 Technical Features
- **Modern Architecture**: Built with Python 3.11+, FastAPI, and React
- **Async Performance**: High-concurrency operations for speed
- **Modular Design**: Easily extensible plugin system
- **Dual Interface**: Both CLI and web-based interfaces
- **Real-time Updates**: WebSocket-powered live monitoring
- **Advanced Encoding**: Multiple evasion techniques and encoders

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/null0git/cypher-framework
   cd cypher-framework
   ```

2. **Set up Python backend**
   ```bash
   cd backend
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Set up React frontend**
   ```bash
   npm install
   ```

### Running the Framework

#### Web Interface (Recommended)
```bash
# Start backend
cd backend
python run.py

# In another terminal, start frontend
npm run dev
```

#### CLI Interface
```bash
cd backend
python main.py --mode cli
```

#### Payload Generation
```bash
cd backend
python main.py --mode build --os windows --arch x64 --type reverse_tcp --lhost 192.168.1.100 --lport 4444
```

## Usage Examples

### Web Interface
1. Navigate to `http://localhost:3000`
2. Use the Dashboard to monitor activities
3. Scanner module for target discovery
4. Exploit Manager for vulnerability exploitation
5. Session Manager for post-exploitation
6. Payload Builder for custom payloads

### CLI Interface
```bash
# Show available modules
cypher > show modules

# Use an exploit module
cypher > use exploit/windows/smb/ms17_010_eternalblue
cypher (ms17_010_eternalblue) > set RHOSTS 192.168.1.100
cypher (ms17_010_eternalblue) > run

# Interact with sessions
cypher > sessions -i sess_001
```

## Architecture

```
/framework_root/
├── backend/
│   ├── core/                 # Framework engine
│   ├── modules/              # Exploit, auxiliary, post modules
│   ├── web/                  # FastAPI web server
│   ├── cli/                  # Command-line interface
│   └── database/             # CVE and target data
├── src/                      # React frontend
└── docs/                     # Documentation
```

## Module Development

### Creating an Exploit Module

```python
from modules.templates.base_exploit import BaseExploit

class MyExploit(BaseExploit):
    name = "My Custom Exploit"
    cve = "CVE-2024-XXXX"
    target_os = ["windows", "linux"]
    
    def _default_options(self):
        return {
            'RHOSTS': {'value': '', 'required': True},
            'RPORT': {'value': 80, 'required': True}
        }
    
    async def check(self, target):
        # Vulnerability check logic
        return {'vulnerable': True, 'confidence': 0.95}
    
    async def run(self, target):
        # Exploitation logic
        return {'success': True, 'session_id': 'sess_123'}
```

### Creating an Auxiliary Module

```python
from modules.templates.base_auxiliary import BaseAuxiliary

class MyScanner(BaseAuxiliary):
    name = "Custom Scanner"
    category = "scanner"
    
    def _default_options(self):
        return {
            'RHOSTS': {'value': '', 'required': True},
            'THREADS': {'value': 10, 'required': False}
        }
    
    async def run(self, options):
        # Scanner logic
        return {'success': True, 'results': []}
```

### Creating an Encoder

```python
from modules.templates.base_encoder import BaseEncoder

class MyEncoder(BaseEncoder):
    name = "Custom Encoder"
    description = "Custom payload encoding"
    
    def encode(self, payload, **options):
        # Encoding logic
        return encoded_payload
    
    def decode(self, encoded_payload, **options):
        # Decoding logic
        return original_payload
```

### Adding Custom Modules

1. **Create your module file** in the appropriate directory:
   - Exploits: `backend/modules/exploits/your_exploit.py`
   - Auxiliary: `backend/modules/auxiliary/your_scanner.py`
   - Encoders: `backend/modules/encoders/your_encoder.py`
   - Post-Exploitation: `backend/modules/post_exploit/your_post.py`

2. **Follow the template structure** (see examples above)

3. **Test your module**:
   ```bash
   # CLI testing
   cypher > use your_module_name
   cypher (your_module) > show options
   cypher (your_module) > run
   ```

4. **Module metadata** (required):
   ```python
   name = "Module Name"
   description = "What this module does"
   author = "Your Name"
   version = "1.0"
   cve = "CVE-XXXX-XXXX"  # If applicable
   target_os = ["windows", "linux"]  # Supported OS
   ```

### Module Directory Structure

```
backend/modules/
├── templates/           # Base classes
│   ├── base_exploit.py
│   ├── base_auxiliary.py
│   ├── base_encoder.py
│   └── base_post_exploit.py
├── exploits/           # Exploit modules
│   ├── eternalblue_ms17_010.py
│   ├── log4shell_cve_2021_44228.py
│   └── your_exploit.py
├── auxiliary/          # Scanner/utility modules
│   ├── port_scanner.py
│   ├── web_scanner.py
│   └── your_scanner.py
├── encoders/           # Payload encoders
│   └── your_encoder.py
└── post_exploit/       # Post-exploitation modules
    ├── system_info.py
    └── your_post.py
```

## Security Considerations

### Authorized Use Only
- Only use against systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Document all testing activities

### Safety Features
- Built-in logging and audit trails
- Session isolation and management
- Configurable rate limiting
- Safe mode options for testing

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Module Contribution Guidelines
- Follow the established module templates
- Include comprehensive tests
- Document all options and usage
- Verify against multiple targets
- Include author attribution

## Legal Notice

This framework is provided for educational and authorized testing purposes only. Users are solely responsible for ensuring their use complies with applicable laws and regulations. The authors assume no liability for misuse or illegal activities.

### Acceptable Use
✅ Authorized penetration testing
✅ Security research (with permission)
✅ Educational purposes
✅ Red team exercises (authorized)

### Prohibited Use
❌ Unauthorized system access
❌ Malicious attacks
❌ Data theft or destruction
❌ Any illegal activities

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Follow responsible disclosure for security issues
- Check documentation and examples first

## Acknowledgments

- Inspired by Metasploit Framework
- Built with modern security practices
- Community-driven exploit database
- Thanks to all security researchers and contributors

---

**Remember**: With great power comes great responsibility. Use this framework ethically and legally.
