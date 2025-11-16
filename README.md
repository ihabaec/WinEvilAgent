# PenAi-Windows

An AI-powered automated Windows penetration testing agent designed for red team operations and security research.

## Overview

PenAi-Windows is a sophisticated Python framework that combines artificial intelligence with automated penetration testing techniques to assess Windows systems. The agent autonomously performs reconnaissance, identifies privilege escalation vectors, and attempts to gain administrator access through intelligent decision-making powered by AI.

## Features

### Core Capabilities

- **AI-Driven Decision Making**: Leverages Groq's Llama 3 model to intelligently select and execute privilege escalation techniques
- **Automated Reconnaissance**: Comprehensive system enumeration including users, services, network configuration, and security posture
- **Multi-Phase Attack Execution**: Structured workflow from reconnaissance through privilege escalation to objective completion
- **WinRM-Based Execution**: Remote command execution via Windows Remote Management protocol
- **Credential Harvesting**: Automated Mimikatz integration for credential dumping
- **Safety Mechanisms**: Built-in command blocklists and pattern detection to prevent destructive operations
- **Complete Audit Trail**: Detailed logging and JSON-formatted results for post-operation analysis

### Reconnaissance Module

- System information gathering (OS, architecture, domain status)
- User and privilege enumeration
- Network configuration analysis
- Software and service enumeration
- Scheduled task analysis
- File permission analysis
- Security product detection

### Privilege Escalation Techniques

- SeDebugPrivilege exploitation
- Unquoted service path abuse
- Registry autorun hijacking
- AlwaysInstallElevated bypass
- DLL injection opportunities
- Token manipulation
- Service misconfiguration exploitation

## Installation

### Prerequisites

- Python 3.13 or higher
- WinRM enabled on target Windows system
- Valid credentials for target system
- Groq API key

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd PenAi-Windows
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables in `.env`:
```env
GROQ_API_KEY=<your-groq-api-key>
TARGET_HOST=<target-ip-address>
TARGET_USER=<username>
TARGET_PASS=<password>
MAX_STEPS=10
ENABLE_SAFETY_CHECKS=true
LOG_COMMANDS=true
```

## Usage

### Running the Agent

**Automatic Mode** (recommended):
```bash
python -m pentest_agent --mode auto
```

**Interactive Mode**:
```bash
python -m pentest_agent --mode interactive
```

**Custom Configuration**:
```bash
python -m pentest_agent --mode auto --enum-config custom_enum.yaml --priv-config custom_priv.yaml --log-file output.log
```

**Create Sample Configs**:
```bash
python -m pentest_agent --mode create-samples
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--mode` | Operation mode: `auto`, `interactive`, or `create-samples` | `auto` |
| `--enum-config` | Path to enumeration YAML config | `pentest_agent/enum.yaml` |
| `--priv-config` | Path to privilege escalation YAML config | `pentest_agent/priv.yaml` |
| `--log-level` | Logging level: DEBUG, INFO, WARNING, ERROR | `INFO` |
| `--log-file` | Path to log file | `None` (console only) |

## Project Structure

```
PenAi-Windows/
├── pentest_agent/              # Main agent module
│   ├── __main__.py             # Package entry point
│   ├── main.py                 # CLI interface
│   ├── agent.py                # Core PentestAgent class
│   ├── ai_assistant.py         # AI integration (Groq API)
│   ├── winrm_client.py         # WinRM connection handler
│   ├── config_loader.py        # YAML configuration loader
│   ├── security_checker.py     # Safety checks
│   ├── recon_module.py         # Reconnaissance module
│   ├── enum.yaml               # Enumeration commands
│   └── priv.yaml               # Privilege escalation methods
│
├── noisebot/                   # SOC detection testing tool
│   ├── noisebot.py             # Telemetry generation
│   └── scenario.yaml           # Scenario configuration
│
├── logs/                       # Execution logs
├── results/                    # Output results (JSON)
├── old-versions/               # Archived code versions
│
├── .env                        # Environment configuration
├── test.py                     # Mimikatz testing
├── apitest.py                  # API testing utility
└── connect.py                  # Connection testing
```

## Configuration

### Enumeration Configuration (enum.yaml)

Defines reconnaissance commands and techniques:

```yaml
- name: "Get User Info"
  category: "user"
  description: "Get current user information"
  command: "whoami /all"
  indicators:
    - "BUILTIN\\Administrators"
    - "SeDebugPrivilege"
  priority: 10
```

### Privilege Escalation Configuration (priv.yaml)

Defines privilege escalation techniques:

```yaml
- name: "Service Binary Hijack"
  category: "service"
  description: "Exploit service binary path with weak permissions"
  command: "sc qc <service_name>"
  indicators:
    - "BINARY_PATH_NAME"
  priority: 8
```

## Attack Workflow

```
1. RECONNAISSANCE PHASE
   - Gather system information
   - Enumerate users, services, and permissions
   - Identify attack vectors
   ↓
2. PRIVILEGE ESCALATION PHASE
   - AI suggests escalation commands
   - Execute and analyze results
   - Repeat until admin access or max attempts
   ↓
3. OBJECTIVE COMPLETION PHASE
   - Harvest credentials (Mimikatz)
   - Create proof-of-compromise
   - Save results to JSON
```

## Output

Results are saved to `results/out.json` containing:

- **System Context**: OS info, users, services, network config, permissions
- **Attack Vectors**: Identified vulnerabilities and weaknesses
- **Action History**: Commands executed with outputs and timestamps
- **Phase Transitions**: Timeline of agent progression
- **Objective Status**: Whether admin access was achieved

## NoiseBot - SOC Testing Tool

PenAi-Windows includes **NoiseBot**, a supplementary tool for generating benign but detectable Windows telemetry to test SOC detection capabilities.

### Running NoiseBot

```bash
python noisebot/noisebot.py
```

### Features

- Simulates realistic attacker behavior patterns
- Generates telemetry for Elastic/Kibana rule testing
- Configurable attack scenarios
- Supports multiple techniques (process masquerade, PowerShell, SMB, registry modifications)

## Security Considerations

### Safety Mechanisms

- **Command Blocklist**: Prevents execution of destructive commands (`del`, `format`, `shutdown`, etc.)
- **Pattern Detection**: Regex-based filtering of dangerous operations
- **Safety Checks**: Controlled via `ENABLE_SAFETY_CHECKS` environment variable
- **Audit Logging**: Complete history of executed commands and results

### Ethical Use

This tool is designed for:
- Authorized penetration testing engagements
- Red team exercises in controlled environments
- Security research and education
- SOC detection testing

**IMPORTANT**: Only use this tool against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

## Requirements

### Target System Requirements

- Windows operating system
- WinRM enabled (ports 5985/5986)
- Valid user credentials
- Network connectivity from testing machine

### Testing Machine Requirements

- Python 3.13+
- Network access to target
- Groq API access

## Troubleshooting

### Connection Issues

- Verify WinRM is enabled: `winrm quickconfig`
- Check firewall rules for ports 5985/5986
- Confirm credentials are correct
- Test connectivity with `connect.py`

### API Issues

- Verify Groq API key is valid
- Check internet connectivity
- Review API rate limits
- Test with `apitest.py`

### Permission Issues

- Ensure initial credentials have sufficient rights
- Verify UAC settings on target
- Check Windows security policies

## Development

### Current Status

- Version: 1.0
- Active development with Mimikatz integration
- Recent focus on credential harvesting capabilities

### Contributing

This is a security research tool. Contributions should focus on:
- Additional enumeration techniques
- New privilege escalation methods
- Improved AI decision-making
- Enhanced safety mechanisms

## License

[Specify your license here]

## Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Users are solely responsible for ensuring they have proper authorization before using this tool against any system.

## Acknowledgments

- Groq for AI API access
- The penetration testing and security research community
- Contributors and testers

## Contact

ihabaec@gmail.com

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
