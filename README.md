# Cyber Agent - Autonomous Penetration Testing CLI Tool

An autonomous cybersecurity penetration testing tool that thinks like a hacker, learns from each interaction, and aims to achieve Remote Code Execution (RCE) when possible.

## Features

- **Autonomous Intelligence**: AI-powered decision making using Mistral AI
- **Knowledge Graph**: Learns and stores patterns in ArangoDB
- **Kali Linux Integration**: Leverages built-in Kali tools (nmap, metasploit, burp suite, etc.)
- **Dynamic Tool Management**: Discovers, installs, and updates security tools
- **RCE Focus**: Primary goal is achieving Remote Code Execution
- **Interactive AI Guidance**: Manual steps for GUI tools with AI analysis

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```
4. Install ArangoDB and start it
5. Make the CLI executable:
   ```bash
   chmod +x bin/cyber-agent
   ```
6. Install globally (optional):
   ```bash
   npm link
   ```

## Usage

```bash
# Run autonomous security test
cyber-agent test <target> --goal rce

# Query knowledge graph
cyber-agent query <question>

# List tools
cyber-agent tools list

# Interactive mode
cyber-agent interactive
```

## Configuration

Edit `.env` file with your:
- Mistral AI API key
- ArangoDB credentials
- Application settings

## Requirements

- Node.js >= 18.0.0
- ArangoDB
- Kali Linux (recommended) or Linux with security tools
- Mistral AI API key

## License

MIT

# cyber-agent
