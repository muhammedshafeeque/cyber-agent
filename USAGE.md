# Cyber Agent - Usage Guide

## Quick Start

### 1. Installation

```bash
# Install dependencies
npm install

# Make CLI executable (if not already)
chmod +x bin/cyber-agent
```

### 2. Configuration

```bash
# Copy sample environment file
cp sample.env .env

# Edit .env with your credentials
nano .env
# or
vim .env
```

**Required Configuration:**
- `MISTRAL_API_KEY` - Get from https://mistral.ai
- `ARANGO_PASSWORD` - Your ArangoDB password

### 3. Initialize Database

```bash
# Start ArangoDB first (if not running)
sudo systemctl start arangodb3
# or
docker run -d -p 8529:8529 -e ARANGO_ROOT_PASSWORD=yourpassword arangodb

# Initialize the knowledge graph
node bin/cyber-agent init
```

---

## Commands

### Main Testing Command

#### Run Autonomous Penetration Test

```bash
# Basic test with RCE goal (default)
node bin/cyber-agent test http://example.com

# Test with specific goal
node bin/cyber-agent test http://example.com --goal rce

# Test using only Kali Linux tools
node bin/cyber-agent test http://example.com --kali-only

# Enable interactive mode for GUI tools
node bin/cyber-agent test http://example.com --interactive
```

**What it does:**
- Performs reconnaissance (nmap scan)
- Discovers vulnerabilities
- Researches exploits online
- Attempts to achieve Remote Code Execution (RCE)
- Stores findings in knowledge graph

**Example:**
```bash
node bin/cyber-agent test https://testphp.vulnweb.com --goal rce
```

---

### Query Knowledge Graph

```bash
# Query stored knowledge
node bin/cyber-agent query "SQL injection vulnerabilities"

# Search for specific vulnerability types
node bin/cyber-agent query "command injection"
```

**Example:**
```bash
node bin/cyber-agent query "What vulnerabilities were found in web applications?"
```

---

### Tool Management

#### List Installed Tools

```bash
node bin/cyber-agent tools list
```

**Output:** Shows all tools discovered and installed

---

#### Install a Tool

```bash
# Install a security tool automatically
node bin/cyber-agent tools install sqlmap

# The system will:
# 1. Check if tool exists (Kali tools prioritized)
# 2. Search online for installation instructions
# 3. Install using appropriate method (apt, pip, npm, git, etc.)
```

**Example:**
```bash
node bin/cyber-agent tools install nikto
```

---

### Exploit Generation

```bash
# Generate exploit for a vulnerability
node bin/cyber-agent exploits generate "SQL injection"

# Generate exploit with vulnerability description
node bin/cyber-agent exploits generate "command injection in login form"
```

**Example:**
```bash
node bin/cyber-agent exploits generate "file upload vulnerability"
```

---

### Knowledge Graph Exploration

```bash
# Explore the knowledge graph interactively
node bin/cyber-agent graph explore
```

---

### Interactive AI Guidance Mode

```bash
# Enter interactive mode for manual testing with AI guidance
node bin/cyber-agent interactive
```

**Features:**
- Ask questions about penetration testing
- Upload screenshots for AI analysis (e.g., Burp Suite, browser)
- Provide tool outputs for analysis
- Get step-by-step guidance

**Example Session:**
```
What would you like to do? upload screenshot
Enter path to screenshot: /path/to/burp_screenshot.png

[AI analyzes screenshot and provides next steps]

What would you like to do? provide output
[Paste nmap scan output]

[AI analyzes and recommends next actions]
```

---

## Usage Workflows

### Workflow 1: Full Autonomous Test

```bash
# 1. Initialize database
node bin/cyber-agent init

# 2. Run full autonomous test
node bin/cyber-agent test http://target.com --goal rce

# The agent will:
# - Scan for open ports and services
# - Discover vulnerabilities
# - Research exploits online
# - Generate custom exploits
# - Attempt RCE
# - Store everything in knowledge graph
```

### Workflow 2: Interactive Testing with GUI Tools

```bash
# 1. Start interactive mode
node bin/cyber-agent interactive

# 2. Upload Burp Suite screenshot when prompted
# 3. Follow AI guidance for next steps
# 4. Provide tool outputs for analysis
```

### Workflow 3: Manual Tool Testing with AI Analysis

```bash
# 1. Run your own nmap scan
nmap -sV target.com > nmap_output.txt

# 2. Enter interactive mode
node bin/cyber-agent interactive

# 3. Choose "provide output"
# 4. Paste the nmap output
# 5. Get AI recommendations
```

---

## Examples

### Example 1: Test a Web Application

```bash
node bin/cyber-agent test https://example.com
```

**Output:**
- Reconnaissance results
- Discovered vulnerabilities
- Generated exploits
- RCE status

### Example 2: Query Previous Findings

```bash
# After running tests, query the knowledge graph
node bin/cyber-agent query "file upload vulnerabilities"
```

### Example 3: Install Missing Tool

```bash
# If agent needs a tool, it will auto-install
# Or manually install:
node bin/cyber-agent tools install wpscan
```

---

## Advanced Usage

### Environment Variables

You can also set environment variables directly:

```bash
MISTRAL_API_KEY=your_key ARANGO_PASSWORD=your_pass node bin/cyber-agent test target.com
```

### Global Installation (Optional)

```bash
# Install globally so you can use 'cyber-agent' from anywhere
npm link

# Then use:
cyber-agent test target.com
```

---

## Tips

1. **First Run**: Always run `init` command first to set up the database
2. **Kali Linux**: Works best on Kali Linux with pre-installed tools
3. **GUI Tools**: Use `--interactive` flag when you need to use Burp Suite or other GUI tools
4. **Knowledge Graph**: The tool learns and stores patterns - subsequent tests will be smarter
5. **RCE Focus**: Default goal is RCE - the tool will prioritize vulnerabilities that can lead to code execution

---

## Troubleshooting

### Database Connection Issues

```bash
# Check if ArangoDB is running
sudo systemctl status arangodb3

# Check connection
curl http://localhost:8529/_api/version
```

### Tool Not Found

```bash
# Tool will auto-install if possible
# Or manually install system packages:
sudo apt-get update
sudo apt-get install nmap sqlmap nikto
```

### API Key Issues

```bash
# Verify API key is set
echo $MISTRAL_API_KEY

# Or check .env file
cat .env | grep MISTRAL_API_KEY
```

---

## Output Files

The tool creates files in `./work/` directory:

- `./work/tools/` - Installed tools from git
- `./work/exploits/` - Generated exploit scripts
- `./work/logs/` - Execution logs

---

## Security Notes

⚠️ **Important:**
- Only use on systems you own or have explicit permission to test
- The tool generates exploits that can cause damage
- Always use in isolated/test environments
- Review generated exploits before execution
- The tool logs all actions for auditing

---

## Getting Help

```bash
# Show help
node bin/cyber-agent --help

# Get help for specific command
node bin/cyber-agent test --help
node bin/cyber-agent tools --help
```

