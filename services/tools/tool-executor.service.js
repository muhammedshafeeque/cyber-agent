const { exec } = require('child_process');
const { promisify } = require('util');
const toolRegistry = require('./tool-registry.service');

const execAsync = promisify(exec);

async function executeTool(toolName, args = [], options = {}) {
  try {
    // Check if tool exists
    const toolStatus = await toolRegistry.findToolInSystem(toolName);
    
    if (!toolStatus.available) {
      return {
        success: false,
        error: `Tool ${toolName} not found`,
      };
    }

    // Check if it's a CLI tool (can be executed automatically)
    if (!toolRegistry.isCLITool(toolName)) {
      return {
        success: false,
        requiresManual: true,
        tool: toolName,
        message: `${toolName} requires manual interaction (GUI tool)`,
      };
    }

    // Validate command for safety
    const commandArgs = args.join(' ');
    if (!validateCommand(toolName, commandArgs)) {
      return {
        success: false,
        error: 'Command validation failed - potentially unsafe',
      };
    }

    // Build command
    const command = `${toolStatus.path || toolName} ${commandArgs}`;
    
    // Execute with timeout
    const timeout = options.timeout || 300000; // 5 minutes default
    
    try {
      const { stdout, stderr } = await Promise.race([
        execAsync(command, {
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer
          timeout,
        }),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Command timeout')), timeout)
        ),
      ]);

      const result = {
        success: true,
        tool: toolName,
        command,
        stdout,
        stderr,
        output: stdout + (stderr || ''),
      };

      // Log execution
      logExecution(toolName, command, result);

      return result;
    } catch (error) {
      const result = {
        success: false,
        tool: toolName,
        command,
        error: error.message,
        stderr: error.stderr,
        stdout: error.stdout,
      };

      // Log execution
      logExecution(toolName, command, result);

      return result;
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

async function executeNmap(target, options = {}) {
  const args = [];
  
  if (options.ports) {
    args.push(`-p ${options.ports}`);
  } else {
    args.push('-p-'); // All ports
  }

  if (options.serviceVersion) {
    args.push('-sV');
  }

  if (options.script) {
    args.push(`--script ${options.script}`);
  }

  args.push(target);

  return await executeTool('nmap', args, { timeout: 600000 }); // 10 minutes for full scan
}

async function executeSqlmap(url, options = {}) {
  const args = ['--batch']; // Non-interactive mode

  if (options.forms) {
    args.push('--forms');
  }

  if (options.crawl) {
    args.push(`--crawl=${options.crawl}`);
  }

  args.push(`-u ${url}`);

  return await executeTool('sqlmap', args, { timeout: 600000 });
}

async function executeNikto(target, options = {}) {
  const args = [];

  if (options.port) {
    args.push(`-p ${options.port}`);
  }

  args.push(`-h ${target}`);

  return await executeTool('nikto', args, { timeout: 300000 });
}

async function executeMetasploit(exploit, payload, options = {}) {
  // Metasploit requires special handling
  const msfScript = `
use ${exploit}
set RHOSTS ${options.target || ''}
set RPORT ${options.port || '80'}
${payload ? `set payload ${payload}` : ''}
${options.lhost ? `set LHOST ${options.lhost}` : ''}
exploit
`;

  // Write script to temp file
  const fs = require('fs-extra');
  const path = require('path');
  const scriptPath = path.join(process.env.WORK_DIR || './work', 'msf_script.rc');
  await fs.writeFile(scriptPath, msfScript);

  // Execute msfconsole
  return await executeTool('msfconsole', ['-r', scriptPath], { timeout: 600000 });
}

async function executeNcat(target, port, command = '') {
  const args = [];
  
  if (command) {
    args.push(`-e ${command}`);
  }

  args.push(target);
  args.push(port);

  return await executeTool('ncat', args, { timeout: 60000 });
}

function validateCommand(toolName, args) {
  // Basic safety checks
  const dangerousPatterns = [
    /rm\s+-rf/,
    /mkfs/,
    /dd\s+if=/,
    /format/,
    />\s*\/dev/,
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(args)) {
      console.error(`Dangerous command pattern detected: ${pattern}`);
      return false;
    }
  }

  // Tool-specific validation
  if (toolName === 'nmap' || toolName === 'sqlmap' || toolName === 'nikto') {
    // These tools are generally safe for scanning
    return true;
  }

  return true; // Default: allow
}

// Audit logging
function logExecution(toolName, command, result) {
  const fs = require('fs-extra');
  const path = require('path');
  
  const logDir = path.join(process.env.WORK_DIR || './work', 'logs');
  fs.ensureDirSync(logDir);
  
  const logFile = path.join(logDir, `execution_${new Date().toISOString().split('T')[0]}.log`);
  const logEntry = {
    timestamp: new Date().toISOString(),
    tool: toolName,
    command,
    success: result.success,
    error: result.error,
  };
  
  fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
}

module.exports = {
  executeTool,
  executeNmap,
  executeSqlmap,
  executeNikto,
  executeMetasploit,
  executeNcat,
  validateCommand,
  logExecution,
};

