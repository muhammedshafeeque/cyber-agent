const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const toolRegistry = require('./tool-registry.service');
const logger = require('../../cli/utils/logger');

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
    
    // Show command being executed
    logger.tool('CMD', `Executing: ${command}`);
    logger.separator();
    
    // Execute with streaming output (real-time)
    const timeout = options.timeout || 300000; // 5 minutes default
    
    return await executeWithStream(toolName, toolStatus.path || toolName, args, {
      ...options,
      timeout,
      command,
    });
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

async function executeWithStream(toolName, executable, args, options = {}) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let output = '';
    
    // Spawn process
    const proc = spawn(executable, args, {
      shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    
    // Stream stdout
    proc.stdout.on('data', (data) => {
      const text = data.toString();
      stdout += text;
      output += text;
      // Display in real-time
      process.stdout.write(text);
    });
    
    // Stream stderr
    proc.stderr.on('data', (data) => {
      const text = data.toString();
      stderr += text;
      output += text;
      // Display in real-time (stderr in yellow)
      process.stdout.write(`\x1b[33m${text}\x1b[0m`); // Yellow for stderr
    });
    
    // Handle completion
    proc.on('close', (code) => {
      logger.separator();
      
      const result = {
        success: code === 0,
        tool: toolName,
        command: options.command || `${executable} ${args.join(' ')}`,
        stdout,
        stderr,
        output,
        exitCode: code,
      };
      
      if (code === 0) {
        logger.success(`Command completed successfully (exit code: ${code})`);
      } else {
        logger.warn(`Command exited with code ${code}`);
      }
      
      // Log execution
      logExecution(toolName, result.command, result);
      
      resolve(result);
    });
    
    // Handle errors
    proc.on('error', (error) => {
      logger.error(`Command execution error: ${error.message}`);
      
      const result = {
        success: false,
        tool: toolName,
        command: options.command || `${executable} ${args.join(' ')}`,
        error: error.message,
        stdout,
        stderr,
        output,
      };
      
      logExecution(toolName, result.command, result);
      resolve(result);
    });
    
    // Handle timeout
    if (options.timeout) {
      setTimeout(() => {
        if (!proc.killed) {
          proc.kill('SIGTERM');
          logger.warn(`Command timed out after ${options.timeout}ms`);
          
          const result = {
            success: false,
            tool: toolName,
            command: options.command || `${executable} ${args.join(' ')}`,
            error: 'Command timeout',
            stdout,
            stderr,
            output,
          };
          
          logExecution(toolName, result.command, result);
          resolve(result);
        }
      }, options.timeout);
    }
  });
}

async function executeNmap(target, options = {}) {
  const args = [];
  
  if (options.ports) {
    args.push(`-p`);
    args.push(options.ports);
  } else {
    args.push('-p-'); // All ports
  }

  if (options.serviceVersion) {
    args.push('-sV');
  }

  if (options.script) {
    args.push(`--script`);
    args.push(options.script);
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

  args.push('-u');
  args.push(url);

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
  executeWithStream,
  validateCommand,
  logExecution,
};

