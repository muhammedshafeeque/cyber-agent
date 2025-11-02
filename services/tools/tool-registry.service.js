const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs-extra');
const path = require('path');
const shell = require('shelljs');

const execAsync = promisify(exec);

// Common Kali Linux tool paths
const KALI_TOOL_PATHS = [
  '/usr/bin',
  '/usr/sbin',
  '/usr/local/bin',
  '/opt',
  '/usr/share',
];

// Common Kali tools
const KALI_TOOLS = [
  'nmap', 'metasploit', 'msfconsole', 'sqlmap', 'nikto', 'dirb', 'gobuster',
  'burpsuite', 'aircrack-ng', 'john', 'hashcat', 'hydra', 'ncat', 'nc',
  'wireshark', 'tcpdump', 'ettercap', 'wpscan', 'searchsploit',
];

async function detectKaliLinux() {
  try {
    // Check for Kali-specific files
    const kaliIndicator = await fs.pathExists('/etc/os-release');
    if (kaliIndicator) {
      const content = await fs.readFile('/etc/os-release', 'utf-8');
      return content.includes('Kali') || content.includes('kali');
    }
    
    // Check for Kali tools directory
    const kaliToolsExists = await fs.pathExists('/usr/share/kali');
    return kaliToolsExists;
  } catch (error) {
    return false;
  }
}

async function findToolInSystem(toolName) {
  // Ensure toolName is a string
  if (typeof toolName !== 'string') {
    console.error(`[Tool Registry] Invalid toolName type: ${typeof toolName}`, toolName);
    return {
      name: String(toolName),
      path: null,
      available: false,
      isKali: false,
      version: null,
    };
  }
  
  try {
    // Check PATH
    const { stdout } = await execAsync(`which ${toolName}`);
    if (stdout && stdout.trim()) {
      return {
        name: toolName,
        path: stdout.trim(),
        available: true,
        isKali: await isKaliTool(toolName, stdout.trim()),
        version: await getToolVersion(toolName, stdout.trim()),
      };
    }
  } catch (error) {
    // Tool not in PATH, continue checking
  }

  // Check Kali-specific paths
  for (const kaliPath of KALI_TOOL_PATHS) {
    const toolPath = path.join(kaliPath, toolName);
    try {
      const exists = await fs.pathExists(toolPath);
      if (exists) {
        const stats = await fs.stat(toolPath);
        if (stats.isFile() && (stats.mode & parseInt('111', 8))) { // Executable
          return {
            name: toolName,
            path: toolPath,
            available: true,
            isKali: true,
            version: await getToolVersion(toolName, toolPath),
          };
        }
      }
    } catch (error) {
      // Continue searching
    }
  }

  return {
    name: toolName,
    path: null,
    available: false,
    isKali: false,
    version: null,
  };
}

async function isKaliTool(toolName, toolPath) {
  if (KALI_TOOLS.includes(toolName)) {
    return true;
  }

  // Check if path contains kali
  if (toolPath && toolPath.includes('kali')) {
    return true;
  }

  // Check common Kali directories
  return KALI_TOOL_PATHS.some(kaliPath => toolPath && toolPath.startsWith(kaliPath));
}

async function getToolVersion(toolName, toolPath) {
  try {
    // Try common version flags
    const versionFlags = ['--version', '-v', '-V', 'version'];
    
    for (const flag of versionFlags) {
      try {
        const { stdout } = await execAsync(`${toolPath || toolName} ${flag} 2>&1 | head -1`);
        if (stdout && stdout.trim()) {
          // Extract version number
          const versionMatch = stdout.match(/[\d]+\.[\d]+(?:\.[\d]+)?/);
          if (versionMatch) {
            return versionMatch[0];
          }
          return stdout.trim().substring(0, 50);
        }
      } catch (error) {
        // Try next flag
      }
    }

    // Try parsing from tool itself
    if (toolName === 'nmap') {
      try {
        const { stdout } = await execAsync('nmap --version 2>&1');
        const versionMatch = stdout.match(/Nmap version ([\d.]+)/);
        return versionMatch ? versionMatch[1] : null;
      } catch (error) {}
    }

    return null;
  } catch (error) {
    return null;
  }
}

async function ensureToolAvailable(toolName) {
  const toolStatus = await findToolInSystem(toolName);
  
  if (toolStatus.available) {
    return {
      ...toolStatus,
      installed: true,
      needsUpdate: false,
    };
  }

  // Tool not found, attempt installation
  const installer = require('./tool-installer.service');
  const installResult = await installer.installTool(toolName);
  
  if (installResult.success) {
    // Re-check after installation
    const newStatus = await findToolInSystem(toolName);
    return {
      ...newStatus,
      installed: true,
      needsUpdate: false,
    };
  }

  return {
    ...toolStatus,
    installed: false,
    error: installResult.error,
  };
}

async function checkToolUpdate(toolName, currentVersion) {
  try {
    // Check if tool is from package manager
    const toolStatus = await findToolInSystem(toolName);
    
    if (toolStatus.isKali || toolStatus.path?.includes('/usr/bin')) {
      // Check apt updates for Kali/Ubuntu
      try {
        const { stdout } = await execAsync(`apt-cache madison ${toolName} 2>&1 | head -1`);
        if (stdout) {
          const versionMatch = stdout.match(/\s+([\d.]+)/);
          const latestVersion = versionMatch ? versionMatch[1] : null;
          
          if (latestVersion && latestVersion !== currentVersion) {
            return {
              needsUpdate: true,
              currentVersion,
              latestVersion,
              updateMethod: 'apt',
            };
          }
        }
      } catch (error) {
        // Not in apt, continue
      }
    }

    // For pip tools
    if (toolName.includes('-') || toolName.includes('_')) {
      try {
        const { stdout } = await execAsync(`pip index versions ${toolName} 2>&1 | grep -i available`);
        if (stdout) {
          const versionMatch = stdout.match(/\(([\d.]+)\)/);
          const latestVersion = versionMatch ? versionMatch[1] : null;
          
          if (latestVersion && latestVersion !== currentVersion) {
            return {
              needsUpdate: true,
              currentVersion,
              latestVersion,
              updateMethod: 'pip',
            };
          }
        }
      } catch (error) {
        // Not in pip, continue
      }
    }

    return {
      needsUpdate: false,
      currentVersion,
    };
  } catch (error) {
    console.error(`Error checking update for ${toolName}:`, error);
    return {
      needsUpdate: false,
      currentVersion,
      error: error.message,
    };
  }
}

function isCLITool(toolName) {
  // GUI tools that require manual interaction
  const guiTools = ['burpsuite', 'burp', 'owasp-zap', 'wireshark'];
  
  return !guiTools.some(gui => toolName.toLowerCase().includes(gui.toLowerCase()));
}

module.exports = {
  detectKaliLinux,
  findToolInSystem,
  ensureToolAvailable,
  checkToolUpdate,
  isCLITool,
  KALI_TOOLS,
};

