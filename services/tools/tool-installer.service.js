const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs-extra');
const path = require('path');
const shell = require('shelljs');
const researchService = require('../research/research.service');
const scraperService = require('../research/scraper.service');
const learningService = require('../research/learning.service');

const execAsync = promisify(exec);

async function installTool(toolName) {
  try {
    // First, try to find installation instructions
    const installInfo = await findInstallationMethod(toolName);
    
    if (!installInfo) {
      return {
        success: false,
        error: `Could not determine installation method for ${toolName}`,
      };
    }

    // Execute installation based on method
    switch (installInfo.method) {
      case 'apt':
        return await installViaApt(toolName);
      case 'pip':
        return await installViaPip(toolName);
      case 'npm':
        return await installViaNpm(toolName);
      case 'gem':
        return await installViaGem(toolName);
      case 'cargo':
        return await installViaCargo(toolName);
      case 'git':
        return await installViaGit(installInfo.gitUrl, toolName);
      default:
        return {
          success: false,
          error: `Unknown installation method: ${installInfo.method}`,
        };
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

async function findInstallationMethod(toolName) {
  // Check common package managers first
  const quickChecks = [
    { method: 'apt', command: `apt-cache search ${toolName}` },
    { method: 'pip', command: `pip search ${toolName} 2>&1` },
  ];

  for (const check of quickChecks) {
    try {
      const { stdout } = await execAsync(check.command);
      if (stdout && stdout.toLowerCase().includes(toolName.toLowerCase())) {
        return { method: check.method };
      }
    } catch (error) {
      // Continue to next method
    }
  }

  // Research online for installation instructions
  const researchResults = await researchService.researchTools(toolName);
  
  for (const result of researchResults.tools || []) {
    if (result.url && result.url.includes('github.com')) {
      // Fetch README
      const readme = await scraperService.parseReadme(result.url);
      if (readme) {
        const instructions = await scraperService.extractInstallationInstructions(readme.content);
        
        if (instructions.installCommands.length > 0) {
          const firstCommand = instructions.installCommands[0];
          
          // Detect method from command
          if (firstCommand.includes('pip install')) {
            return { method: 'pip', gitUrl: result.url };
          } else if (firstCommand.includes('npm install')) {
            return { method: 'npm', gitUrl: result.url };
          } else if (firstCommand.includes('gem install')) {
            return { method: 'gem', gitUrl: result.url };
          } else if (firstCommand.includes('cargo install')) {
            return { method: 'cargo', gitUrl: result.url };
          } else if (firstCommand.includes('git clone')) {
            const gitMatch = firstCommand.match(/git clone\s+(https?:\/\/[^\s]+)/);
            return { method: 'git', gitUrl: gitMatch ? gitMatch[1] : result.url };
          } else if (firstCommand.includes('apt install')) {
            const aptMatch = firstCommand.match(/apt install\s+([^\s]+)/);
            return { method: 'apt', packageName: aptMatch ? aptMatch[1] : toolName };
          }
        }
      }
    }
  }

  // Default: try git clone from GitHub
  return {
    method: 'git',
    gitUrl: `https://github.com/search?q=${toolName}`,
  };
}

async function installViaApt(toolName) {
  try {
    // Check if sudo is needed
    const needsSudo = process.getuid && process.getuid() !== 0;
    const sudo = needsSudo ? 'sudo ' : '';
    
    const { stdout, stderr } = await execAsync(`${sudo}apt install -y ${toolName}`);
    
    return {
      success: !stderr || !stderr.includes('error'),
      output: stdout,
      method: 'apt',
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      method: 'apt',
    };
  }
}

async function installViaPip(toolName) {
  try {
    const { stdout, stderr } = await execAsync(`pip install ${toolName}`);
    
    return {
      success: !stderr || !stderr.includes('error'),
      output: stdout,
      method: 'pip',
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      method: 'pip',
    };
  }
}

async function installViaNpm(toolName) {
  try {
    const { stdout, stderr } = await execAsync(`npm install -g ${toolName}`);
    
    return {
      success: !stderr || !stderr.includes('error'),
      output: stdout,
      method: 'npm',
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      method: 'npm',
    };
  }
}

async function installViaGem(toolName) {
  try {
    const { stdout, stderr } = await execAsync(`gem install ${toolName}`);
    
    return {
      success: !stderr || !stderr.includes('error'),
      output: stdout,
      method: 'gem',
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      method: 'gem',
    };
  }
}

async function installViaCargo(toolName) {
  try {
    const { stdout, stderr } = await execAsync(`cargo install ${toolName}`);
    
    return {
      success: !stderr || !stderr.includes('error'),
      output: stdout,
      method: 'cargo',
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      method: 'cargo',
    };
  }
}

async function installViaGit(gitUrl, toolName) {
  try {
    const installDir = path.join(process.env.WORK_DIR || './work', 'tools', toolName);
    await fs.ensureDir(installDir);

    // Clone repository
    const { stdout, stderr } = await execAsync(`git clone ${gitUrl} ${installDir}`);
    
    if (stderr && !stderr.includes('Cloning')) {
      return {
        success: false,
        error: stderr,
        method: 'git',
      };
    }

    // Check for installation script
    const packageJson = path.join(installDir, 'package.json');
    const setupPy = path.join(installDir, 'setup.py');
    const requirements = path.join(installDir, 'requirements.txt');

    if (await fs.pathExists(packageJson)) {
      // npm install
      const { stdout: npmOut } = await execAsync(`cd ${installDir} && npm install`);
      return {
        success: true,
        output: npmOut,
        method: 'git+npm',
        installPath: installDir,
      };
    } else if (await fs.pathExists(setupPy)) {
      // pip install
      const { stdout: pipOut } = await execAsync(`cd ${installDir} && pip install .`);
      return {
        success: true,
        output: pipOut,
        method: 'git+pip',
        installPath: installDir,
      };
    } else if (await fs.pathExists(requirements)) {
      // pip install requirements
      const { stdout: pipOut } = await execAsync(`cd ${installDir} && pip install -r requirements.txt`);
      return {
        success: true,
        output: pipOut,
        method: 'git+pip',
        installPath: installDir,
      };
    }

    return {
      success: true,
      output: stdout,
      method: 'git',
      installPath: installDir,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      method: 'git',
    };
  }
}

async function updateTool(toolName, updateMethod) {
  switch (updateMethod) {
    case 'apt':
      return await installViaApt(toolName); // apt install updates
    case 'pip':
      return await execAsync(`pip install --upgrade ${toolName}`);
    case 'npm':
      return await execAsync(`npm update -g ${toolName}`);
    case 'git':
      // For git, need to pull and reinstall
      const installDir = path.join(process.env.WORK_DIR || './work', 'tools', toolName);
      if (await fs.pathExists(installDir)) {
        await execAsync(`cd ${installDir} && git pull`);
        // Re-run install if needed
      }
      return { success: true, method: 'git' };
    default:
      return { success: false, error: 'Unknown update method' };
  }
}

module.exports = {
  installTool,
  updateTool,
  findInstallationMethod,
};

