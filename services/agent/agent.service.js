const { AgentState } = require('../../models/agent.models');
const decisionService = require('./decision.service');
const planningService = require('./planning.service');
const memoryService = require('./memory.service');
const scannerService = require('../scanner.service');
const { chat } = require('../../config/mistral.config');
const logger = require('../../cli/utils/logger');
const chalk = require('chalk');

class AutonomousAgent {
  constructor(target, options = {}) {
    this.state = new AgentState();
    this.state.target = target;
    this.state.rceGoal = options.goal === 'rce' || options.goal === undefined;
    this.state.setPhase('initialization');
    this.options = options;
  }

  async start() {
    try {
      this.state.setPhase('reconnaissance');
      await this.executePhase();
    } catch (error) {
      logger.error('Agent error:', error);
      throw error;
    }
  }

  async executePhase() {
    while (!this.isGoalAchieved() && !this.shouldStop()) {
      const currentPhase = this.state.currentPhase;
      
      switch (currentPhase) {
        case 'reconnaissance':
          await this.reconnaissancePhase();
          break;
        case 'vulnerability_discovery':
          await this.vulnerabilityDiscoveryPhase();
          break;
        case 'research':
          await this.researchPhase();
          break;
        case 'tool_installation':
          await this.toolInstallationPhase();
          break;
        case 'exploitation':
          await this.exploitationPhase();
          break;
        case 'analysis':
          await this.analysisPhase();
          break;
        default:
          await this.decisionPhase();
      }
    }

    return this.generateReport();
  }

  async reconnaissancePhase() {
    logger.phase('RECONNAISSANCE', `Target: ${this.state.target}`);
    
    // Check knowledge graph for existing information
    logger.step('Checking knowledge graph for existing reconnaissance data...');
    const existingInfo = await memoryService.retrieveContext(this.state.target);
    
    if (!existingInfo || existingInfo.length === 0) {
      logger.step('No existing data found. Running initial reconnaissance scans...');
      // Run initial scans
      const scanResults = await scannerService.runReconnaissance(this.state.target);
      
      if (scanResults && scanResults.parsed) {
        logger.scanResult('Reconnaissance', {
          success: true,
          vulnerabilities: scanResults.parsed.vulnerabilities || [],
          ports: scanResults.parsed.ports || [],
          services: scanResults.parsed.services || [],
        });
      }
      
      this.state.addScanResult(scanResults);
      
      // Store in memory
      logger.step('Storing reconnaissance results in knowledge graph...');
      await memoryService.storeContext(this.state.target, 'reconnaissance', scanResults);
      logger.success('Reconnaissance phase completed');
    } else {
      logger.info('Using existing reconnaissance data from knowledge graph');
      this.state.addScanResult(existingInfo);
    }

    logger.step(`Moving to vulnerability discovery phase... (Step ${this.state.currentStep + 1})`);
    this.state.setPhase('vulnerability_discovery');
    this.state.incrementStep();
  }

  async vulnerabilityDiscoveryPhase() {
    logger.phase('VULNERABILITY DISCOVERY', `Step ${this.state.currentStep}`);
    
    const scanResults = this.state.scanResults[this.state.scanResults.length - 1];
    
    // Use AI to decide which tools to run
    logger.step('AI analyzing context to decide next actions...');
    const decision = await decisionService.decideNextAction(
      this.state,
      'vulnerability_discovery',
      scanResults
    );

    logger.decision(decision.action, decision.reasoning);
    this.state.recordDecision(decision.action, decision.reasoning);

    // Ensure recommendedTools is an array of strings
    let recommendedTools = [];
    if (decision.recommendedTools) {
      if (Array.isArray(decision.recommendedTools)) {
        recommendedTools = decision.recommendedTools.filter(t => typeof t === 'string');
      } else if (typeof decision.recommendedTools === 'string') {
        recommendedTools = [decision.recommendedTools];
      }
    }
    
    if (recommendedTools.length > 0) {
      logger.info(`Executing ${recommendedTools.length} tools: ${recommendedTools.join(', ')}`);
    } else {
      logger.warn('No tools recommended. Using default scan tools.');
      recommendedTools = ['nmap', 'nikto']; // Default tools
    }
    
    // Execute vulnerability scans with progressive strategy
    logger.separator();
    
    // Learn from previous attempts
    const { getPreviousLearnings, adaptStrategy, thinkBeforeAction } = require('../learning/adaptation.service');
    logger.step('Learning from previous attempts and planning...');
    
    const previousLearnings = await getPreviousLearnings(this.state.target, 10);
    const adaptations = await adaptStrategy(this.state.target, previousLearnings);
    
    // Get discovered services from scan results
    const discoveredServices = scanResults?.parsed?.services || [];
    const previousErrors = previousLearnings
      .filter(l => l.result && l.result.errors)
      .flatMap(l => l.result.errors.map(e => e.error));
    
    // Think before acting - plan simple actions first
    const plan = await thinkBeforeAction(this.state.target, discoveredServices, previousErrors);
    
    if (plan.simpleActions.length > 0) {
      logger.info(`Planning to start with ${plan.simpleActions.length} simple action(s) (~${plan.estimatedTime}s)`);
      plan.simpleActions.forEach(action => {
        logger.step(`  → ${action.action}: ${action.reason} (~${action.time}s)`);
      });
    }
    
    // Track scan attempts
    let attemptNumber = 0;
    let previousScanResults = null;
    let vulnResults = [];
    
    // Try progressive scanning: quick first, escalate if needed
    const maxAttempts = 2; // Quick + one deeper attempt
    
    while (attemptNumber < maxAttempts) {
      logger.info(`\n=== Scan Attempt ${attemptNumber + 1}/${maxAttempts} ===`);
      
      // Apply adaptations
      if (adaptations.skipTools.length > 0 && attemptNumber === 0) {
        logger.warn(`Skipping tools that previously failed: ${adaptations.skipTools.join(', ')}`);
        recommendedTools = recommendedTools.filter(t => !adaptations.skipTools.includes(t));
      }
      
      const currentResults = await scannerService.runVulnerabilityScans(
        this.state.target,
        attemptNumber === 0 ? recommendedTools : [], // Use recommended on first, auto-select on retry
        {
          attemptNumber,
          previousResults: previousScanResults,
          adaptations, // Pass adaptations to scanner
        }
      );
      
      vulnResults = vulnResults.concat(currentResults);
      
      // Check if we found vulnerabilities
      const hasVulnerabilities = currentResults.some(r => 
        r.vulnerabilities && r.vulnerabilities.length > 0
      );
      
      if (hasVulnerabilities && attemptNumber === 0) {
        logger.success('Quick scan found vulnerabilities - sufficient for now');
        break; // Found results on quick scan, stop early
      }
      
      if (hasVulnerabilities) {
        logger.success('Found vulnerabilities on deeper scan');
        break; // Found results, stop
      }
      
      // No vulnerabilities found - but check if we should stop scanning and analyze deeper
      if (attemptNumber === 0 && currentResults.length > 0) {
        // Even if no explicit vulnerabilities, analyze services for exploitation
        logger.step('No explicit vulnerabilities found, but analyzing services for RCE opportunities...');
        const { identifyServiceExploits } = require('../exploit/exploit-analyzer.service');
        const serviceExploits = await identifyServiceExploits(currentResults, this.state.target);
        
        if (serviceExploits.length > 0) {
          logger.success(`Found ${serviceExploits.length} RCE opportunity(ies) from service analysis`);
          serviceExploits.forEach(exp => {
            this.state.addVulnerability({
              type: 'rce_opportunity',
              description: exp.explanation,
              severity: 'critical',
              exploit: exp.exploit,
              metasploit_module: exp.metasploit_module,
              port: exp.port,
              service: exp.service,
            });
          });
          break; // Found opportunities, stop scanning and exploit
        }
      }
      
      // No results, try deeper scan only if we haven't tried already
      if (attemptNumber < maxAttempts - 1 && !this.state.discoveredVulnerabilities.some(v => v.exploit)) {
        logger.warn('No vulnerabilities found - escalating to deeper scan...');
        previousScanResults = currentResults;
        attemptNumber++;
      } else {
        // Already tried or found something, stop scanning
        logger.info('Stopping scan attempts - moving to exploitation');
        break;
      }
    }
    
    logger.separator();

    if (vulnResults && Array.isArray(vulnResults)) {
      vulnResults.forEach(result => {
        if (result.tool) {
          logger.scanResult(result.tool, result);
        }
      });
    }

    this.state.addScanResult(vulnResults);
    
    // Deep analysis: Extract vulnerabilities AND identify RCE opportunities
    logger.step('Analyzing scan results for vulnerabilities...');
    const vulnerabilities = await this.extractVulnerabilities(vulnResults);
    
    // Deep RCE analysis - analyze ALL scan results, not just recent ones
    logger.step('Performing deep RCE exploitation analysis on all scan results...');
    const { analyzeForRCE, identifyServiceExploits } = require('../exploit/exploit-analyzer.service');
    
    // Analyze all scan results for RCE opportunities
    const allScanResults = this.state.scanResults;
    const rceOpportunities = await analyzeForRCE(allScanResults.length > 0 ? allScanResults : vulnResults, this.state.target);
    
    // Also identify exploits from discovered services (even if no explicit vulnerabilities)
    logger.step('Identifying exploits from discovered services...');
    const serviceExploits = await identifyServiceExploits(allScanResults.length > 0 ? allScanResults : vulnResults, this.state.target);
    
    // Combine all RCE opportunities
    const allRCEOpportunities = [...rceOpportunities, ...serviceExploits];
    
    if (vulnerabilities.length > 0 || allRCEOpportunities.length > 0) {
      logger.success(`Found ${vulnerabilities.length} vulnerability(ies) and ${allRCEOpportunities.length} RCE opportunity(ies)`);
      
      // Add vulnerabilities
      vulnerabilities.forEach(v => {
        logger.vulnerability(v);
        this.state.addVulnerability(v);
      });
      
      // Add RCE opportunities as high-priority vulnerabilities (prioritize these!)
      allRCEOpportunities.forEach(opp => {
        logger.success(`  [RCE OPPORTUNITY] ${opp.service || opp.type} on port ${opp.port}`);
        logger.info(`    Exploit: ${opp.exploit || opp.metasploit_module || 'custom'}`);
        logger.info(`    Confidence: ${opp.confidence}`);
        if (opp.steps && opp.steps.length > 0) {
          logger.step(`    Steps: ${opp.steps[0]}${opp.steps.length > 1 ? '...' : ''}`);
        }
        
        this.state.addVulnerability({
          type: opp.type || 'rce_opportunity',
          description: opp.explanation || `RCE opportunity via ${opp.service}`,
          severity: 'critical',
          service: opp.service,
          port: opp.port,
          exploit: opp.exploit || opp.metasploit_module,
          cve: opp.cve,
          confidence: opp.confidence,
          steps: opp.steps,
          metasploit_module: opp.metasploit_module,
        });
      });
      
      // If we have RCE opportunities, go straight to exploitation - DON'T KEEP SCANNING!
      if (allRCEOpportunities.length > 0 && this.state.rceGoal) {
        logger.success(`🎯 ${allRCEOpportunities.length} RCE opportunity(ies) found - moving directly to exploitation phase`);
        logger.warn('Stopping further scans - focusing on exploitation');
        this.state.setPhase('exploitation');
      } else if (vulnerabilities.length > 0) {
        logger.step('Moving to research phase to gather exploit information...');
        this.state.setPhase('research');
      }
    } else {
      logger.info('No vulnerabilities or RCE opportunities found in this scan.');
      
      // If we've done multiple scans with no results, stop looping
      if (this.state.currentStep > 5) {
        logger.warn('Multiple scans completed with no findings - stopping scan loop');
        this.state.setPhase('complete');
      } else {
        logger.step('Moving to analysis phase...');
        this.state.setPhase('analysis');
      }
    }
    
    this.state.incrementStep();
  }

  async researchPhase() {
    logger.phase('RESEARCH', `Analyzing ${this.state.discoveredVulnerabilities.length} vulnerabilities`);
    
    const vulnerabilities = this.state.discoveredVulnerabilities;
    
    // Research each vulnerability
    logger.step(`Researching ${vulnerabilities.length} discovered vulnerabilities...`);
    for (let i = 0; i < vulnerabilities.length; i++) {
      const vuln = vulnerabilities[i];
      logger.info(`Researching vulnerability ${i + 1}/${vulnerabilities.length}: ${vuln.type}`);
      
      const researchResults = await decisionService.researchVulnerability(vuln);
      
      if (researchResults && researchResults.exploits) {
        logger.info(`  Found ${researchResults.exploits.length} potential exploit(s)`);
      }
      if (researchResults && researchResults.tools) {
        logger.info(`  Recommended tools: ${researchResults.tools.join(', ')}`);
      }
      
      // Store research results
      await memoryService.storeResearch(vuln, researchResults);
    }

    // Check if we have RCE opportunities
    const rceOpportunities = vulnerabilities.filter(v => 
      v.type.toLowerCase().includes('command') ||
      v.type.toLowerCase().includes('rce') ||
      v.type.toLowerCase().includes('code execution') ||
      v.type.toLowerCase().includes('file upload') ||
      v.type.toLowerCase().includes('deserialization')
    );

    if (rceOpportunities.length > 0) {
      logger.success(`Identified ${rceOpportunities.length} RCE opportunity(ies)`);
      if (this.state.rceGoal) {
        logger.step('Moving to exploitation phase...');
        this.state.setPhase('exploitation');
      } else {
        logger.step('RCE goal not enabled. Moving to tool installation...');
        this.state.setPhase('tool_installation');
      }
    } else {
      logger.info('No direct RCE opportunities found.');
      logger.step('Moving to tool installation phase...');
      this.state.setPhase('tool_installation');
    }

    this.state.incrementStep();
  }

  async toolInstallationPhase() {
    logger.phase('TOOL INSTALLATION', `Preparing tools for exploitation`);
    
    logger.step('AI determining required tools...');
    const decision = await decisionService.decideToolsNeeded(this.state);
    const toolsNeeded = decision.tools || [];

    if (toolsNeeded.length === 0) {
      logger.info('No additional tools needed.');
    } else {
      logger.info(`Installing/checking ${toolsNeeded.length} tool(s): ${toolsNeeded.join(', ')}`);
    }

    for (let i = 0; i < toolsNeeded.length; i++) {
      const toolName = toolsNeeded[i];
      logger.tool('Install', `Checking ${toolName}`, `(${i + 1}/${toolsNeeded.length})`);
      
      // Check if tool exists, install if needed
      const toolStatus = await this.checkAndInstallTool(toolName);
      if (toolStatus.installed || toolStatus.available) {
        logger.success(`${toolName} ${toolStatus.installed ? 'installed' : 'available'}`);
        this.state.addTool(toolStatus);
      } else {
        logger.warn(`${toolName} not available and could not be installed`);
      }
    }

    logger.step('Moving to exploitation phase...');
    this.state.setPhase('exploitation');
    this.state.incrementStep();
  }

  async exploitationPhase() {
    logger.phase('EXPLOITATION', 'Attempting RCE');
    
    // Prioritize vulnerabilities with known exploits and RCE opportunities
    const vulnerabilities = this.state.discoveredVulnerabilities.filter(v => 
      this.canLeadToRCE(v) || v.exploit || v.metasploit_module
    );
    
    // Sort by confidence and exploit availability
    vulnerabilities.sort((a, b) => {
      if (a.metasploit_module && !b.metasploit_module) return -1;
      if (b.metasploit_module && !a.metasploit_module) return 1;
      if (a.confidence === 'high' && b.confidence !== 'high') return -1;
      if (b.confidence === 'high' && a.confidence !== 'high') return 1;
      return 0;
    });
    
    if (vulnerabilities.length === 0) {
      logger.warn('No RCE-capable vulnerabilities found for exploitation.');
      logger.step('Re-analyzing scan results for missed opportunities...');
      
      // Try deep analysis again on latest scan results
      const latestScans = this.state.scanResults.slice(-3); // Last 3 scans
      if (latestScans.length > 0) {
        const { analyzeForRCE } = require('../exploit/exploit-analyzer.service');
        const newOpportunities = await analyzeForRCE(latestScans, this.state.target);
        
        if (newOpportunities.length > 0) {
          logger.success(`Found ${newOpportunities.length} additional RCE opportunity(ies) from deep analysis`);
          newOpportunities.forEach(opp => {
            this.state.addVulnerability({
              type: opp.type,
              description: opp.explanation,
              severity: 'critical',
              exploit: opp.exploit,
              metasploit_module: opp.metasploit_module,
              port: opp.port,
              service: opp.service,
            });
          });
          // Retry exploitation with new opportunities
          return await this.exploitationPhase();
        }
      }
      
      this.state.setPhase('analysis');
      this.state.incrementStep();
      return;
    }
    
    logger.info(`Attempting exploitation on ${vulnerabilities.length} vulnerability(ies) (prioritized by exploit availability)...`);
    
    for (let i = 0; i < vulnerabilities.length; i++) {
      const vuln = vulnerabilities[i];
      
      logger.tool('Exploit', `Attempting RCE via ${vuln.type || vuln.service}`, 
        vuln.metasploit_module ? `(${i + 1}/${vulnerabilities.length}) - Metasploit: ${vuln.metasploit_module}` : 
        `(${i + 1}/${vulnerabilities.length})`);
      
      // Show exploitation steps if available
      if (vuln.steps && vuln.steps.length > 0) {
        logger.info(`Exploitation steps:`);
        vuln.steps.forEach((step, idx) => {
          logger.step(`  ${idx + 1}. ${step}`);
        });
      }
      
      if (this.state.rceGoal) {
        const exploitResult = await scannerService.attemptRCE(this.state.target, vuln);
        
        if (exploitResult.success) {
          this.state.setRCEAchieved(true);
          logger.success('🎯 RCE ACHIEVED!', exploitResult);
          logger.separator();
          break;
        } else {
          logger.warn(`Exploitation attempt ${i + 1} failed: ${exploitResult.error || 'Unknown error'}`);
          
          // Learn from failure and adapt
          if (vuln.metasploit_module && exploitResult.error) {
            logger.step('Trying alternative exploitation method...');
            // Could try different payload or exploit variant here
          }
        }
      }
    }

    if (!this.state.rceAchieved) {
      logger.info('RCE not achieved in this phase.');
      logger.step('Reviewing results for additional exploitation paths...');
    }
    
    logger.step('Moving to analysis phase...');
    this.state.setPhase('analysis');
    this.state.incrementStep();
  }

  async analysisPhase() {
    logger.phase('ANALYSIS', `Step ${this.state.currentStep}`);
    
    logger.info(`Current status:
  - Vulnerabilities found: ${this.state.discoveredVulnerabilities.length}
  - Tools installed: ${this.state.installedTools.length}
  - RCE Goal: ${this.state.rceGoal ? 'Yes' : 'No'}
  - RCE Achieved: ${this.state.rceAchieved ? chalk.green('YES ✓') : chalk.red('No ✗')}
  - Total steps: ${this.state.currentStep}`);
    
    logger.step('AI analyzing current state and deciding next steps...');
    const analysis = await decisionService.analyzeCurrentState(this.state);
    
    if (analysis.recommendation) {
      logger.info(`AI Recommendation: ${analysis.recommendation.substring(0, 300)}`);
    }
    
    if (analysis.shouldContinue && !this.state.rceAchieved) {
      logger.step('Continuing testing. Moving back to vulnerability discovery...');
      logger.separator();
      this.state.setPhase('vulnerability_discovery');
    } else {
      logger.success('Testing cycle complete.');
      if (this.state.rceAchieved) {
        logger.success('🎯 RCE Goal Achieved!');
      }
      this.state.setPhase('complete');
    }

    this.state.incrementStep();
  }

  async decisionPhase() {
    const decision = await decisionService.decideNextAction(this.state);
    this.state.recordDecision(decision.action, decision.reasoning);
    
    // Execute decision
    this.state.setPhase(decision.nextPhase || 'analysis');
    this.state.incrementStep();
  }

  async checkAndInstallTool(toolName) {
    const toolManager = require('../tools/tool-registry.service');
    return await toolManager.ensureToolAvailable(toolName);
  }

  async extractVulnerabilities(scanResults) {
    const analyzer = require('../analyzer.service');
    return await analyzer.extractVulnerabilities(scanResults);
  }

  canLeadToRCE(vulnerability) {
    const rceKeywords = [
      'command injection',
      'code execution',
      'rce',
      'file upload',
      'deserialization',
      'eval',
      'exec',
      'system',
    ];

    const vulnType = vulnerability.type.toLowerCase();
    const vulnDesc = (vulnerability.description || '').toLowerCase();

    return rceKeywords.some(keyword => 
      vulnType.includes(keyword) || vulnDesc.includes(keyword)
    );
  }

  isGoalAchieved() {
    if (this.state.rceGoal) {
      return this.state.rceAchieved;
    }
    return this.state.discoveredVulnerabilities.length > 0;
  }

  shouldStop() {
    return this.state.currentStep > 100 || // Max steps
           this.state.currentPhase === 'complete';
  }

  generateReport() {
    return {
      target: this.state.target,
      goal: this.state.rceGoal ? 'RCE' : 'Vulnerability Discovery',
      achieved: this.state.rceGoal ? this.state.rceAchieved : this.state.discoveredVulnerabilities.length > 0,
      vulnerabilities: this.state.discoveredVulnerabilities,
      toolsUsed: this.state.installedTools,
      scanResults: this.state.scanResults,
      decisions: this.state.decisionHistory,
      summary: this.state.getStateSummary(),
    };
  }
}

module.exports = AutonomousAgent;


