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
    
    // Execute vulnerability scans
    logger.separator();
    const vulnResults = await scannerService.runVulnerabilityScans(
      this.state.target,
      recommendedTools
    );

    if (vulnResults && Array.isArray(vulnResults)) {
      vulnResults.forEach(result => {
        if (result.tool) {
          logger.scanResult(result.tool, result);
        }
      });
    }

    this.state.addScanResult(vulnResults);
    
    // Extract vulnerabilities
    logger.step('Analyzing scan results for vulnerabilities...');
    const vulnerabilities = await this.extractVulnerabilities(vulnResults);
    
    if (vulnerabilities.length > 0) {
      logger.success(`Found ${vulnerabilities.length} vulnerability(ies):`);
      vulnerabilities.forEach(v => {
        logger.vulnerability(v);
        this.state.addVulnerability(v);
      });
      logger.step('Moving to research phase to gather exploit information...');
      this.state.setPhase('research');
    } else {
      logger.info('No vulnerabilities found in this scan.');
      logger.step('Moving to analysis phase...');
      this.state.setPhase('analysis');
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
    
    const vulnerabilities = this.state.discoveredVulnerabilities.filter(v => 
      this.canLeadToRCE(v)
    );
    
    if (vulnerabilities.length === 0) {
      logger.warn('No RCE-capable vulnerabilities found for exploitation.');
      this.state.setPhase('analysis');
      this.state.incrementStep();
      return;
    }
    
    logger.info(`Attempting exploitation on ${vulnerabilities.length} vulnerability(ies)...`);
    
    for (let i = 0; i < vulnerabilities.length; i++) {
      const vuln = vulnerabilities[i];
      logger.tool('Exploit', `Attempting RCE via ${vuln.type}`, `(${i + 1}/${vulnerabilities.length})`);
      
      if (this.state.rceGoal) {
        const exploitResult = await scannerService.attemptRCE(this.state.target, vuln);
        
        if (exploitResult.success) {
          this.state.setRCEAchieved(true);
          logger.success('🎯 RCE ACHIEVED!', exploitResult);
          logger.separator();
          break;
        } else {
          logger.warn(`Exploitation attempt ${i + 1} failed: ${exploitResult.error || 'Unknown error'}`);
        }
      }
    }

    if (!this.state.rceAchieved) {
      logger.info('RCE not achieved in this phase.');
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


