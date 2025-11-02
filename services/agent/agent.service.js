const { AgentState } = require('../../models/agent.models');
const decisionService = require('./decision.service');
const planningService = require('./planning.service');
const memoryService = require('./memory.service');
const scannerService = require('../scanner.service');
const { chat } = require('../../config/mistral.config');

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
      console.error('Agent error:', error);
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
    console.log('[Agent] Starting reconnaissance phase...');
    
    // Check knowledge graph for existing information
    const existingInfo = await memoryService.retrieveContext(this.state.target);
    
    if (!existingInfo || existingInfo.length === 0) {
      // Run initial scans
      const scanResults = await scannerService.runReconnaissance(this.state.target);
      this.state.addScanResult(scanResults);
      
      // Store in memory
      await memoryService.storeContext(this.state.target, 'reconnaissance', scanResults);
    } else {
      console.log('[Agent] Using existing reconnaissance data');
      this.state.addScanResult(existingInfo);
    }

    this.state.setPhase('vulnerability_discovery');
    this.state.incrementStep();
  }

  async vulnerabilityDiscoveryPhase() {
    console.log('[Agent] Starting vulnerability discovery phase...');
    
    const scanResults = this.state.scanResults[this.state.scanResults.length - 1];
    
    // Use AI to decide which tools to run
    const decision = await decisionService.decideNextAction(
      this.state,
      'vulnerability_discovery',
      scanResults
    );

    this.state.recordDecision(decision.action, decision.reasoning);

    // Execute vulnerability scans
    const vulnResults = await scannerService.runVulnerabilityScans(
      this.state.target,
      decision.recommendedTools
    );

    this.state.addScanResult(vulnResults);
    
    // Extract vulnerabilities
    const vulnerabilities = await this.extractVulnerabilities(vulnResults);
    vulnerabilities.forEach(v => this.state.addVulnerability(v));

    if (vulnerabilities.length > 0) {
      this.state.setPhase('research');
    } else {
      this.state.setPhase('analysis');
    }
    
    this.state.incrementStep();
  }

  async researchPhase() {
    console.log('[Agent] Starting research phase...');
    
    const vulnerabilities = this.state.discoveredVulnerabilities;
    
    // Research each vulnerability
    for (const vuln of vulnerabilities) {
      const researchResults = await decisionService.researchVulnerability(vuln);
      
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

    if (rceOpportunities.length > 0 && this.state.rceGoal) {
      this.state.setPhase('exploitation');
    } else {
      this.state.setPhase('tool_installation');
    }

    this.state.incrementStep();
  }

  async toolInstallationPhase() {
    console.log('[Agent] Starting tool installation phase...');
    
    const decision = await decisionService.decideToolsNeeded(this.state);
    const toolsNeeded = decision.tools || [];

    for (const toolName of toolsNeeded) {
      // Check if tool exists, install if needed
      const toolStatus = await this.checkAndInstallTool(toolName);
      if (toolStatus.installed || toolStatus.available) {
        this.state.addTool(toolStatus);
      }
    }

    this.state.setPhase('exploitation');
    this.state.incrementStep();
  }

  async exploitationPhase() {
    console.log('[Agent] Starting exploitation phase...');
    
    const vulnerabilities = this.state.discoveredVulnerabilities;
    
    for (const vuln of vulnerabilities) {
      if (this.state.rceGoal && this.canLeadToRCE(vuln)) {
        const exploitResult = await scannerService.attemptRCE(this.state.target, vuln);
        
        if (exploitResult.success) {
          this.state.setRCEAchieved(true);
          console.log('[Agent] RCE achieved!');
          break;
        }
      }
    }

    this.state.setPhase('analysis');
    this.state.incrementStep();
  }

  async analysisPhase() {
    console.log('[Agent] Starting analysis phase...');
    
    const analysis = await decisionService.analyzeCurrentState(this.state);
    
    if (analysis.shouldContinue && !this.state.rceAchieved) {
      this.state.setPhase('vulnerability_discovery');
    } else {
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

