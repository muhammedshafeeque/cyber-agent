class AgentState {
  constructor() {
    this.currentPhase = 'initialization';
    this.target = null;
    this.discoveredVulnerabilities = [];
    this.installedTools = [];
    this.scanResults = [];
    this.rceGoal = false;
    this.rceAchieved = false;
    this.currentStep = 0;
    this.totalSteps = 0;
    this.decisionHistory = [];
  }

  setPhase(phase) {
    this.currentPhase = phase;
  }

  addVulnerability(vulnerability) {
    this.discoveredVulnerabilities.push(vulnerability);
  }

  addTool(tool) {
    this.installedTools.push(tool);
  }

  addScanResult(result) {
    this.scanResults.push(result);
  }

  recordDecision(decision, reasoning) {
    this.decisionHistory.push({
      decision,
      reasoning,
      timestamp: new Date().toISOString(),
      phase: this.currentPhase,
    });
  }

  setRCEGoal(value) {
    this.rceGoal = value;
  }

  setRCEAchieved(value) {
    this.rceAchieved = value;
  }

  incrementStep() {
    this.currentStep++;
  }

  getStateSummary() {
    return {
      phase: this.currentPhase,
      target: this.target,
      vulnerabilitiesFound: this.discoveredVulnerabilities.length,
      toolsInstalled: this.installedTools.length,
      scanResultsCount: this.scanResults.length,
      rceGoal: this.rceGoal,
      rceAchieved: this.rceAchieved,
      currentStep: this.currentStep,
      totalSteps: this.totalSteps,
    };
  }
}

module.exports = {
  AgentState,
};

