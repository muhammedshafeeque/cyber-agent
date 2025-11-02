const { v4: uuidv4 } = require('uuid');

function createApplication(name, url, description = '') {
  return {
    _key: uuidv4(),
    name,
    url,
    description,
    createdAt: new Date().toISOString(),
    type: 'application',
  };
}

function createVulnerability(type, description, severity = 'medium', cve = null) {
  return {
    _key: uuidv4(),
    type,
    description,
    severity,
    cve,
    discoveredAt: new Date().toISOString(),
    type: 'vulnerability',
  };
}

function createTool(name, version, installationMethod, path = null, isKali = false) {
  return {
    _key: uuidv4(),
    name,
    version,
    installationMethod,
    path,
    isKali,
    installedAt: new Date().toISOString(),
    type: 'tool',
  };
}

function createScan(target, scanType, status = 'running') {
  return {
    _key: uuidv4(),
    target,
    scanType,
    status,
    startedAt: new Date().toISOString(),
    type: 'scan',
  };
}

function createExploit(name, code, vulnerabilityType, language = 'python') {
  return {
    _key: uuidv4(),
    name,
    code,
    vulnerabilityType,
    language,
    createdAt: new Date().toISOString(),
    type: 'exploit',
  };
}

function createCVEEntry(cveId, description, severity, publishedDate) {
  return {
    _key: cveId.replace('CVE-', '').replace('-', '_'),
    cveId,
    description,
    severity,
    publishedDate,
    type: 'cve',
  };
}

function createTechnique(name, description, phase, tactic) {
  return {
    _key: uuidv4(),
    name,
    description,
    phase,
    tactic,
    type: 'technique',
  };
}

function createAgentMemory(action, reasoning, context, result = null) {
  return {
    _key: uuidv4(),
    action,
    reasoning,
    context,
    result,
    timestamp: new Date().toISOString(),
    type: 'agent_memory',
  };
}

function createResearchSource(url) {
  return {
    _key: uuidv4(),
    url,
    accessedAt: new Date().toISOString(),
    type: 'research_source',
  };
}

module.exports = {
  createApplication,
  createVulnerability,
  createTool,
  createScan,
  createExploit,
  createCVEEntry,
  createTechnique,
  createAgentMemory,
  createResearchSource,
};

