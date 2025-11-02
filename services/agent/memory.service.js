const { createDocument, queryAQL, getDB } = require('../graph.service');
const { createAgentMemory } = require('../../models/graph.models');

async function storeDecision(action, reasoning, context, result = null) {
  try {
    const memory = createAgentMemory(action, reasoning, context, result);
    return await createDocument('agent_memory', memory);
  } catch (error) {
    console.error('Error storing decision:', error);
    return null;
  }
}

async function retrieveContext(target) {
  try {
    const query = `
      FOR scan IN scans
        FILTER scan.target == @target
        SORT scan.startedAt DESC
        LIMIT 5
        RETURN scan
    `;
    
    return await queryAQL(query, { target });
  } catch (error) {
    console.error('Error retrieving context:', error);
    return [];
  }
}

async function retrieveSimilarScans(target, scanType) {
  try {
    const query = `
      FOR scan IN scans
        FILTER scan.scanType == @scanType
        FILTER scan.target != @target
        SORT scan.startedAt DESC
        LIMIT 10
        RETURN scan
    `;
    
    return await queryAQL(query, { target, scanType });
  } catch (error) {
    console.error('Error retrieving similar scans:', error);
    return [];
  }
}

async function storeContext(target, contextType, data) {
  try {
    const scanData = {
      target,
      contextType,
      data,
      storedAt: new Date().toISOString(),
      type: 'scan_context',
    };

    return await createDocument('scans', scanData);
  } catch (error) {
    console.error('Error storing context:', error);
    return null;
  }
}

async function storeResearch(vulnerability, researchResults) {
  try {
    const memory = createAgentMemory(
      'research',
      `Research for ${vulnerability.type}`,
      { vulnerability, researchResults },
      researchResults
    );
    
    return await createDocument('agent_memory', memory);
  } catch (error) {
    console.error('Error storing research:', error);
    return null;
  }
}

async function getDecisionHistory(limit = 50) {
  try {
    const query = `
      FOR memory IN agent_memory
        FILTER memory.type == 'agent_memory'
        SORT memory.timestamp DESC
        LIMIT @limit
        RETURN memory
    `;
    
    return await queryAQL(query, { limit });
  } catch (error) {
    console.error('Error retrieving decision history:', error);
    return [];
  }
}

module.exports = {
  storeDecision,
  retrieveContext,
  retrieveSimilarScans,
  storeContext,
  storeResearch,
  getDecisionHistory,
};

