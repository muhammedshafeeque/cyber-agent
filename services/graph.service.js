const { ensureDatabase, ensureCollections, ensureGraph } = require('../config/arango.config');

let db = null;

async function initializeGraph() {
  try {
    db = await ensureDatabase();
    await ensureCollections(db);
    await ensureGraph(db);
    return db;
  } catch (error) {
    console.error('Error initializing graph:', error);
    throw error;
  }
}

function getDB() {
  if (!db) {
    throw new Error('Database not initialized. Call initializeGraph() first.');
  }
  return db;
}

async function createDocument(collectionName, document) {
  const database = getDB();
  const collection = database.collection(collectionName);
  return await collection.save(document);
}

async function getDocument(collectionName, key) {
  const database = getDB();
  const collection = database.collection(collectionName);
  return await collection.document(key);
}

async function queryAQL(query, bindVars = {}) {
  const database = getDB();
  const cursor = await database.query(query, bindVars);
  return await cursor.all();
}

async function createEdge(edgeCollectionName, fromId, toId, data = {}) {
  const database = getDB();
  const edgeCollection = database.collection(edgeCollectionName);
  return await edgeCollection.save({
    _from: fromId,
    _to: toId,
    ...data,
  });
}

async function findSimilarVulnerabilities(vulnerabilityType, limit = 5) {
  const query = `
    FOR v IN vulnerabilities
      FILTER v.type == @type OR LIKE(v.description, @pattern)
      LIMIT @limit
      RETURN v
  `;
  return await queryAQL(query, {
    type: vulnerabilityType,
    pattern: `%${vulnerabilityType}%`,
    limit,
  });
}

async function findToolsForVulnerability(vulnerabilityId) {
  const query = `
    FOR v, e, t IN 1..1 OUTBOUND @vulnId
      GRAPH 'security_knowledge_graph'
      FILTER t.type == 'tool'
      RETURN DISTINCT t
  `;
  return await queryAQL(query, { vulnId: `vulnerabilities/${vulnerabilityId}` });
}

async function findExploitForVulnerability(vulnerabilityId) {
  const query = `
    FOR v, e, exp IN 1..1 OUTBOUND @vulnId
      GRAPH 'security_knowledge_graph'
      FILTER exp.type == 'exploit'
      RETURN DISTINCT exp
  `;
  return await queryAQL(query, { vulnId: `vulnerabilities/${vulnerabilityId}` });
}

module.exports = {
  initializeGraph,
  getDB,
  createDocument,
  getDocument,
  queryAQL,
  createEdge,
  findSimilarVulnerabilities,
  findToolsForVulnerability,
  findExploitForVulnerability,
};

