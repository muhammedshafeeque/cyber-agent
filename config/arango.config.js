const { Database } = require('arangojs');

let dbInstance = null;

function getArangoDB() {
  if (dbInstance) {
    return dbInstance;
  }

  const config = {
    url: `http://${process.env.ARANGO_HOST || 'localhost'}:${process.env.ARANGO_PORT || 8529}`,
    auth: {
      username: process.env.ARANGO_USER || 'root',
      password: process.env.ARANGO_PASSWORD || '',
    },
    databaseName: process.env.ARANGO_DB_NAME || 'cyber_security',
  };

  const db = new Database({
    url: config.url,
    auth: config.auth,
  });

  dbInstance = db;
  return dbInstance;
}

async function ensureDatabase() {
  const db = getArangoDB();
  const dbName = process.env.ARANGO_DB_NAME || 'cyber_security';
  
  try {
    // Check if database exists
    const databases = await db.listDatabases();
    if (!databases.includes(dbName)) {
      await db.createDatabase(dbName);
      console.log(`Database ${dbName} created.`);
    }
    
    const targetDb = db.database(dbName);
    return targetDb;
  } catch (error) {
    console.error('Error ensuring database:', error);
    throw error;
  }
}

async function ensureCollections(db) {
  const collections = [
    'applications',
    'vulnerabilities',
    'scans',
    'tools',
    'scripts',
    'exploits',
    'cves',
    'techniques',
    'installations',
    'agent_memory',
    'research_sources',
  ];

  for (const collectionName of collections) {
    try {
      const collection = db.collection(collectionName);
      if (!(await collection.exists())) {
        await db.createCollection(collectionName);
        console.log(`Collection ${collectionName} created.`);
      }
    } catch (error) {
      console.error(`Error creating collection ${collectionName}:`, error.message);
    }
  }
  
  // Create indexes after collections are created
  await createIndexes(db);
}

async function ensureGraph(db) {
  const graphName = 'security_knowledge_graph';
  
  try {
    const graph = db.graph(graphName);
    // Check if graph exists - if it does but is misconfigured, drop and recreate
    if (await graph.exists()) {
      try {
        // Try to get graph info to see if it's properly configured
        const info = await graph.get();
        console.log(`Graph ${graphName} already exists.`);
        return; // Graph exists and is configured
      } catch (error) {
        // Graph exists but might be misconfigured, try to drop it
        console.log(`Graph ${graphName} exists but may be misconfigured. Dropping...`);
        try {
          await graph.drop();
          console.log(`Dropped existing graph ${graphName}`);
        } catch (dropError) {
          console.warn(`Could not drop graph: ${dropError.message}`);
          return; // Can't recreate, use existing
        }
      }
    }
    
    if (!(await graph.exists())) {
      // First create edge collections
      const edgeCollections = [
        'vulnerability_found_in',
        'detected_by',
        'exploits',
        'exploits_cves',
        'tool_for',
        'combines_tools_tools',
        'combines_tools_scripts',
        'combines_with_scripts',
        'combines_scripts_tools',
        'generates',
        'generates_scripts',
        'similar_vuln_vuln',
        'similar_vuln_technique',
        'similar_technique_technique',
        'similar_technique_vuln',
        'requires',
        'learned_from',
        'learned_from_tools',
        'learned_from_exploits',
      ];

      for (const edgeName of edgeCollections) {
        try {
          const edgeCollection = db.collection(edgeName);
          if (!(await edgeCollection.exists())) {
            await db.createEdgeCollection(edgeName);
            console.log(`Edge collection ${edgeName} created.`);
          }
        } catch (error) {
          console.error(`Error creating edge collection ${edgeName}:`, error.message);
        }
      }

      // Create graph with edge definitions
      // ArangoDB requires each edge collection to appear only once
      // For edges with multiple from/to, we split into separate edge collections
      const edgeDefinitions = [
        {
          edgeCollection: 'vulnerability_found_in',
          from: ['vulnerabilities'],
          to: ['applications'],
        },
        {
          edgeCollection: 'detected_by',
          from: ['tools'],
          to: ['vulnerabilities'],
        },
        {
          edgeCollection: 'exploits',
          from: ['exploits'],
          to: ['vulnerabilities'],
        },
        {
          edgeCollection: 'exploits_cves',
          from: ['exploits'],
          to: ['cves'],
        },
        {
          edgeCollection: 'tool_for',
          from: ['tools'],
          to: ['vulnerabilities'],
        },
        {
          edgeCollection: 'combines_tools_tools',
          from: ['tools'],
          to: ['tools'],
        },
        {
          edgeCollection: 'combines_tools_scripts',
          from: ['tools'],
          to: ['scripts'],
        },
        {
          edgeCollection: 'combines_scripts_scripts',
          from: ['scripts'],
          to: ['scripts'],
        },
        {
          edgeCollection: 'combines_scripts_tools',
          from: ['scripts'],
          to: ['tools'],
        },
        {
          edgeCollection: 'generates',
          from: ['tools'],
          to: ['exploits'],
        },
        {
          edgeCollection: 'generates_scripts',
          from: ['scripts'],
          to: ['exploits'],
        },
        {
          edgeCollection: 'similar_vuln_vuln',
          from: ['vulnerabilities'],
          to: ['vulnerabilities'],
        },
        {
          edgeCollection: 'similar_vuln_technique',
          from: ['vulnerabilities'],
          to: ['techniques'],
        },
        {
          edgeCollection: 'similar_technique_technique',
          from: ['techniques'],
          to: ['techniques'],
        },
        {
          edgeCollection: 'similar_technique_vuln',
          from: ['techniques'],
          to: ['vulnerabilities'],
        },
        {
          edgeCollection: 'requires',
          from: ['tools'],
          to: ['tools'],
        },
        {
          edgeCollection: 'learned_from',
          from: ['vulnerabilities'],
          to: ['research_sources'],
        },
        {
          edgeCollection: 'learned_from_tools',
          from: ['tools'],
          to: ['research_sources'],
        },
        {
          edgeCollection: 'learned_from_exploits',
          from: ['exploits'],
          to: ['research_sources'],
        },
      ];

      // Ensure all edge collections exist before creating graph
      for (const def of edgeDefinitions) {
        const edgeCol = db.collection(def.edgeCollection);
        if (!(await edgeCol.exists())) {
          await db.createEdgeCollection(def.edgeCollection);
        }
      }

      const graph = db.graph(graphName);
      // Use proper format for graph creation - pass edgeDefinitions as an object
      await graph.create({
        edgeDefinitions: edgeDefinitions
      });
      console.log(`Graph ${graphName} created.`);
    }
  } catch (error) {
    console.error(`Error creating graph:`, error.message);
  }
}

async function createIndexes(db) {
  try {
    // Create full-text indexes
    const collections = ['tools', 'vulnerabilities', 'cves'];
    for (const collectionName of collections) {
      const collection = db.collection(collectionName);
      try {
        // Create separate fulltext indexes for each field (ArangoDB requirement)
        try {
          await collection.ensureIndex({
            type: 'fulltext',
            fields: ['name'],
            minLength: 3,
          });
        } catch (e) {}
        try {
          await collection.ensureIndex({
            type: 'fulltext',
            fields: ['description'],
            minLength: 3,
          });
        } catch (e) {}
        console.log(`Full-text indexes created on ${collectionName}.`);
      } catch (error) {
        // Index might already exist
        if (!error.message.includes('already exists')) {
          console.error(`Error creating index on ${collectionName}:`, error.message);
        }
      }
    }

    // Create hash indexes for common queries
    const hashIndexes = [
      { collection: 'vulnerabilities', fields: ['type', 'severity'] },
      { collection: 'tools', fields: ['name', 'version'] },
      { collection: 'scans', fields: ['target', 'status'] },
    ];

    for (const { collection: collectionName, fields } of hashIndexes) {
      const collection = db.collection(collectionName);
      try {
        await collection.ensureIndex({
          type: 'hash',
          fields,
        });
        console.log(`Hash index created on ${collectionName} for ${fields.join(', ')}.`);
      } catch (error) {
        if (!error.message.includes('already exists')) {
          console.error(`Error creating hash index:`, error.message);
        }
      }
    }
  } catch (error) {
    console.error('Error creating indexes:', error.message);
  }
}

module.exports = {
  getArangoDB,
  ensureDatabase,
  ensureCollections,
  ensureGraph,
  createIndexes,
};

