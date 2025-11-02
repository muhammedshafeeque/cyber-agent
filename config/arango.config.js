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
    if (!(await graph.exists())) {
      // First create edge collections
      const edgeCollections = [
        'vulnerability_found_in',
        'detected_by',
        'exploits',
        'tool_for',
        'combines_with',
        'generates',
        'similar_to',
        'requires',
        'learned_from',
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
          to: ['cves', 'vulnerabilities'],
        },
        {
          edgeCollection: 'tool_for',
          from: ['tools'],
          to: ['vulnerabilities'],
        },
        {
          edgeCollection: 'combines_with',
          from: ['tools', 'scripts'],
          to: ['tools', 'scripts'],
        },
        {
          edgeCollection: 'generates',
          from: ['tools', 'scripts'],
          to: ['exploits'],
        },
        {
          edgeCollection: 'similar_to',
          from: ['vulnerabilities', 'techniques'],
          to: ['vulnerabilities', 'techniques'],
        },
        {
          edgeCollection: 'requires',
          from: ['tools'],
          to: ['tools'],
        },
        {
          edgeCollection: 'learned_from',
          from: ['vulnerabilities', 'tools', 'exploits'],
          to: ['research_sources'],
        },
      ];

      await db.createGraph(graphName, {
        edgeDefinitions,
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
        await collection.ensureIndex({
          type: 'fulltext',
          fields: ['name', 'description'],
          minLength: 3,
        });
        console.log(`Full-text index created on ${collectionName}.`);
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

