const { Command } = require('commander');
const chalk = require('chalk');
const { initializeGraph } = require('../../services/graph.service');
const { displayInfo, displaySuccess, displayError } = require('../utils/display');

const command = new Command('init');

command
  .description('Initialize ArangoDB database and knowledge graph')
  .action(async () => {
    try {
      displayInfo('Initializing ArangoDB database and knowledge graph...');
      await initializeGraph();
      displaySuccess('Database and knowledge graph initialized successfully!');
    } catch (error) {
      displayError(`Failed to initialize: ${error.message}`);
      process.exit(1);
    }
  });

module.exports = command;

