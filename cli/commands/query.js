const { Command } = require('commander');
const chalk = require('chalk');
const { queryAQL } = require('../../services/graph.service');
const { chat } = require('../../config/mistral.config');
const { displayInfo, displaySuccess } = require('../utils/display');

const command = new Command('query');

command
  .description('Query knowledge graph')
  .argument('<question>', 'Question to query the knowledge graph')
  .action(async (question) => {
    try {
      displayInfo(`Querying knowledge graph: ${question}`);

      // Query knowledge graph
      const query = `
        FOR doc IN vulnerabilities
          FILTER doc.description LIKE @pattern OR doc.type LIKE @pattern
          LIMIT 10
          RETURN doc
      `;

      const results = await queryAQL(query, {
        pattern: `%${question}%`,
      });

      if (results.length > 0) {
        console.log(chalk.green(`\nFound ${results.length} relevant entries:`));
        results.forEach((r, i) => {
          console.log(`\n${i + 1}. ${chalk.cyan(r.type)}`);
          if (r.description) {
            console.log(`   ${r.description}`);
          }
        });
      } else {
        // Use AI to answer question
        const answer = await chat([
          {
            role: 'system',
            content: 'You are a cybersecurity expert answering questions based on knowledge from penetration testing.',
          },
          {
            role: 'user',
            content: question,
          },
        ]);

        console.log(chalk.yellow('\nNo exact matches found. AI response:'));
        console.log(answer);
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

module.exports = command;

