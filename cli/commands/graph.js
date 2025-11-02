const { Command } = require('commander');
const chalk = require('chalk');

const command = new Command('graph');

command
  .description('Explore knowledge graph')
  .action(() => {
    command.help();
  });

command
  .command('explore')
  .description('Explore knowledge graph interactively')
  .action(async () => {
    console.log(chalk.blue('Exploring knowledge graph...'));
    // TODO: Implement graph exploration
    console.log(chalk.yellow('Graph exploration not yet implemented'));
  });

module.exports = command;

