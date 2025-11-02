const { Command } = require('commander');
const initCommand = require('./commands/init');
const testCommand = require('./commands/test');
const queryCommand = require('./commands/query');
const toolsCommand = require('./commands/tools');
const exploitsCommand = require('./commands/exploits');
const graphCommand = require('./commands/graph');
const interactiveCommand = require('./commands/interactive');

const program = new Command();

program
  .name('cyber-agent')
  .description('Autonomous Cybersecurity Penetration Testing CLI Tool')
  .version('1.0.0');

// Register commands
program.addCommand(initCommand);
program.addCommand(testCommand);
program.addCommand(queryCommand);
program.addCommand(toolsCommand);
program.addCommand(exploitsCommand);
program.addCommand(graphCommand);
program.addCommand(interactiveCommand);

module.exports = { program };

