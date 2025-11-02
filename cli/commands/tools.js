const { Command } = require('commander');
const chalk = require('chalk');

const toolsCommand = new Command('tools');

toolsCommand
  .description('Manage security tools')
  .action(() => {
    toolsCommand.help();
  });

toolsCommand
  .command('list')
  .description('List discovered/installed tools')
  .action(async () => {
    try {
      const toolRegistry = require('../../services/tools/tool-registry.service');
      const { queryAQL } = require('../../services/graph.service');
      const { displayTable } = require('../utils/display');

      // Get tools from knowledge graph
      const tools = await queryAQL(`
        FOR tool IN tools
          LIMIT 50
          RETURN tool
      `);

      if (tools.length > 0) {
        const tableData = [
          ['Name', 'Version', 'Installation Method', 'Kali'],
        ];

        for (const tool of tools) {
          tableData.push([
            tool.name || 'Unknown',
            tool.version || 'Unknown',
            tool.installationMethod || 'Unknown',
            tool.isKali ? 'Yes' : 'No',
          ]);
        }

        displayTable(tableData);
      } else {
        console.log(chalk.yellow('No tools found in knowledge graph.'));
        console.log(chalk.gray('Tools will be discovered during scans.'));
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
    }
  });

toolsCommand
  .command('install')
  .description('Install a tool')
  .argument('<tool>', 'Tool name to install')
  .action(async (tool) => {
    try {
      const toolRegistry = require('../../services/tools/tool-registry.service');
      const toolInstaller = require('../../services/tools/tool-installer.service');
      const { displayInfo, displaySuccess, displayError } = require('../utils/display');
      const { createSpinner } = require('../utils/progress');

      displayInfo(`Installing tool: ${tool}`);

      // Check if already installed
      const existing = await toolRegistry.findToolInSystem(tool);
      if (existing.available) {
        console.log(chalk.green(`Tool ${tool} is already installed at: ${existing.path}`));
        return;
      }

      const spinner = createSpinner(`Installing ${tool}...`);
      
      const result = await toolInstaller.installTool(tool);
      
      if (result.success) {
        spinner.succeed(`${tool} installed successfully`);
        displaySuccess(`Installation method: ${result.method}`);
      } else {
        spinner.fail(`Failed to install ${tool}`);
        displayError(result.error || 'Unknown error');
      }
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
    }
  });

module.exports = toolsCommand;

