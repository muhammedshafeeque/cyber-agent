const { Command } = require('commander');
const chalk = require('chalk');
const AutonomousAgent = require('../../services/agent/agent.service');
const { displayInfo, displaySuccess, displayError, displayStep } = require('../utils/display');
const { createSpinner } = require('../utils/progress');

const command = new Command('test');

command
  .description('Run autonomous security test with RCE goal')
  .argument('<target>', 'Target URL (e.g., http://example.com) or IP address (e.g., 192.168.1.1)')
  .option('--goal <goal>', 'Primary goal (default: rce)', 'rce')
  .option('--kali-only', 'Use only Kali Linux tools', false)
  .option('--interactive', 'Enable AI-guided manual steps', false)
  .action(async (target, options) => {
    try {
      displayInfo(`Starting security test on: ${target}`);
      displayInfo(`Goal: ${options.goal}`);
      
      // Initialize database if needed
      const { initializeGraph } = require('../../services/graph.service');
      await initializeGraph();

      // Create and start agent
      const agent = new AutonomousAgent(target, {
        goal: options.goal,
        kaliOnly: options.kaliOnly,
        interactive: options.interactive,
      });

      const spinner = createSpinner('Running autonomous penetration test...');
      
      try {
        const report = await agent.start();
        spinner.succeed('Test completed');

        // Display results
        console.log('\n' + chalk.bold('=== Test Results ==='));
        console.log(chalk.cyan(`Target: ${report.target}`));
        console.log(chalk.cyan(`Goal: ${report.goal}`));
        console.log(chalk.cyan(`Achieved: ${report.achieved ? chalk.green('Yes') : chalk.red('No')}`));
        
        if (report.vulnerabilities && report.vulnerabilities.length > 0) {
          console.log(chalk.yellow(`\nVulnerabilities Found: ${report.vulnerabilities.length}`));
          report.vulnerabilities.forEach((v, i) => {
            console.log(`  ${i + 1}. ${chalk.red(v.type)} - ${v.description || 'No description'}`);
          });
        }

        if (report.goal === 'RCE' && report.achieved) {
          displaySuccess('Remote Code Execution achieved!');
        }

        // Summary
        console.log(chalk.gray('\n=== Summary ==='));
        console.log(JSON.stringify(report.summary, null, 2));
      } catch (error) {
        spinner.fail('Test failed');
        displayError(error.message);
        process.exit(1);
      }
    } catch (error) {
      displayError(`Failed to start test: ${error.message}`);
      process.exit(1);
    }
  });

module.exports = command;

