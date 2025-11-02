const { Command } = require('commander');
const chalk = require('chalk');
const { AutonomousAgent } = require('../../services/agent/agent.service');
const StepByStepPentest = require('../../services/penetration/step-by-step-pentest.service');
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
      // Use step-by-step methodical approach
      const useStepByStep = true; // Enable step-by-step mode

      let report;
      const spinner = createSpinner('Running penetration test...');

      try {
        if (useStepByStep) {
          spinner.stop();
          spinner.succeed('Starting step-by-step penetration test');
          
          // Step-by-step methodical approach
          const stepByStep = new StepByStepPentest(target, {
            goal: options.goal,
            kaliOnly: options.kaliOnly,
            interactive: options.interactive,
          });
          
          report = await stepByStep.start();
        } else {
          // Original autonomous agent approach
          const agent = new AutonomousAgent(target, {
            goal: options.goal,
            kaliOnly: options.kaliOnly,
            interactive: options.interactive,
          });
          
          // Start agent - it will handle its own logging with live command output
          report = await agent.start();
        }
        
        // Stop spinner before showing final results
        if (spinner && spinner.stop) {
          spinner.stop();
        }
        spinner.succeed('Test completed');

        // Display results
        console.log('\n' + chalk.bold('=== Test Results ==='));
        console.log(chalk.cyan(`Target: ${report.target || target}`));
        console.log(chalk.cyan(`Goal: ${report.goal || options.goal}`));
        
        if (useStepByStep) {
          console.log(chalk.cyan(`RCE Achieved: ${report.rceAchieved ? chalk.green('YES ✓') : chalk.red('NO ✗')}`));
          console.log(chalk.cyan(`Ports Scanned: ${report.portsScanned || 0}`));
          console.log(chalk.cyan(`Ports Analyzed: ${report.portsAnalyzed || 0}`));
          
          if (report.todoSummary) {
            console.log(chalk.cyan(`Tasks Completed: ${report.todoSummary.completed}/${report.todoSummary.total}`));
          }
          
          if (report.rceAchieved) {
            displaySuccess('\n🎯🎯🎯 REMOTE CODE EXECUTION ACHIEVED! 🎯🎯🎯');
            console.log(chalk.green('\nMetasploit session is active and running'));
            console.log(chalk.cyan('To access your shell:'));
            console.log(chalk.white('  msfconsole'));
            console.log(chalk.white('  sessions -l          # List active sessions'));
            console.log(chalk.white('  sessions -i 1        # Interact with session 1'));
            console.log(chalk.gray('\nPenetration test stopped - objective complete!'));
          }
        } else {
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
        }

        // Summary
        if (report.summary) {
          console.log(chalk.gray('\n=== Summary ==='));
          console.log(JSON.stringify(report.summary, null, 2));
        }
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

