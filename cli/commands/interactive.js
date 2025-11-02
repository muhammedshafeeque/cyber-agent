const { Command } = require('commander');
const chalk = require('chalk');
const { promptText, promptConfirm, promptScreenshotPath, promptOutput } = require('../utils/prompts');
const { analyzeScreenshot, analyzeUserOutput } = require('../../services/analyzer.service');
const { displayInfo, displayStep, displaySuccess } = require('../utils/display');
const { chat } = require('../../config/mistral.config');

const command = new Command('interactive');

command
  .description('Enter interactive mode with AI guidance')
  .action(async () => {
    try {
      console.log(chalk.blue.bold('\n=== Interactive AI Guidance Mode ===\n'));
      displayInfo('This mode provides step-by-step AI guidance for manual security testing.\n');

      let continueSession = true;
      let context = {};

      while (continueSession) {
        const action = await promptText('What would you like to do? (ask question, upload screenshot, provide output, exit): ');

        if (action.toLowerCase() === 'exit') {
          continueSession = false;
          break;
        }

        if (action.toLowerCase().includes('screenshot') || action.toLowerCase().includes('image')) {
          const imagePath = await promptScreenshotPath();
          displayStep(1, 'Analyzing screenshot...');
          
          const analysis = await analyzeScreenshot(imagePath);
          console.log(chalk.green('\nAnalysis:'));
          console.log(analysis.analysis);
          
          // Get next steps from AI
          const nextSteps = await chat([
            {
              role: 'system',
              content: 'Provide next steps for penetration testing based on the screenshot analysis.',
            },
            {
              role: 'user',
              content: `Screenshot analysis: ${analysis.analysis}\n\nWhat should be done next?`,
            },
          ]);

          console.log(chalk.cyan('\nRecommended Next Steps:'));
          console.log(nextSteps);
        } else if (action.toLowerCase().includes('output') || action.toLowerCase().includes('result')) {
          const output = await promptOutput();
          displayStep(1, 'Analyzing output...');
          
          const analysis = await analyzeUserOutput(output);
          console.log(chalk.green('\nAnalysis:'));
          console.log(analysis.analysis);
          
          if (analysis.recommendations && analysis.recommendations.length > 0) {
            console.log(chalk.cyan('\nRecommendations:'));
            analysis.recommendations.forEach((rec, i) => {
              console.log(`${i + 1}. ${rec}`);
            });
          }
        } else {
          // General question
          const response = await chat([
            {
              role: 'system',
              content: 'You are a penetration testing expert providing guidance. Answer questions and provide step-by-step instructions.',
            },
            {
              role: 'user',
              content: action,
            },
          ]);

          console.log(chalk.green('\nAI Response:'));
          console.log(response);
        }

        console.log(); // Empty line
        continueSession = await promptConfirm('Continue session?', true);
      }

      displaySuccess('Interactive session ended.');
    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

module.exports = command;

