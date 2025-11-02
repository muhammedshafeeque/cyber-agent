const inquirer = require('inquirer');

async function promptText(question) {
  const { answer } = await inquirer.prompt([
    {
      type: 'input',
      name: 'answer',
      message: question,
    },
  ]);
  return answer;
}

async function promptConfirm(message, defaultValue = true) {
  const { answer } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'answer',
      message,
      default: defaultValue,
    },
  ]);
  return answer;
}

async function promptSelect(message, choices) {
  const { answer } = await inquirer.prompt([
    {
      type: 'list',
      name: 'answer',
      message,
      choices,
    },
  ]);
  return answer;
}

async function promptScreenshotPath() {
  const { path } = await inquirer.prompt([
    {
      type: 'input',
      name: 'path',
      message: 'Enter path to screenshot/image:',
      validate: (input) => {
        // Basic validation - can be enhanced
        return input.length > 0 || 'Please enter a valid path';
      },
    },
  ]);
  return path;
}

async function promptOutput() {
  const { output } = await inquirer.prompt([
    {
      type: 'editor',
      name: 'output',
      message: 'Paste the output/text (press Ctrl+X then Y to save):',
    },
  ]);
  return output;
}

module.exports = {
  promptText,
  promptConfirm,
  promptSelect,
  promptScreenshotPath,
  promptOutput,
};

