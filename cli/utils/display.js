const chalk = require('chalk');
const { table } = require('table');
const boxen = require('boxen');

function displayInfo(message) {
  console.log(chalk.blue('ℹ'), message);
}

function displaySuccess(message) {
  console.log(chalk.green('✓'), message);
}

function displayError(message) {
  console.log(chalk.red('✗'), message);
}

function displayWarning(message) {
  console.log(chalk.yellow('⚠'), message);
}

function displayStep(stepNumber, description) {
  console.log(chalk.cyan(`[${stepNumber}]`), description);
}

function displayTable(data) {
  const config = {
    border: {
      topBody: '─',
      topJoin: '┬',
      topLeft: '┌',
      topRight: '┐',
      bottomBody: '─',
      bottomJoin: '┴',
      bottomLeft: '└',
      bottomRight: '┘',
      bodyLeft: '│',
      bodyRight: '│',
      bodyJoin: '│',
      joinBody: '─',
      joinLeft: '├',
      joinRight: '┤',
      joinJoin: '┼',
    },
  };
  
  console.log(table(data, config));
}

function displayBox(title, content) {
  const box = boxen(content, {
    title,
    padding: 1,
    borderColor: 'blue',
  });
  console.log(box);
}

module.exports = {
  displayInfo,
  displaySuccess,
  displayError,
  displayWarning,
  displayStep,
  displayTable,
  displayBox,
};

