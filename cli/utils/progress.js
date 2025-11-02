const cliProgress = require('cli-progress');
const ora = require('ora');

function createProgressBar(total, description = 'Progress') {
  const bar = new cliProgress.SingleBar({
    format: `${description} |{bar}| {percentage}% | {value}/{total}`,
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true,
  });
  
  bar.start(total, 0);
  return bar;
}

function createSpinner(text = 'Loading...') {
  return ora(text).start();
}

module.exports = {
  createProgressBar,
  createSpinner,
};

