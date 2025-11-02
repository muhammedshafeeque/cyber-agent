const cliProgress = require('cli-progress');

// Ora v7 uses default export
let oraFn;
try {
  const oraModule = require('ora');
  // Ora v7 exports default function
  oraFn = oraModule.default || oraModule;
} catch (error) {
  // Fallback if ora fails to load
  oraFn = null;
}

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
  if (!oraFn || typeof oraFn !== 'function') {
    // Fallback spinner if ora is not available
    console.log(`⏳ ${text}`);
    return {
      succeed: (msg) => console.log(`✓ ${msg || text}`),
      fail: (msg) => console.log(`✗ ${msg || text}`),
      info: (msg) => console.log(`ℹ ${msg || text}`),
      warn: (msg) => console.log(`⚠ ${msg || text}`),
      stop: () => {},
      clear: () => {},
    };
  }
  
  try {
    return oraFn(text).start();
  } catch (error) {
    // Fallback if start() fails
    console.log(`⏳ ${text}`);
    return {
      succeed: (msg) => console.log(`✓ ${msg || text}`),
      fail: (msg) => console.log(`✗ ${msg || text}`),
      stop: () => {},
    };
  }
}

module.exports = {
  createProgressBar,
  createSpinner,
};

