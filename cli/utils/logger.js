const chalk = require('chalk');

class Logger {
  constructor() {
    this.verbose = process.env.LOG_LEVEL === 'debug' || process.env.LOG_LEVEL === 'verbose';
  }

  info(message, data = null) {
    console.log(chalk.blue('ℹ'), message);
    if (data && this.verbose) {
      console.log(chalk.gray(JSON.stringify(data, null, 2)));
    }
  }

  success(message, data = null) {
    console.log(chalk.green('✓'), message);
    if (data && this.verbose) {
      console.log(chalk.gray(JSON.stringify(data, null, 2)));
    }
  }

  warn(message, data = null) {
    console.log(chalk.yellow('⚠'), message);
    if (data && this.verbose) {
      console.log(chalk.gray(JSON.stringify(data, null, 2)));
    }
  }

  error(message, error = null) {
    console.log(chalk.red('✗'), message);
    if (error && this.verbose) {
      console.error(chalk.red(error.stack || error.message));
    }
  }

  step(message) {
    console.log(chalk.cyan('→'), message);
  }

  phase(phaseName, message = '') {
    console.log('\n' + chalk.bold.magenta(`[${phaseName.toUpperCase()}]`) + ' ' + message);
  }

  tool(toolName, action, details = '') {
    console.log(chalk.yellow(`[${toolName}]`), chalk.white(action), details);
  }

  vulnerability(vuln) {
    console.log(chalk.red('  [VULN]'), chalk.bold(vuln.type || 'Unknown'), '-', vuln.description || 'No description');
    if (vuln.severity) {
      console.log(chalk.gray(`    Severity: ${vuln.severity}`));
    }
  }

  scanResult(toolName, result) {
    const status = result.success ? chalk.green('SUCCESS') : chalk.red('FAILED');
    console.log(chalk.cyan(`  [SCAN]`), `${toolName}:`, status);
    
    if (result.vulnerabilities && result.vulnerabilities.length > 0) {
      console.log(chalk.yellow(`    Found ${result.vulnerabilities.length} vulnerabilities`));
    }
    
    if (result.ports && result.ports.length > 0) {
      console.log(chalk.blue(`    Open ports: ${result.ports.join(', ')}`));
    }
    
    if (result.services && result.services.length > 0) {
      console.log(chalk.blue(`    Services: ${result.services.map(s => s.name || s).join(', ')}`));
    }
  }

  decision(action, reasoning) {
    console.log(chalk.magenta('  [DECISION]'), chalk.bold(action));
    if (reasoning) {
      console.log(chalk.gray(`    Reasoning: ${reasoning.substring(0, 200)}${reasoning.length > 200 ? '...' : ''}`));
    }
  }

  progress(current, total, label = 'Progress') {
    const percentage = Math.round((current / total) * 100);
    const barLength = 30;
    const filled = Math.round((percentage / 100) * barLength);
    const bar = '█'.repeat(filled) + '░'.repeat(barLength - filled);
    process.stdout.write(`\r${chalk.blue(label)}: [${bar}] ${percentage}% (${current}/${total})`);
    if (current === total) {
      process.stdout.write('\n');
    }
  }

  separator() {
    console.log(chalk.gray('─'.repeat(60)));
  }
}

module.exports = new Logger();

