/**
 * Progressive Scanning Strategy
 * Start with quick/simple methods, escalate to thorough if needed
 */

const logger = require('../../cli/utils/logger');

// Scan profiles: quick -> medium -> thorough
const SCAN_PROFILES = {
  quick: {
    name: 'Quick Scan',
    nmap: { ports: '80,443,22,21,25,3306,5432,8080', serviceVersion: true },
    timeout: 60000, // 1 minute
    description: 'Fast scan of common ports only',
  },
  medium: {
    name: 'Medium Scan',
    nmap: { ports: '1-1000', serviceVersion: true, script: 'vuln' },
    timeout: 300000, // 5 minutes
    description: 'Standard scan with vulnerability scripts',
  },
  thorough: {
    name: 'Thorough Scan',
    nmap: { ports: '1-65535', serviceVersion: true, script: 'vuln,safe' },
    timeout: 600000, // 10 minutes
    description: 'Complete port scan with all scripts',
  },
};

// Tool priority: simple/fast tools first
const TOOL_PRIORITY = {
  quick: ['nmap', 'nikto'], // Fast, essential tools
  medium: ['nmap', 'nikto', 'dirb', 'gobuster'], // Add directory scanners
  thorough: ['nmap', 'nikto', 'sqlmap', 'dirb', 'gobuster', 'metasploit'], // Full suite
};

/**
 * Get scan profile based on attempt number and previous results
 */
function getScanProfile(attemptNumber = 0, previousResults = null) {
  // If we have results, use them; otherwise start quick
  if (previousResults && previousResults.length > 0) {
    const hasVulnerabilities = previousResults.some(r => 
      r.vulnerabilities && r.vulnerabilities.length > 0
    );
    
    if (hasVulnerabilities) {
      // Found something! Switch to medium to get more details
      return SCAN_PROFILES.medium;
    }
  }
  
  // Progressive escalation
  if (attemptNumber === 0) {
    return SCAN_PROFILES.quick;
  } else if (attemptNumber === 1) {
    return SCAN_PROFILES.medium;
  } else {
    return SCAN_PROFILES.thorough;
  }
}

/**
 * Get tools based on scan profile
 */
function getToolsForProfile(profile) {
  return TOOL_PRIORITY[profile] || TOOL_PRIORITY.quick;
}

/**
 * Progressive tool execution with retry
 */
async function executeProgressiveScan(scanFunction, target, options = {}) {
  const maxAttempts = options.maxAttempts || 3;
  let lastResult = null;
  let attempt = 0;
  
  while (attempt < maxAttempts) {
    const profile = getScanProfile(attempt, lastResult ? [lastResult] : null);
    
    logger.info(`Attempt ${attempt + 1}/${maxAttempts}: ${profile.name} - ${profile.description}`);
    
    try {
      const result = await scanFunction(target, profile, options);
      
      // Check if we got useful results
      if (result && (
        (result.success) ||
        (result.vulnerabilities && result.vulnerabilities.length > 0) ||
        (result.parsed && result.parsed.ports && result.parsed.ports.length > 0)
      )) {
        logger.success(`${profile.name} completed successfully`);
        
        // If we found something and it's a quick scan, we can stop early
        if (profile.name === 'Quick Scan' && 
            result.vulnerabilities && result.vulnerabilities.length > 0) {
          logger.info('Quick scan found results - stopping early for efficiency');
          return result;
        }
        
        lastResult = result;
        
        // If we found results, try one level deeper to get more info
        if (result.vulnerabilities && result.vulnerabilities.length > 0 && attempt < maxAttempts - 1) {
          logger.step('Results found - escalating to deeper scan for more details...');
          attempt++;
          continue;
        }
        
        // Good results, return
        return result;
      } else {
        // No useful results, try next level
        logger.warn(`${profile.name} completed but found no vulnerabilities`);
        lastResult = result;
      }
    } catch (error) {
      logger.warn(`${profile.name} failed: ${error.message}`);
      
      // If it's not the last attempt, try again with better method
      if (attempt < maxAttempts - 1) {
        logger.step(`Retrying with ${getScanProfile(attempt + 1).name}...`);
      }
      
      lastResult = { success: false, error: error.message };
    }
    
    attempt++;
    
    // Don't escalate if we're on the last attempt
    if (attempt >= maxAttempts) {
      break;
    }
  }
  
  // Return last result (even if failed)
  return lastResult || { success: false, error: 'All scan attempts failed' };
}

/**
 * Smart tool selection - prioritize fast tools first
 */
function selectTools(target, discoveredServices = [], attemptNumber = 0) {
  const tools = [];
  
  // Always start with nmap (quick version first)
  tools.push('nmap');
  
  // Check if web services detected
  const hasWebService = discoveredServices.some(s => 
    s.type === 'web_service' || s.port === 80 || s.port === 443 || s.port === 8080
  );
  
  if (hasWebService) {
    // Quick web scan tools first
    if (attemptNumber === 0) {
      tools.push('nikto'); // Fast web scanner
    } else if (attemptNumber === 1) {
      tools.push('nikto', 'dirb'); // Add directory bruteforce
    } else {
      tools.push('nikto', 'sqlmap', 'dirb', 'gobuster'); // Full web scan suite
    }
  }
  
  // If SQL detected, add sqlmap on later attempts
  const hasSQL = discoveredServices.some(s => 
    s.port === 3306 || s.port === 5432 || s.service?.includes('mysql') || s.service?.includes('postgres')
  );
  
  if (hasSQL && attemptNumber > 0) {
    tools.push('sqlmap');
  }
  
  return tools;
}

module.exports = {
  SCAN_PROFILES,
  TOOL_PRIORITY,
  getScanProfile,
  getToolsForProfile,
  executeProgressiveScan,
  selectTools,
};

