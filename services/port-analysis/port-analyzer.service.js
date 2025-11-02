/**
 * Port Analysis Service
 * Deep analysis of individual ports and services for RCE opportunities
 */

const logger = require('../../cli/utils/logger');
const { exec } = require('child_process');
const { promisify } = require('util');
const toolExecutor = require('../tools/tool-executor.service');
const toolRegistry = require('../tools/tool-registry.service');
const axios = require('axios');

const execAsync = promisify(exec);

/**
 * Analyze a single port deeply - collect maximum information
 */
async function analyzePort(target, port, service = null, previousContext = {}) {
  const analysis = {
    port,
    service,
    target,
    information: {},
    cves: [],
    exploits: [],
    rceOpportunities: [],
    nextSteps: [],
    context: previousContext,
  };

  logger.phase('PORT ANALYSIS', `Port ${port} - ${service || 'Unknown service'}`);

  try {
    // Step 1: Gather basic information about the port
    logger.step(`Step 1/5: Gathering basic information about port ${port}...`);
    analysis.information = await gatherPortInformation(target, port, service);
    
    // Step 2: Identify service version and details
    logger.step(`Step 2/5: Identifying service version and details...`);
    const serviceDetails = await identifyServiceDetails(target, port, analysis.information);
    analysis.service = serviceDetails.service || service;
    analysis.information.version = serviceDetails.version;
    analysis.information.banner = serviceDetails.banner;

    // Step 3: Search for CVEs and exploits (multiple sources)
    logger.step(`Step 3/5: Researching CVEs and exploits from multiple sources...`);
    const exploitResearch = await researchExploitsMultiSource(
      analysis.service,
      analysis.information.version,
      port,
      previousContext
    );
    analysis.cves = exploitResearch.cves;
    analysis.exploits = exploitResearch.exploits;

    // Step 4: Analyze for RCE opportunities
    logger.step(`Step 4/5: Analyzing RCE opportunities...`);
    analysis.rceOpportunities = await analyzeRCEOpportunities(
      analysis.service,
      analysis.information,
      exploitResearch,
      previousContext
    );

    // Step 5: Determine next steps
    logger.step(`Step 5/5: Determining next steps...`);
    analysis.nextSteps = generateNextSteps(analysis, previousContext);

    logger.success(`Port ${port} analysis complete:`);
    logger.info(`  Service: ${analysis.service || 'Unknown'}`);
    logger.info(`  Version: ${analysis.information.version || 'Unknown'}`);
    logger.info(`  CVEs: ${analysis.cves.length}`);
    logger.info(`  Exploits: ${analysis.exploits.length}`);
    logger.info(`  RCE Opportunities: ${analysis.rceOpportunities.length}`);

    return analysis;
  } catch (error) {
    logger.error(`Error analyzing port ${port}:`, error);
    analysis.error = error.message;
    return analysis;
  }
}

/**
 * Gather basic port information
 */
async function gatherPortInformation(target, port, service) {
  const info = {
    port,
    state: 'open',
    protocol: 'tcp',
    service: service || 'unknown',
    version: null,
    banner: null,
    product: null,
    os: null,
  };

  try {
    // Use nmap for detailed port scan
    logger.tool('nmap', `Scanning port ${port}`, `on ${target}`);
    const nmapResult = await toolExecutor.executeNmap(target, {
      ports: port.toString(),
      serviceVersion: true,
      script: 'version,default',
    });

    if (nmapResult.success && nmapResult.output) {
      // Parse nmap output for this port
      const portInfo = parsePortInfoFromNmap(nmapResult.output, port);
      Object.assign(info, portInfo);
    }

    // Try banner grabbing
    logger.step(`Attempting banner grab on port ${port}...`);
    const banner = await grabBanner(target, port);
    if (banner) {
      info.banner = banner;
    }

    // Try service-specific probes
    if (service) {
      const serviceInfo = await probeService(target, port, service);
      Object.assign(info, serviceInfo);
    }

    return info;
  } catch (error) {
    logger.warn(`Could not gather full information for port ${port}: ${error.message}`);
    return info;
  }
}

/**
 * Identify service details
 */
async function identifyServiceDetails(target, port, information) {
  const details = {
    service: information.service || 'unknown',
    version: information.version || null,
    banner: information.banner || null,
  };

  // If we already have version info, use it
  if (information.version) {
    return details;
  }

  // Try additional service detection
  try {
    // Use netcat or telnet to grab banner
    const banner = await grabBanner(target, port);
    if (banner) {
      details.banner = banner;
      // Try to extract version from banner
      const versionMatch = banner.match(/(\d+\.\d+\.\d+|\d+\.\d+)/);
      if (versionMatch) {
        details.version = versionMatch[1];
      }
    }
  } catch (error) {
    // Continue without banner
  }

  return details;
}

/**
 * Research exploits from multiple sources
 */
async function researchExploitsMultiSource(service, version, port, previousContext) {
  const results = {
    cves: [],
    exploits: {
      searchsploit: [],
      metasploit: [],
      exploitdb: [],
      github: [],
    },
  };

  const searchTerms = [];
  if (service) searchTerms.push(service);
  if (version) searchTerms.push(version);
  if (port) searchTerms.push(`port ${port}`);

  const searchQuery = searchTerms.join(' ');

  logger.info(`Researching exploits for: ${searchQuery}`);

  // Source 1: Searchsploit (Exploit-DB local)
  try {
    logger.step('Checking Searchsploit (local Exploit-DB)...');
    const searchsploitResults = await searchSearchsploit(service, version);
    results.exploits.searchsploit = searchsploitResults;
    logger.info(`  Found ${searchsploitResults.length} exploit(s) in Searchsploit`);
  } catch (error) {
    logger.warn(`  Searchsploit search failed: ${error.message}`);
  }

  // Source 2: Metasploit modules
  try {
    logger.step('Checking Metasploit modules...');
    const msfResults = await searchMetasploit(service, version);
    results.exploits.metasploit = msfResults;
    logger.info(`  Found ${msfResults.length} Metasploit module(s)`);
  } catch (error) {
    logger.warn(`  Metasploit search failed: ${error.message}`);
  }

  // Source 3: Exploit-DB (online)
  try {
    logger.step('Checking Exploit-DB (online)...');
    const edbResults = await searchExploitDB(service, version);
    results.exploits.exploitdb = edbResults;
    logger.info(`  Found ${edbResults.length} exploit(s) in Exploit-DB`);
  } catch (error) {
    logger.warn(`  Exploit-DB search failed: ${error.message}`);
  }

  // Source 4: GitHub (public exploits)
  try {
    logger.step('Checking GitHub for public exploits...');
    const githubResults = await searchGitHub(service, version, previousContext);
    results.exploits.github = githubResults;
    logger.info(`  Found ${githubResults.length} GitHub exploit(s)`);
  } catch (error) {
    logger.warn(`  GitHub search failed: ${error.message}`);
  }

  // Extract CVEs from all sources
  results.cves = extractCVEs(results.exploits);

  return results;
}

/**
 * Search Searchsploit (local Exploit-DB)
 */
async function searchSearchsploit(service, version) {
  try {
    const searchTerm = version ? `${service} ${version}` : service;
    const result = await execAsync(`searchsploit "${searchTerm}" --json 2>/dev/null || searchsploit "${searchTerm}"`, {
      timeout: 30000,
    });

    const exploits = [];
    
    // Parse JSON output if available
    if (result.stdout.includes('{')) {
      try {
        const json = JSON.parse(result.stdout);
        if (json.SEARCHSPLOIT && json.SEARCHSPLOIT.DB_PATH) {
          exploits.push(...json.SEARCHSPLOIT.results || []);
        }
      } catch (e) {
        // Fallback to text parsing
      }
    }

    // Parse text output
    const lines = result.stdout.split('\n');
    for (const line of lines) {
      if (line.includes('|') && !line.includes('Exploit Title')) {
        const parts = line.split('|').map(p => p.trim());
        if (parts.length >= 3) {
          exploits.push({
            title: parts[1],
            path: parts[2],
            edb_id: parts[0],
            source: 'searchsploit',
          });
        }
      }
    }

    return exploits;
  } catch (error) {
    if (error.code !== 'ENOENT') {
      logger.warn(`Searchsploit not available: ${error.message}`);
    }
    return [];
  }
}

/**
 * Search Metasploit modules
 */
async function searchMetasploit(service, version) {
  const modules = [];

  try {
    // Check if msfconsole is available
    const msfStatus = await toolRegistry.findToolInSystem('msfconsole');
    if (!msfStatus.available) {
      return modules;
    }

    // Use msfconsole search
    const searchTerm = version ? `${service} ${version}` : service;
    const result = await execAsync(
      `msfconsole -q -x "search ${searchTerm}; exit" 2>/dev/null`,
      { timeout: 30000 }
    );

    // Parse metasploit search output
    const lines = result.stdout.split('\n');
    let inResults = false;

    for (const line of lines) {
      if (line.includes('Name') && line.includes('Disclosure')) {
        inResults = true;
        continue;
      }

      if (inResults && line.trim() && !line.includes('=') && !line.includes('search')) {
        const parts = line.split(/\s{2,}/);
        if (parts.length >= 3) {
          modules.push({
            name: parts[0]?.trim(),
            disclosure: parts[1]?.trim(),
            rank: parts[2]?.trim(),
            description: parts.slice(3).join(' ').trim(),
            source: 'metasploit',
            path: parts[0]?.trim(),
          });
        }
      }
    }

    return modules;
  } catch (error) {
    logger.warn(`Metasploit search failed: ${error.message}`);
    return modules;
  }
}

/**
 * Search Exploit-DB online
 */
async function searchExploitDB(service, version) {
  const exploits = [];

  try {
    // Exploit-DB search via web (using simplified search)
    const searchTerm = encodeURIComponent(version ? `${service} ${version}` : service);
    const url = `https://www.exploit-db.com/search?q=${searchTerm}`;

    // Note: Full web scraping would be better, but for now return basic structure
    logger.step('  Exploit-DB online search (limited - web scraping not fully implemented)');
    
    // Could implement cheerio/puppeteer scraping here
    return exploits;
  } catch (error) {
    logger.warn(`Exploit-DB search failed: ${error.message}`);
    return exploits;
  }
}

/**
 * Search GitHub for exploits
 */
async function searchGitHub(service, version, previousContext) {
  const exploits = [];

  try {
    const searchTerm = version ? `${service} ${version} exploit` : `${service} exploit`;
    logger.step(`  Searching GitHub: ${searchTerm}`);

    // GitHub API search (requires token for rate limits, but works without for limited requests)
    const query = encodeURIComponent(`${searchTerm} language:python OR language:bash OR language:c`);
    
    // Note: GitHub API requires authentication for higher rate limits
    // For now, we'll use a simplified approach or skip if no token
    logger.step('  GitHub search (limited - API token recommended)');
    
    return exploits;
  } catch (error) {
    logger.warn(`GitHub search failed: ${error.message}`);
    return exploits;
  }
}

/**
 * Extract CVEs from exploits
 */
function extractCVEs(exploits) {
  const cves = new Set();
  
  // Extract from all exploit sources
  Object.values(exploits).flat().forEach(exploit => {
    // Look for CVE patterns
    const cveMatches = (exploit.title || exploit.name || exploit.description || '').match(/CVE-\d{4}-\d+/g);
    if (cveMatches) {
      cveMatches.forEach(cve => cves.add(cve));
    }
  });

  return Array.from(cves);
}

/**
 * Analyze RCE opportunities
 */
async function analyzeRCEOpportunities(service, information, exploitResearch, previousContext) {
  const opportunities = [];

  // Check if any exploits can lead to RCE
  const allExploits = Object.values(exploitResearch.exploits).flat();
  
  for (const exploit of allExploits) {
    // Check if exploit mentions RCE, command execution, shell, etc.
    const exploitText = (exploit.title || exploit.description || exploit.name || '').toLowerCase();
    const rceKeywords = ['rce', 'remote code execution', 'command execution', 'shell', 'meterpreter', 'backdoor', 'arbitrary code'];
    
    if (rceKeywords.some(keyword => exploitText.includes(keyword))) {
      opportunities.push({
        exploit,
        type: 'known_exploit',
        confidence: 'high',
        method: exploit.source === 'metasploit' ? 'metasploit' : 'manual',
        source: exploit.source,
      });
    }
  }

  // Check service-specific RCE opportunities
  const serviceOpportunities = checkServiceRCEOpportunities(service, information, previousContext);
  opportunities.push(...serviceOpportunities);

  return opportunities;
}

/**
 * Check service-specific RCE opportunities
 */
function checkServiceRCEOpportunities(service, information, previousContext) {
  const opportunities = [];
  const serviceName = (service || '').toLowerCase();

  // Known vulnerable services with RCE
  const vulnerableServices = {
    'vsftpd': { port: 21, exploit: 'exploit/unix/ftp/vsftpd_234_backdoor', description: 'vsftpd 2.3.4 backdoor' },
    'distcc': { port: 3632, exploit: 'exploit/unix/misc/distcc_exec', description: 'DistCC command execution' },
    'unrealircd': { port: 6667, exploit: 'exploit/unix/irc/unreal_ircd_3281_backdoor', description: 'UnrealIRCd backdoor' },
    'proftpd': { port: 2121, exploit: 'exploit/unix/ftp/proftpd_133c_backdoor', description: 'ProFTPd backdoor' },
  };

  for (const [key, info] of Object.entries(vulnerableServices)) {
    if (serviceName.includes(key)) {
      opportunities.push({
        type: 'service_backdoor',
        service: key,
        exploit: info.exploit,
        description: info.description,
        confidence: 'high',
        method: 'metasploit',
      });
    }
  }

  return opportunities;
}

/**
 * Generate next steps based on analysis
 */
function generateNextSteps(analysis, previousContext) {
  const steps = [];

  if (analysis.rceOpportunities.length > 0) {
    steps.push({
      action: 'attempt_rce',
      priority: 'high',
      description: `Attempt RCE using ${analysis.rceOpportunities[0].exploit || analysis.rceOpportunities[0].method}`,
    });
  }

  if (analysis.exploits.metasploit.length > 0) {
    steps.push({
      action: 'try_metasploit',
      priority: 'high',
      description: `Try Metasploit module: ${analysis.exploits.metasploit[0].path}`,
    });
  }

  if (analysis.exploits.searchsploit.length > 0) {
    steps.push({
      action: 'try_local_exploit',
      priority: 'medium',
      description: `Try local exploit: ${analysis.exploits.searchsploit[0].path}`,
    });
  }

  return steps;
}

/**
 * Parse port info from nmap output
 */
function parsePortInfoFromNmap(output, port) {
  const info = {};
  const lines = output.split('\n');

  for (const line of lines) {
    if (line.includes(`${port}/tcp`)) {
      const match = line.match(/(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
      if (match) {
        info.service = match[3];
        info.version = match[4]?.trim() || null;
      }
    }

    // Look for service/product info
    if (line.includes('Service Info') || line.includes('Product:')) {
      const productMatch = line.match(/Product:\s*(.+)/);
      if (productMatch) {
        info.product = productMatch[1].trim();
      }
    }
  }

  return info;
}

/**
 * Grab banner from port
 */
async function grabBanner(target, port) {
  try {
    // Try netcat
    const ncResult = await execAsync(`timeout 3 nc ${target} ${port} < /dev/null`, {
      timeout: 5000,
    }).catch(() => null);

    if (ncResult && ncResult.stdout) {
      return ncResult.stdout.trim();
    }

    // Try telnet
    const telnetResult = await execAsync(`timeout 2 telnet ${target} ${port} 2>&1 | head -5`, {
      timeout: 5000,
    }).catch(() => null);

    if (telnetResult && telnetResult.stdout) {
      return telnetResult.stdout.trim();
    }

    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Probe service with service-specific tools
 */
async function probeService(target, port, service) {
  const info = {};

  try {
    const serviceName = service.toLowerCase();

    // Service-specific probes
    if (serviceName.includes('ftp')) {
      info.protocol = 'ftp';
      // Could use ftp client to get more info
    } else if (serviceName.includes('ssh')) {
      info.protocol = 'ssh';
      // Could use ssh to check version
    } else if (serviceName.includes('http')) {
      info.protocol = 'http';
      // Could use curl to get headers
    }

    return info;
  } catch (error) {
    return info;
  }
}

module.exports = {
  analyzePort,
  researchExploitsMultiSource,
};

