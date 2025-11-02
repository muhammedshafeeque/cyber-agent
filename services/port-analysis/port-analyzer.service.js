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
    // Step 1: Quick service identification (with version detection)
    logger.step(`Step 1/5: Quick service identification on port ${port}...`);
    analysis.information = await gatherPortInformation(target, port, service);
    
    // Step 2: Identify service version and details (DEEP scan for THIS port only)
    logger.step(`Step 2/5: Deep service version detection on port ${port}...`);
    const serviceDetails = await identifyServiceDetails(target, port, analysis.information);
    analysis.service = serviceDetails.service || service;
    analysis.information.version = serviceDetails.version;
    analysis.information.banner = serviceDetails.banner;

    // Step 3: Search for CVEs and exploits (multiple sources) - FAST parallel search
    logger.step(`Step 3/5: Researching CVEs/exploits from multiple sources (parallel)...`);
    const exploitResearch = await researchExploitsMultiSource(
      analysis.service,
      analysis.information.version,
      port,
      previousContext
    );
    analysis.cves = exploitResearch.cves;
    analysis.exploits = exploitResearch.exploits;

    // Step 4: Analyze for RCE opportunities (prioritize high-confidence)
    logger.step(`Step 4/5: Analyzing RCE opportunities (prioritizing high-confidence)...`);
    analysis.rceOpportunities = await analyzeRCEOpportunities(
      analysis.service,
      analysis.information,
      exploitResearch,
      previousContext
    );

    // Step 5: Determine next steps (prioritize immediate RCE attempts)
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
    // Use nmap for THIS port ONLY with service detection (fast since it's just one port)
    logger.tool('nmap', `Deep scan port ${port} only`, `on ${target} (service + version detection)`);
    const nmapResult = await toolExecutor.executeNmap(target, {
      ports: port.toString(), // Only scan this one port
      serviceVersion: true, // Enable version detection for this port
      script: 'version,banner', // Only version and banner scripts for speed
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
 * Research exploits from multiple sources (OPTIMIZED FOR SPEED - parallel where possible)
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

  // First: Check port-based exploits (FASTEST - no search needed)
  logger.step('Checking known port-based exploits (instant lookup)...');
  const portBasedExploits = checkPortBasedExploits(port);
  if (portBasedExploits.length > 0) {
    // Ensure all exploits have the correct structure with string paths
    const normalizedExploits = portBasedExploits.map(exp => ({
      ...exp,
      exploit: exp.exploit || exp.path || exp.name,
      path: exp.path || exp.exploit || exp.name,
      name: exp.name || exp.exploit || exp.path,
      metasploit_module: exp.exploit || exp.path || exp.name,
    }));
    results.exploits.metasploit.push(...normalizedExploits);
    logger.info(`  Found ${portBasedExploits.length} known exploit(s) for port ${port}`);
    // If we have high-confidence exploits, we can skip deeper research for speed
    const hasHighConfidence = portBasedExploits.some(e => e.confidence === 'high');
    if (hasHighConfidence) {
      logger.info('  High-confidence exploit found - skipping deeper research for speed');
      results.cves = extractCVEs(results.exploits);
      return results; // Return early - we have what we need!
    }
  }

  const searchTerms = [];
  if (service) searchTerms.push(service);
  if (version) searchTerms.push(version);

  const searchQuery = searchTerms.join(' ');

  logger.info(`Researching exploits for: ${searchQuery || port}`);

  // Run searches in parallel for speed (Promise.all)
  const searchPromises = [];

  // Source 1: Searchsploit (Exploit-DB local) - FAST
  searchPromises.push(
    (async () => {
      try {
        const searchsploitResults = await searchSearchsploit(service, version);
        results.exploits.searchsploit = searchsploitResults;
        if (searchsploitResults.length > 0) {
          logger.info(`  ✓ Searchsploit: ${searchsploitResults.length} exploit(s)`);
        }
      } catch (error) {
        // Silent fail for speed
      }
    })()
  );

  // Source 2: Metasploit modules - FAST if local
  searchPromises.push(
    (async () => {
      try {
        const msfResults = await searchMetasploit(service, version);
        // Merge with port-based exploits
        results.exploits.metasploit = [...portBasedExploits, ...msfResults];
        if (msfResults.length > 0) {
          logger.info(`  ✓ Metasploit: ${msfResults.length} module(s)`);
        }
      } catch (error) {
        // Silent fail for speed
      }
    })()
  );

  // Source 3 & 4: Online sources (slower, run in parallel but don't wait if we have local results)
  if (results.exploits.searchsploit.length === 0 && results.exploits.metasploit.length === 0) {
    // Only search online if we don't have local results (speed optimization)
    logger.step('No local exploits found - checking online sources...');
    searchPromises.push(
      searchExploitDB(service, version).then(edbResults => {
        results.exploits.exploitdb = edbResults;
        if (edbResults.length > 0) {
          logger.info(`  ✓ Exploit-DB: ${edbResults.length} exploit(s)`);
        }
      }).catch(() => {})
    );
  }

  // Wait for parallel searches (with timeout)
  await Promise.race([
    Promise.all(searchPromises),
    new Promise(resolve => setTimeout(resolve, 10000)), // 10 second timeout
  ]);

  // Extract CVEs from all sources
  results.cves = extractCVEs(results.exploits);

  return results;
}

/**
 * Check port-based exploits (instant lookup, no search needed)
 */
function checkPortBasedExploits(port) {
  const portExploits = {
    21: [{ 
      name: 'exploit/unix/ftp/vsftpd_234_backdoor',
      path: 'exploit/unix/ftp/vsftpd_234_backdoor',
      exploit: 'exploit/unix/ftp/vsftpd_234_backdoor',
      confidence: 'high', 
      description: 'vsftpd 2.3.4 backdoor',
      source: 'metasploit',
    }],
    3632: [{ 
      name: 'exploit/unix/misc/distcc_exec',
      path: 'exploit/unix/misc/distcc_exec',
      exploit: 'exploit/unix/misc/distcc_exec',
      confidence: 'high', 
      description: 'DistCC command execution',
      source: 'metasploit',
    }],
    6667: [{ 
      name: 'exploit/unix/irc/unreal_ircd_3281_backdoor',
      path: 'exploit/unix/irc/unreal_ircd_3281_backdoor',
      exploit: 'exploit/unix/irc/unreal_ircd_3281_backdoor',
      confidence: 'high', 
      description: 'UnrealIRCd backdoor',
      source: 'metasploit',
    }],
    2121: [{ 
      name: 'exploit/unix/ftp/proftpd_133c_backdoor',
      path: 'exploit/unix/ftp/proftpd_133c_backdoor',
      exploit: 'exploit/unix/ftp/proftpd_133c_backdoor',
      confidence: 'high', 
      description: 'ProFTPd backdoor',
      source: 'metasploit',
    }],
    1524: [{ 
      name: 'exploit/unix/misc/distcc_exec',
      path: 'exploit/unix/misc/distcc_exec',
      exploit: 'exploit/unix/misc/distcc_exec',
      confidence: 'medium', 
      description: 'Ingres lock port - often has shell',
      source: 'metasploit',
    }],
    514: [{ 
      name: 'exploit/multi/samba/usermap_script',
      path: 'exploit/multi/samba/usermap_script',
      exploit: 'exploit/multi/samba/usermap_script',
      confidence: 'medium', 
      description: 'Rsh remote shell',
      source: 'metasploit',
    }],
    512: [{ 
      name: 'exploit/multi/samba/usermap_script',
      path: 'exploit/multi/samba/usermap_script',
      exploit: 'exploit/multi/samba/usermap_script',
      confidence: 'medium', 
      description: 'Rexec remote exec',
      source: 'metasploit',
    }],
    513: [{ 
      name: 'auxiliary/scanner/rservices/rlogin_login',
      path: 'auxiliary/scanner/rservices/rlogin_login',
      exploit: 'auxiliary/scanner/rservices/rlogin_login',
      confidence: 'medium', 
      description: 'Rlogin service',
      source: 'metasploit',
    }],
  };

  return portExploits[port] || [];
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

  // First, add port-based Metasploit exploits directly (they're already normalized with string paths)
  if (exploitResearch.exploits.metasploit && exploitResearch.exploits.metasploit.length > 0) {
    for (const msfExploit of exploitResearch.exploits.metasploit) {
      // Ensure we have a string path
      const modulePath = typeof msfExploit.exploit === 'string' ? msfExploit.exploit :
                        typeof msfExploit.path === 'string' ? msfExploit.path :
                        typeof msfExploit.name === 'string' ? msfExploit.name :
                        null;
      
      if (modulePath && (modulePath.startsWith('exploit/') || modulePath.startsWith('auxiliary/'))) {
        opportunities.push({
          exploit: modulePath,
          path: modulePath,
          name: modulePath,
          metasploit_module: modulePath,
          type: 'metasploit_exploit',
          confidence: msfExploit.confidence || 'high',
          method: 'metasploit',
          source: 'metasploit',
          description: msfExploit.description || `${modulePath} - known RCE exploit`,
        });
      }
    }
  }

  // Check if any other exploits can lead to RCE
  const allExploits = Object.values(exploitResearch.exploits).flat()
    .filter(exp => !exp.path || (!exp.path.startsWith('exploit/') && !exp.path.startsWith('auxiliary/')));
  
  for (const exploit of allExploits) {
    // Check if exploit mentions RCE, command execution, shell, etc.
    const exploitText = (exploit.title || exploit.description || exploit.name || exploit.path || '').toLowerCase();
    const rceKeywords = ['rce', 'remote code execution', 'command execution', 'shell', 'meterpreter', 'backdoor', 'arbitrary code'];
    
    if (rceKeywords.some(keyword => exploitText.includes(keyword))) {
      // Extract module path as string
      const modulePath = typeof exploit.path === 'string' ? exploit.path :
                        typeof exploit.name === 'string' ? exploit.name :
                        typeof exploit.title === 'string' ? exploit.title :
                        null;
      
      if (modulePath) {
        opportunities.push({
          exploit: modulePath,  // Store as string, not object
          path: modulePath,
          name: modulePath,
          metasploit_module: modulePath.startsWith('exploit/') || modulePath.startsWith('auxiliary/') ? modulePath : null,
          type: 'known_exploit',
          confidence: 'high',
          method: exploit.source === 'metasploit' || modulePath.startsWith('exploit/') || modulePath.startsWith('auxiliary/') ? 'metasploit' : 'manual',
          source: exploit.source || 'metasploit',
          description: exploit.description || exploit.title || '',
        });
      }
    }
  }

  // Check service-specific RCE opportunities (adds port-based exploits if not already added)
  const serviceOpportunities = checkServiceRCEOpportunities(service, information, previousContext);
  
  // Merge but avoid duplicates
  serviceOpportunities.forEach(serviceOpp => {
    const exists = opportunities.some(opp => 
      opp.exploit === serviceOpp.exploit || 
      opp.metasploit_module === serviceOpp.exploit
    );
    if (!exists) {
      opportunities.push(serviceOpp);
    }
  });

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
    if (serviceName.includes(key) && info.versionMatch) {
      const modulePath = info.exploit; // Already a string
      opportunities.push({
        type: 'service_backdoor',
        service: key,
        exploit: modulePath,  // String path
        path: modulePath,
        name: modulePath,
        metasploit_module: modulePath,
        description: info.description,
        confidence: 'high',
        method: 'metasploit',
        source: 'metasploit',
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

