const scraperService = require('./scraper.service');
const searchService = require('./search.service');
const learningService = require('./learning.service');

async function researchTools(vulnerabilityType) {
  const results = {
    tools: [],
    exploits: [],
    techniques: [],
  };

  try {
    // Search for tools
    const toolQueries = [
      `${vulnerabilityType} scanner tool`,
      `${vulnerabilityType} penetration testing tool`,
      `exploit ${vulnerabilityType} github`,
    ];

    for (const query of toolQueries) {
      const searchResults = await searchService.search(query);
      results.tools.push(...searchResults);

      // Also search GitHub directly
      const githubResults = await scraperService.searchGitHub(query);
      results.tools.push(...githubResults);
    }

    // Search for exploits
    const exploitQueries = [
      `${vulnerabilityType} exploit`,
      `${vulnerabilityType} poc proof of concept`,
      `CVE ${vulnerabilityType}`,
    ];

    for (const query of exploitQueries) {
      const searchResults = await searchService.search(query);
      results.exploits.push(...searchResults);
    }

    return results;
  } catch (error) {
    console.error('Error in research:', error);
    return results;
  }
}

async function researchForRCE(target, discoveredVulnerabilities) {
  const results = {
    tools: [],
    exploits: [],
    techniques: [],
  };

  try {
    // Focus research on RCE opportunities
    for (const vuln of discoveredVulnerabilities) {
      const rceQueries = [
        `${vuln.type} remote code execution`,
        `${vuln.type} RCE exploit`,
        `command injection ${vuln.type}`,
        `${vuln.type} shell upload`,
      ];

      for (const query of rceQueries) {
        const searchResults = await searchService.search(query);
        results.exploits.push(...searchResults);

        // Check Exploit-DB
        const exploitDbResults = await scraperService.searchExploitDB(query);
        results.exploits.push(...exploitDbResults);
      }
    }

    return results;
  } catch (error) {
    console.error('Error in RCE research:', error);
    return results;
  }
}

async function learnFromSource(url, sourceType = 'github') {
  try {
    const content = await scraperService.fetchContent(url);
    return await learningService.parseAndLearn(content, sourceType, url);
  } catch (error) {
    console.error(`Error learning from ${url}:`, error);
    return null;
  }
}

module.exports = {
  researchTools,
  researchForRCE,
  learnFromSource,
};

