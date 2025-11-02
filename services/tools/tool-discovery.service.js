const researchService = require('../research/research.service');
const scraperService = require('../research/scraper.service');

async function discoverToolsForVulnerability(vulnerabilityType) {
  try {
    // Research tools online
    const researchResults = await researchService.researchTools(vulnerabilityType);
    
    // Extract tool names from results
    const tools = [];
    
    // From search results
    for (const result of researchResults.tools || []) {
      const toolName = extractToolName(result);
      if (toolName) {
        tools.push({
          name: toolName,
          source: result.source || 'internet',
          url: result.url,
          description: result.description || result.snippet,
        });
      }
    }

    // From GitHub results
    for (const result of researchResults.tools || []) {
      if (result.url && result.url.includes('github.com')) {
        const toolInfo = await scraperService.parseReadme(result.url);
        if (toolInfo) {
          tools.push({
            name: extractToolNameFromGitHub(result.url),
            source: 'github',
            url: result.url,
            githubRepo: result.url,
            readme: toolInfo.content,
          });
        }
      }
    }

    return tools;
  } catch (error) {
    console.error('Error discovering tools:', error);
    return [];
  }
}

function extractToolName(result) {
  // Extract tool name from title or URL
  if (result.title) {
    // Common patterns: "ToolName - Description" or "ToolName v1.0"
    const match = result.title.match(/^([\w-]+)/);
    if (match) {
      return match[1].toLowerCase();
    }
  }

  if (result.url) {
    // Extract from GitHub URLs
    const githubMatch = result.url.match(/github\.com\/[\w-]+\/([\w-]+)/);
    if (githubMatch) {
      return githubMatch[1].toLowerCase();
    }

    // Extract from domain/path
    const pathMatch = result.url.match(/\/([\w-]+)\.(git|html|php)$/);
    if (pathMatch) {
      return pathMatch[1].toLowerCase();
    }
  }

  return null;
}

function extractToolNameFromGitHub(url) {
  const match = url.match(/github\.com\/[\w-]+\/([\w-]+)/);
  return match ? match[1].toLowerCase() : null;
}

async function discoverToolsForRCE() {
  const rceTools = [
    'metasploit',
    'nc',
    'ncat',
    'netcat',
    'msfvenom',
    'weevely',
    'webshell',
  ];

  const discovered = [];

  for (const tool of rceTools) {
    const researchResults = await researchService.researchTools(`${tool} remote code execution`);
    discovered.push(...researchResults.tools);
  }

  return discovered;
}

module.exports = {
  discoverToolsForVulnerability,
  discoverToolsForRCE,
};

