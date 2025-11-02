const scraperService = require('./scraper.service');
const { createDocument } = require('../graph.service');
const { createTool, createExploit, createCVEEntry } = require('../../models/graph.models');

async function parseAndLearn(content, sourceType, url) {
  const learned = {
    tools: [],
    exploits: [],
    installationMethods: [],
    usagePatterns: [],
  };

  try {
    if (sourceType === 'github') {
      // Parse GitHub repository
      const installationInfo = await scraperService.extractInstallationInstructions(content);
      learned.installationMethods.push(installationInfo);

      // Extract tool information
      const toolInfo = extractToolInfo(content);
      if (toolInfo) {
        learned.tools.push(toolInfo);
      }
    } else if (sourceType === 'exploit-db' || sourceType === 'exploit') {
      // Parse exploit information
      const exploitInfo = extractExploitInfo(content);
      if (exploitInfo) {
        learned.exploits.push(exploitInfo);
      }
    }

    // Store in knowledge graph
    await storeLearnedKnowledge(learned, url);

    return learned;
  } catch (error) {
    console.error('Error in learning service:', error.message);
    return learned;
  }
}

function extractToolInfo(content) {
  try {
    const cheerio = require('cheerio');
    const $ = cheerio.load(content);

    const name = $('h1, h2').first().text().trim() || 'Unknown Tool';
    const description = $('p').first().text().trim() || '';
    
    // Extract usage examples
    const usageExamples = [];
    $('code, pre').each((i, elem) => {
      const code = $(elem).text();
      if (code.includes(name.toLowerCase())) {
        usageExamples.push(code.trim());
      }
    });

    // Detect installation method
    let installationMethod = 'unknown';
    const text = content.toLowerCase();
    if (text.includes('pip install')) installationMethod = 'pip';
    else if (text.includes('npm install')) installationMethod = 'npm';
    else if (text.includes('apt install')) installationMethod = 'apt';
    else if (text.includes('gem install')) installationMethod = 'gem';
    else if (text.includes('cargo install')) installationMethod = 'cargo';
    else if (text.includes('git clone')) installationMethod = 'git';

    // Detect version
    const versionMatch = content.match(/version[:\s]+([\d.]+)/i);
    const version = versionMatch ? versionMatch[1] : 'unknown';

    return {
      name: name.replace(/[^\w\s-]/g, '').trim(),
      description,
      version,
      installationMethod,
      usageExamples,
    };
  } catch (error) {
    console.error('Error extracting tool info:', error.message);
    return null;
  }
}

function extractExploitInfo(content) {
  try {
    const cheerio = require('cheerio');
    const $ = cheerio.load(content);

    const title = $('h1, h2, title').first().text().trim() || 'Unknown Exploit';
    
    // Extract code blocks
    const codeBlocks = [];
    $('code, pre').each((i, elem) => {
      const code = $(elem).text();
      if (code.length > 50) { // Meaningful code block
        codeBlocks.push(code.trim());
      }
    });

    // Extract CVE references
    const cveMatches = content.match(/CVE-\d{4}-\d+/gi);
    const cves = cveMatches ? [...new Set(cveMatches)] : [];

    // Detect language
    let language = 'unknown';
    if (content.includes('#!/bin/bash') || content.includes('bash')) language = 'bash';
    else if (content.includes('python') || content.includes('#!/usr/bin/env python')) language = 'python';
    else if (content.includes('#!/usr/bin/perl')) language = 'perl';
    else if (content.includes('#!/usr/bin/ruby')) language = 'ruby';

    return {
      title,
      code: codeBlocks.join('\n\n'),
      language,
      cves,
    };
  } catch (error) {
    console.error('Error extracting exploit info:', error.message);
    return null;
  }
}

async function storeLearnedKnowledge(learned, sourceUrl) {
  try {
    const { createDocument, createEdge } = require('../graph.service');
    const { createResearchSource, createTool, createExploit, createCVEEntry } = require('../../models/graph.models');

    // Store research source
    const sourceDoc = createResearchSource(sourceUrl);
    let savedSource = null;
    try {
      savedSource = await createDocument('research_sources', sourceDoc);
    } catch (error) {
      console.error('Error saving research source:', error);
    }

    // Store tools
    for (const tool of learned.tools) {
      const toolDoc = createTool(
        tool.name,
        tool.version || 'unknown',
        tool.installationMethod || 'unknown'
      );
      const savedTool = await createDocument('tools', toolDoc);
      
      // Link to source
      if (savedSource && savedSource._id && savedTool && savedTool._id) {
        try {
          await createEdge('learned_from', savedTool._id, savedSource._id);
        } catch (error) {
          console.error('Error creating edge:', error);
        }
      }
    }

    // Store exploits
    for (const exploit of learned.exploits) {
      const exploitDoc = createExploit(
        exploit.title,
        exploit.code,
        exploit.language,
        'unknown' // vulnerability type
      );
      const savedExploit = await createDocument('exploits', exploitDoc);
      
      // Link to source
      if (savedSource && savedSource._id && savedExploit && savedExploit._id) {
        try {
          await createEdge('learned_from', savedExploit._id, savedSource._id);
        } catch (error) {
          console.error('Error creating edge:', error);
        }
      }

      // Link to CVEs
      for (const cveId of exploit.cves) {
        try {
          const cveDoc = createCVEEntry(cveId, '', 'unknown', new Date().toISOString());
          const savedCVE = await createDocument('cves', cveDoc);
          if (savedExploit && savedExploit._id && savedCVE && savedCVE._id) {
            await createEdge('exploits', savedExploit._id, savedCVE._id);
          }
        } catch (error) {
          console.error(`Error linking CVE ${cveId}:`, error);
        }
      }
    }

    return true;
  } catch (error) {
    console.error('Error storing learned knowledge:', error.message);
    return false;
  }
}

// Moved to graph.models.js

module.exports = {
  parseAndLearn,
  extractToolInfo,
  extractExploitInfo,
  storeLearnedKnowledge,
};

