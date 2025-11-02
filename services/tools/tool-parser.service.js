const { chat } = require('../../config/mistral.config');

async function parseToolOutput(toolName, output, format = 'auto') {
  try {
    // Try structured parsing first
    if (format === 'json' || output.trim().startsWith('{')) {
      return JSON.parse(output);
    }

    if (format === 'xml' || output.trim().startsWith('<?xml')) {
      const xml2js = require('xml2js');
      const parser = new xml2js.Parser();
      return await parser.parseStringPromise(output);
    }

    // Tool-specific parsers
    switch (toolName) {
      case 'nmap':
        return parseNmapOutput(output);
      case 'sqlmap':
        return parseSqlmapOutput(output);
      case 'nikto':
        return parseNiktoOutput(output);
      case 'metasploit':
      case 'msfconsole':
        return parseMetasploitOutput(output);
      default:
        // Use AI to parse unknown formats
        return await parseWithAI(toolName, output);
    }
  } catch (error) {
    console.error(`Error parsing ${toolName} output:`, error);
    // Fallback to AI parsing
    return await parseWithAI(toolName, output);
  }
}

function parseNmapOutput(output) {
  // Enhanced parsing for Metasploitable detection
  const result = {
    openPorts: [],
    services: [],
    hosts: [],
  };

  // Enhanced nmap parsing - multiple patterns to catch different formats
  // Pattern 1: Standard port/service line: "21/tcp   open  ftp     vsftpd 2.3.4"
  const portServiceRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*?)(?:\n|$)/g;
  let match;
  while ((match = portServiceRegex.exec(output)) !== null) {
    const port = parseInt(match[1]);
    const service = match[3];
    const version = (match[4] || '').trim();
    
    result.openPorts.push({
      port: port,
      protocol: match[2],
      state: 'open',
      service: service,
    });
    
    // Also add to services with version info
    result.services.push({
      port: port,
      name: service,
      service: service,
      version: version,
    });
  }
  
  // Pattern 2: More detailed version detection lines
  const versionRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)\s+(\S+.*?)(?:\n|$)/g;
  while ((match = versionRegex.exec(output)) !== null) {
    const port = parseInt(match[1]);
    const existingService = result.services.find(s => s.port === port);
    if (!existingService) {
      result.services.push({
        port: port,
        name: match[3],
        service: match[3],
        version: match[4].trim(),
      });
    } else {
      existingService.version = match[4].trim();
    }
  }
  
  // Normalize: ensure ports array matches services
  result.ports = [...new Set(result.openPorts.map(p => p.port))];

  // Extract hosts
  const hostRegex = /Nmap scan report for (.+)/g;
  while ((match = hostRegex.exec(output)) !== null) {
    result.hosts.push(match[1]);
  }

  return result;
}

function parseSqlmapOutput(output) {
  const result = {
    vulnerable: false,
    injectionType: null,
    parameters: [],
    database: null,
  };

  // Check for SQL injection
  if (output.includes('injectable') || output.includes('vulnerable')) {
    result.vulnerable = true;
  }

  // Extract injection type
  const injectionMatch = output.match(/Type: (.+)/);
  if (injectionMatch) {
    result.injectionType = injectionMatch[1].trim();
  }

  // Extract parameters
  const paramRegex = /Parameter: (.+?) \(/g;
  let match;
  while ((match = paramRegex.exec(output)) !== null) {
    result.parameters.push(match[1]);
  }

  // Extract database
  const dbMatch = output.match(/Database: (.+)/);
  if (dbMatch) {
    result.database = dbMatch[1].trim();
  }

  return result;
}

function parseNiktoOutput(output) {
  const result = {
    vulnerabilities: [],
    information: [],
  };

  // Extract vulnerabilities
  const vulnRegex = /\+\s+OSVDB-\d+:\s*(.+)/g;
  let match;
  while ((match = vulnRegex.exec(output)) !== null) {
    result.vulnerabilities.push({
      description: match[1].trim(),
      source: 'nikto',
    });
  }

  // Extract information
  const infoRegex = /\+\s+(.+):\s*(.+)/g;
  while ((match = infoRegex.exec(output)) !== null) {
    result.information.push({
      key: match[1].trim(),
      value: match[2].trim(),
    });
  }

  return result;
}

function parseMetasploitOutput(output) {
  const result = {
    sessions: [],
    exploits: [],
    success: false,
  };

  // Check for successful exploit
  if (output.includes('session opened') || output.includes('Command shell opened')) {
    result.success = true;
  }

  // Extract session IDs
  const sessionRegex = /session\s+(\d+)/gi;
  let match;
  while ((match = sessionRegex.exec(output)) !== null) {
    result.sessions.push(parseInt(match[1]));
  }

  return result;
}

async function parseWithAI(toolName, output) {
  try {
    const prompt = `Parse the output from the security tool "${toolName}". 
Extract:
1. Any vulnerabilities found
2. Open ports/services
3. Important findings
4. Any errors or warnings

Output format: JSON with keys: vulnerabilities (array), ports (array), findings (array), errors (array)

Output:
${output.substring(0, 5000)}`; // Limit output size

    const response = await chat([
      {
        role: 'system',
        content: 'You are a security tool output parser. Extract structured information from tool outputs.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ], {
      temperature: 0.3,
      maxTokens: 1500,
    });

    // Try to extract JSON from response
    const { parseAIJSON } = require('../utils/json-utils');
    const parsed = parseAIJSON(response);
    if (parsed) {
      return parsed;
    }
    
    // Fallback: try direct match
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      try {
        const cleaned = jsonMatch[0]
          .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '')
          .replace(/\n/g, '\\n')
          .replace(/\r/g, '\\r')
          .replace(/\t/g, '\\t');
        return JSON.parse(cleaned);
      } catch (e) {
        // Continue to fallback
      }
    }

    // Fallback: return raw output with basic structure
    return {
      raw: output,
      parsed: response,
      tool: toolName,
    };
  } catch (error) {
    console.error('Error in AI parsing:', error);
    return {
      raw: output,
      tool: toolName,
      error: error.message,
    };
  }
}

module.exports = {
  parseToolOutput,
  parseNmapOutput,
  parseSqlmapOutput,
  parseNiktoOutput,
  parseMetasploitOutput,
};

