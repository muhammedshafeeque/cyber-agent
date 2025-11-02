const { chat, analyzeImage } = require('../config/mistral.config');
const toolParser = require('./tools/tool-parser.service');
const logger = require('../cli/utils/logger');
const fs = require('fs-extra');
// Sharp is optional - only needed for advanced image processing
// Making it optional to avoid native dependency issues
let sharp = null;
try {
  sharp = require('sharp');
} catch (error) {
  // Sharp not available, will use basic image reading
  console.warn('Sharp not available - basic image support only');
}

async function analyzeOutput(toolName, output, options = {}) {
  try {
    // Parse structured output
    const parsed = await toolParser.parseToolOutput(toolName, output);
    
    // Extract vulnerabilities
    const vulnerabilities = await extractVulnerabilities(parsed, toolName);
    
    // Extract attack surfaces
    const attackSurfaces = await extractAttackSurfaces(parsed);
    
    // Identify RCE opportunities
    const rceOpportunities = await identifyRCEOpportunities(vulnerabilities, parsed);
    
    // Normalize parsed data to ensure consistent format
    const normalizedParsed = {
      ...parsed,
      ports: parsed.ports || parsed.openPorts?.map(p => p.port) || [],
      services: parsed.services || [],
    };
    
    return {
      tool: toolName,
      parsed: normalizedParsed,
      vulnerabilities,
      attackSurfaces,
      rceOpportunities,
      ports: normalizedParsed.ports,
      services: normalizedParsed.services,
      summary: generateSummary(vulnerabilities, attackSurfaces, rceOpportunities),
    };
  } catch (error) {
    console.error('Error analyzing output:', error);
    return {
      tool: toolName,
      raw: output,
      error: error.message,
    };
  }
}

async function extractVulnerabilities(parsedData, toolName) {
  const vulnerabilities = [];

  try {
    // Direct vulnerabilities from parsed data
    if (parsedData.vulnerabilities) {
      vulnerabilities.push(...parsedData.vulnerabilities);
    }

    // Extract from ports/services
    if (parsedData.services) {
      for (const service of parsedData.services) {
        const vulns = await identifyServiceVulnerabilities(service);
        vulnerabilities.push(...vulns);
      }
    }

    // Use AI to identify vulnerabilities if not found
    if (vulnerabilities.length === 0 && parsedData.raw) {
      const aiVulns = await identifyVulnerabilitiesWithAI(parsedData.raw, toolName);
      vulnerabilities.push(...aiVulns);
    }

    return vulnerabilities;
  } catch (error) {
    console.error('Error extracting vulnerabilities:', error);
    return vulnerabilities;
  }
}

async function identifyServiceVulnerabilities(service) {
  const vulnerabilities = [];

  // Metasploitable-specific vulnerable services (high priority for RCE)
  const metasploitableExploits = {
    'vsftpd 2.3.4': { type: 'backdoor', cve: 'CVE-2011-2523', exploit: 'exploit/unix/ftp/vsftpd_234_backdoor', rce: true },
    'OpenSSH 4.7p1': { type: 'weak_keys', exploit: 'exploit/multi/ssh/sshexec', rce: true },
    'distcc': { type: 'command_execution', cve: 'CVE-2004-2687', exploit: 'exploit/unix/misc/distcc_exec', rce: true },
    'UnrealIRCd': { type: 'backdoor', cve: 'CVE-2010-2075', exploit: 'exploit/unix/irc/unreal_ircd_3281_backdoor', rce: true },
    'proftpd': { type: 'backdoor', cve: 'CVE-2011-4157', exploit: 'exploit/unix/ftp/proftpd_133c_backdoor', rce: true },
    'ingreslock': { type: 'command_execution', exploit: 'exploit/unix/misc/distcc_exec', rce: true },
    'rlogin': { type: 'weak_auth', exploit: 'auxiliary/scanner/rservices/rlogin_login', rce: false },
    'rexec': { type: 'weak_auth', exploit: 'exploit/multi/samba/usermap_script', rce: true },
    'rsh': { type: 'weak_auth', exploit: 'exploit/multi/samba/usermap_script', rce: true },
  };

  // Check if service matches known vulnerable pattern
  const serviceName = (service.name || '').toLowerCase();
  const serviceVersion = (service.version || '').toLowerCase();
  const serviceKey = `${serviceName} ${serviceVersion}`.trim();
  
  for (const [key, vuln] of Object.entries(metasploitableExploits)) {
    if (serviceKey.includes(key.toLowerCase()) || serviceName.includes(key.toLowerCase())) {
      vulnerabilities.push({
        type: vuln.type || 'known_vulnerability',
        description: `Known ${vuln.type} in ${service.name || serviceName} - ${vuln.cve || 'exploit available'}`,
        severity: 'critical',
        service: service.name || serviceName,
        port: service.port,
        version: service.version,
        cve: vuln.cve,
        exploit: vuln.exploit,
        metasploit_module: vuln.exploit,
        canLeadToRCE: vuln.rce || false,
        confidence: 'high',
      });
      
      logger.info(`Identified vulnerable service: ${service.name} - ${vuln.exploit}`);
    }
  }

  // Common vulnerable services/versions
  const vulnerableVersions = {
    'apache': ['2.2', '2.4.0', '2.4.1'],
    'nginx': ['1.0', '1.1', '1.2'],
    'php': ['5.6', '7.0', '7.1'],
    'mysql': ['5.5', '5.6', '5.7'],
    'ssh': ['6.0', '7.0'],
  };

  if (service.service && service.version) {
    const serviceName = service.service.toLowerCase();
    for (const [vulnService, versions] of Object.entries(vulnerableVersions)) {
      if (serviceName.includes(vulnService)) {
        for (const version of versions) {
          if (service.version.includes(version)) {
            vulnerabilities.push({
              type: 'Outdated Service Version',
              description: `${service.service} ${service.version} may be vulnerable`,
              severity: 'medium',
              service: service.service,
              version: service.version,
            });
          }
        }
      }
    }
  }

  return vulnerabilities;
}

async function identifyVulnerabilitiesWithAI(output, toolName) {
  try {
    const prompt = `Analyze this security scan output from ${toolName} and identify:
1. Any security vulnerabilities
2. Potential attack vectors
3. Configuration issues

For each vulnerability, provide: type, description, severity (high/medium/low), and potential impact.

Output format: JSON array with keys: type, description, severity, impact

Output:
${output.substring(0, 4000)}`;

    const response = await chat([
      {
        role: 'system',
        content: 'You are a security expert analyzing scan results. Identify vulnerabilities and security issues.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ], {
      temperature: 0.5,
      maxTokens: 2000,
    });

    const { parseAIJSON } = require('./utils/json-utils');
    const parsed = parseAIJSON(response);
    if (parsed && Array.isArray(parsed)) {
      return parsed;
    }
    
    // Try array format
    const jsonMatch = response.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      try {
        const cleaned = jsonMatch[0]
          .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '')
          .replace(/\n/g, '\\n')
          .replace(/\r/g, '\\r')
          .replace(/\t/g, '\\t');
        return JSON.parse(cleaned);
      } catch (e) {
        // Continue to return empty array
      }
    }

    return [];
  } catch (error) {
    console.error('Error in AI vulnerability identification:', error);
    return [];
  }
}

async function extractAttackSurfaces(parsedData) {
  const surfaces = [];

  // Open ports
  if (parsedData.openPorts) {
    surfaces.push({
      type: 'network_port',
      details: parsedData.openPorts,
      description: 'Open network ports',
    });
  }

  // Web services
  if (parsedData.services) {
    const webServices = parsedData.services.filter(s => 
      s.service && (s.service.includes('http') || s.service.includes('www'))
    );
    if (webServices.length > 0) {
      surfaces.push({
        type: 'web_service',
        details: webServices,
        description: 'Web services detected',
      });
    }
  }

  // Database services
  if (parsedData.services) {
    const dbServices = parsedData.services.filter(s =>
      s.service && (s.service.includes('mysql') || s.service.includes('postgres') || s.service.includes('mongo'))
    );
    if (dbServices.length > 0) {
      surfaces.push({
        type: 'database_service',
        details: dbServices,
        description: 'Database services exposed',
      });
    }
  }

  // Vulnerable parameters (from sqlmap, etc.)
  if (parsedData.parameters && parsedData.parameters.length > 0) {
    surfaces.push({
      type: 'vulnerable_parameters',
      details: parsedData.parameters,
      description: 'Vulnerable input parameters',
    });
  }

  return surfaces;
}

async function identifyRCEOpportunities(vulnerabilities, parsedData) {
  const opportunities = [];

  // Check vulnerabilities for RCE potential
  for (const vuln of vulnerabilities) {
    const rceKeywords = [
      'command injection',
      'code execution',
      'rce',
      'file upload',
      'deserialization',
      'eval',
      'exec',
      'system call',
    ];

    const vulnText = `${vuln.type} ${vuln.description || ''}`.toLowerCase();

    if (rceKeywords.some(keyword => vulnText.includes(keyword))) {
      opportunities.push({
        vulnerability: vuln,
        rceType: identifyRCEType(vuln),
        confidence: 'high',
        exploitationMethod: await suggestExploitationMethod(vuln),
      });
    }
  }

  // Check for file upload capabilities
  if (parsedData.services) {
    const webServices = parsedData.services.filter(s =>
      s.service && (s.service.includes('http') || s.service.includes('www'))
    );
    if (webServices.length > 0) {
      opportunities.push({
        vulnerability: {
          type: 'File Upload',
          description: 'Web service may allow file uploads',
        },
        rceType: 'file_upload',
        confidence: 'medium',
        exploitationMethod: 'Upload webshell and execute',
      });
    }
  }

  return opportunities;
}

function identifyRCEType(vulnerability) {
  const vulnText = `${vulnerability.type} ${vulnerability.description || ''}`.toLowerCase();

  if (vulnText.includes('command injection')) return 'command_injection';
  if (vulnText.includes('file upload')) return 'file_upload';
  if (vulnText.includes('deserialization')) return 'deserialization';
  if (vulnText.includes('eval') || vulnText.includes('exec')) return 'code_eval';
  
  return 'unknown';
}

async function suggestExploitationMethod(vulnerability) {
  try {
    const prompt = `Given this vulnerability, suggest how to achieve Remote Code Execution:
Type: ${vulnerability.type}
Description: ${vulnerability.description || 'No description'}

Provide a brief exploitation method and recommended tools.`;

    const response = await chat([
      {
        role: 'system',
        content: 'You are a penetration testing expert specializing in RCE.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ], {
      temperature: 0.7,
      maxTokens: 500,
    });

    return response;
  } catch (error) {
    return 'Manual exploitation required';
  }
}

async function analyzeScreenshot(imagePath) {
  try {
    // Read and convert image to base64
    const imageBuffer = await fs.readFile(imagePath);
    const base64Image = imageBuffer.toString('base64');

    const prompt = `Analyze this screenshot from a security tool or application interface. 
Identify:
1. What tool/interface is shown
2. Any security-relevant information (ports, services, vulnerabilities, etc.)
3. Current configuration or state
4. Recommended next actions

Provide structured analysis.`;

    const analysis = await analyzeImage(base64Image, prompt);
    
    return {
      image: imagePath,
      analysis,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    console.error('Error analyzing screenshot:', error);
    return {
      image: imagePath,
      error: error.message,
    };
  }
}

async function analyzeUserOutput(output) {
  try {
    const prompt = `Analyze this output/text provided by the user. 
Extract:
1. Any security vulnerabilities or findings
2. Important information (IPs, ports, services, etc.)
3. Current state or configuration
4. Recommended next steps for penetration testing

Output:
${output.substring(0, 5000)}`;

    const analysis = await chat([
      {
        role: 'system',
        content: 'You are a security expert analyzing user-provided output.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ], {
      temperature: 0.5,
      maxTokens: 2000,
    });

    return {
      analysis,
      extractedInfo: extractStructuredInfo(analysis),
      recommendations: extractRecommendations(analysis),
    };
  } catch (error) {
    console.error('Error analyzing user output:', error);
    return {
      error: error.message,
    };
  }
}

function extractStructuredInfo(analysis) {
  const info = {
    ips: [],
    ports: [],
    services: [],
    vulnerabilities: [],
  };

  // Extract IPs
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const ips = analysis.match(ipRegex);
  if (ips) {
    info.ips = [...new Set(ips)];
  }

  // Extract ports
  const portRegex = /(?:port|Port|PORT)\s*:?\s*(\d+)/gi;
  let match;
  while ((match = portRegex.exec(analysis)) !== null) {
    info.ports.push(parseInt(match[1]));
  }

  return info;
}

function extractRecommendations(analysis) {
  const recommendations = [];
  
  const recKeywords = ['recommend', 'should', 'next step', 'try', 'use'];
  const lines = analysis.split('\n');

  for (const line of lines) {
    const lowerLine = line.toLowerCase();
    if (recKeywords.some(keyword => lowerLine.includes(keyword))) {
      recommendations.push(line.trim());
    }
  }

  return recommendations;
}

function generateSummary(vulnerabilities, attackSurfaces, rceOpportunities) {
  return {
    totalVulnerabilities: vulnerabilities.length,
    totalAttackSurfaces: attackSurfaces.length,
    rceOpportunities: rceOpportunities.length,
    highSeverity: vulnerabilities.filter(v => v.severity === 'high').length,
    mediumSeverity: vulnerabilities.filter(v => v.severity === 'medium').length,
    lowSeverity: vulnerabilities.filter(v => v.severity === 'low').length,
    canAchieveRCE: rceOpportunities.length > 0,
  };
}

module.exports = {
  analyzeOutput,
  extractVulnerabilities,
  extractAttackSurfaces,
  identifyRCEOpportunities,
  analyzeScreenshot,
  analyzeUserOutput,
};

