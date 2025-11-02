const { chat } = require('../../config/mistral.config');
const researchService = require('../research/research.service');
const { findSimilarVulnerabilities, findToolsForVulnerability } = require('../graph.service');

async function decideNextAction(agentState, context = 'general', additionalData = {}) {
  const prompt = buildDecisionPrompt(agentState, context, additionalData);
  
  try {
    const response = await chat([
      {
        role: 'system',
        content: 'You are an autonomous penetration testing agent. Make decisions about what actions to take next based on the current state and findings. Focus on achieving Remote Code Execution (RCE) when possible.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ], {
      temperature: 0.7,
      maxTokens: 1500,
    });

    const decision = parseDecisionResponse(response);
    
    return {
      action: decision.action || 'continue',
      reasoning: decision.reasoning || response,
      recommendedTools: decision.tools || [],
      nextPhase: decision.nextPhase,
      priority: decision.priority || 'medium',
    };
  } catch (error) {
    console.error('Error in decision service:', error);
    return defaultDecision(context);
  }
}

function buildDecisionPrompt(agentState, context, additionalData) {
  let prompt = `Current Agent State:
- Phase: ${agentState.currentPhase}
- Target: ${agentState.target}
- Vulnerabilities Found: ${agentState.discoveredVulnerabilities.length}
- Tools Installed: ${agentState.installedTools.length}
- RCE Goal: ${agentState.rceGoal ? 'Yes' : 'No'}
- RCE Achieved: ${agentState.rceAchieved ? 'Yes' : 'No'}
- Current Step: ${agentState.currentStep}

Context: ${context}

`;

  if (agentState.discoveredVulnerabilities.length > 0) {
    prompt += `Discovered Vulnerabilities:
${agentState.discoveredVulnerabilities.map((v, i) => 
  `${i + 1}. ${v.type} - ${v.description || 'No description'}`).join('\n')}

`;
  }

  if (additionalData.scanResults) {
    prompt += `Recent Scan Results:
${JSON.stringify(additionalData.scanResults, null, 2)}

`;
  }

  prompt += `Based on this information, what should be the next action? Provide:
1. Action to take (scan, install_tool, exploit, research, analyze)
2. Reasoning for this decision
3. Recommended tools (if any)
4. Next phase
5. Priority (high/medium/low)

Format your response as JSON with keys: action, reasoning, tools (array), nextPhase, priority.`;

  return prompt;
}

function parseDecisionResponse(response) {
  try {
    // Try to extract JSON from response
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    
    // Fallback: parse text response
    return {
      action: extractAction(response),
      reasoning: response,
      tools: extractTools(response),
      nextPhase: extractPhase(response),
      priority: extractPriority(response),
    };
  } catch (error) {
    console.error('Error parsing decision response:', error);
    return {
      action: 'continue',
      reasoning: response,
      tools: [],
      priority: 'medium',
    };
  }
}

function extractAction(text) {
  const actions = ['scan', 'install_tool', 'exploit', 'research', 'analyze', 'continue'];
  const lowerText = text.toLowerCase();
  
  for (const action of actions) {
    if (lowerText.includes(action)) {
      return action;
    }
  }
  return 'continue';
}

function extractTools(text) {
  const tools = [];
  const commonTools = ['nmap', 'sqlmap', 'nikto', 'metasploit', 'burp', 'dirb', 'gobuster'];
  
  const lowerText = text.toLowerCase();
  for (const tool of commonTools) {
    if (lowerText.includes(tool)) {
      tools.push(tool);
    }
  }
  
  return tools;
}

function extractPhase(text) {
  const phases = [
    'reconnaissance',
    'vulnerability_discovery',
    'research',
    'tool_installation',
    'exploitation',
    'analysis',
  ];
  
  const lowerText = text.toLowerCase();
  for (const phase of phases) {
    if (lowerText.includes(phase)) {
      return phase;
    }
  }
  return null;
}

function extractPriority(text) {
  const lowerText = text.toLowerCase();
  if (lowerText.includes('high')) return 'high';
  if (lowerText.includes('low')) return 'low';
  return 'medium';
}

async function researchVulnerability(vulnerability) {
  try {
    // Check knowledge graph first
    const similar = await findSimilarVulnerabilities(vulnerability.type, 5);
    const tools = await findToolsForVulnerability(vulnerability._id || vulnerability._key);

    if (similar.length > 0 || tools.length > 0) {
      return {
        similarVulnerabilities: similar,
        recommendedTools: tools,
        source: 'knowledge_graph',
      };
    }

    // Research online
    const researchResults = await researchService.researchTools(vulnerability.type);
    return {
      ...researchResults,
      source: 'internet',
    };
  } catch (error) {
    console.error('Error researching vulnerability:', error);
    return { tools: [], exploits: [], source: 'error' };
  }
}

async function decideToolsNeeded(agentState) {
  const prompt = `Given the current state:
- Vulnerabilities: ${agentState.discoveredVulnerabilities.map(v => v.type).join(', ')}
- Target: ${agentState.target}
- Goal: ${agentState.rceGoal ? 'RCE' : 'General security testing'}

What tools are needed? List tool names that should be installed/used.

Respond with JSON: {"tools": ["tool1", "tool2"], "reasoning": "..."}`;

  try {
    const response = await chat([
      {
        role: 'system',
        content: 'You are a penetration testing tool selection expert.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ]);

    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }

    return { tools: [], reasoning: response };
  } catch (error) {
    console.error('Error deciding tools:', error);
    return { tools: [], reasoning: 'Error in tool decision' };
  }
}

async function analyzeCurrentState(agentState) {
  const prompt = `Current penetration test state:
- Phase: ${agentState.currentPhase}
- Vulnerabilities: ${agentState.discoveredVulnerabilities.length}
- RCE Goal: ${agentState.rceGoal}
- RCE Achieved: ${agentState.rceAchieved}

Should testing continue? What is the next step?

Respond with JSON: {"shouldContinue": true/false, "recommendation": "..."}`;

  try {
    const response = await chat([
      {
        role: 'system',
        content: 'You are analyzing the progress of a penetration test.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ]);

    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }

    return {
      shouldContinue: !agentState.rceAchieved && agentState.currentStep < 50,
      recommendation: response,
    };
  } catch (error) {
    console.error('Error analyzing state:', error);
    return {
      shouldContinue: !agentState.rceAchieved,
      recommendation: 'Continue testing',
    };
  }
}

function defaultDecision(context) {
  const decisions = {
    reconnaissance: {
      action: 'scan',
      reasoning: 'Starting reconnaissance',
      nextPhase: 'vulnerability_discovery',
    },
    vulnerability_discovery: {
      action: 'scan',
      reasoning: 'Discovering vulnerabilities',
      nextPhase: 'research',
    },
    research: {
      action: 'research',
      reasoning: 'Researching vulnerabilities',
      nextPhase: 'tool_installation',
    },
  };

  return decisions[context] || {
    action: 'continue',
    reasoning: 'Continuing test',
    nextPhase: 'analysis',
  };
}

module.exports = {
  decideNextAction,
  researchVulnerability,
  decideToolsNeeded,
  analyzeCurrentState,
};

