const { chat } = require('../../config/mistral.config');
const { findSimilarVulnerabilities } = require('../graph.service');

async function createAttackPlan(target, goal = 'rce') {
  const prompt = `Create a penetration testing attack plan for:
- Target: ${target}
- Primary Goal: ${goal === 'rce' ? 'Remote Code Execution (RCE)' : 'General security assessment'}

Provide a step-by-step attack plan in phases:
1. Reconnaissance
2. Vulnerability Discovery
3. Exploitation Planning
4. RCE Achievement (if goal is RCE)

Format as JSON with phases array containing: phase_name, description, tools_needed, expected_outcomes`;

  try {
    const response = await chat([
      {
        role: 'system',
        content: 'You are an expert penetration tester creating attack plans. Focus on practical, actionable steps.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ], {
      temperature: 0.8,
      maxTokens: 2000,
    });

    const plan = parsePlanResponse(response);
    
    // Enhance with knowledge graph data
    const enhancedPlan = await enhancePlanWithKnowledge(plan, target);
    
    return enhancedPlan;
  } catch (error) {
    console.error('Error creating attack plan:', error);
    return defaultAttackPlan(target, goal);
  }
}

function parsePlanResponse(response) {
  try {
    const { parseAIJSON } = require('../utils/json-utils');
    const parsed = parseAIJSON(response);
    if (parsed) {
      return parsed;
    }

    // Fallback: create plan from text
    return {
      phases: [
        {
          phase_name: 'reconnaissance',
          description: 'Initial reconnaissance',
          tools_needed: ['nmap'],
          expected_outcomes: 'Discover open ports and services',
        },
        {
          phase_name: 'vulnerability_discovery',
          description: 'Discover vulnerabilities',
          tools_needed: ['nikto', 'sqlmap'],
          expected_outcomes: 'Identify security weaknesses',
        },
        {
          phase_name: 'exploitation',
          description: 'Exploit vulnerabilities',
          tools_needed: ['metasploit'],
          expected_outcomes: 'Gain access or execute code',
        },
      ],
    };
  } catch (error) {
    console.error('Error parsing plan:', error);
    return defaultAttackPlan();
  }
}

async function enhancePlanWithKnowledge(plan, target) {
  // Query knowledge graph for similar targets and techniques
  try {
    const similarVulns = await findSimilarVulnerabilities('web', 10);
    
    if (similarVulns.length > 0) {
      plan.knowledge_graph_insights = {
        similar_vulnerabilities: similarVulns.length,
        recommendations: 'Use knowledge from previous similar tests',
      };
    }

    return plan;
  } catch (error) {
    console.error('Error enhancing plan:', error);
    return plan;
  }
}

async function buildAttackChain(vulnerabilities, target) {
  const prompt = `Given these vulnerabilities:
${vulnerabilities.map((v, i) => `${i + 1}. ${v.type} - ${v.description || ''}`).join('\n')}

Target: ${target}
Goal: Remote Code Execution

Create an attack chain that links these vulnerabilities to achieve RCE. Show the sequence of exploitation.

Format as JSON:
{
  "chain": [
    {"step": 1, "vulnerability": "...", "tool": "...", "action": "..."},
    ...
  ],
  "explanation": "..."
}`;

  try {
    const response = await chat([
      {
        role: 'system',
        content: 'You are an expert at chaining vulnerabilities to achieve RCE.',
      },
      {
        role: 'user',
        content: prompt,
      },
    ]);

    const { parseAIJSON } = require('../utils/json-utils');
    const parsed = parseAIJSON(response);
    if (parsed) {
      return parsed;
    }

    return {
      chain: vulnerabilities.map((v, i) => ({
        step: i + 1,
        vulnerability: v.type,
        tool: 'metasploit',
        action: 'Exploit',
      })),
      explanation: response.substring(0, 1000),
    };
  } catch (error) {
    console.error('Error building attack chain:', error);
    return { chain: [], explanation: 'Error building chain' };
  }
}

function defaultAttackPlan(target, goal) {
  return {
    target,
    goal,
    phases: [
      {
        phase_name: 'reconnaissance',
        description: `Initial reconnaissance of ${target}`,
        tools_needed: ['nmap'],
        expected_outcomes: 'Discover open ports, services, and versions',
      },
      {
        phase_name: 'vulnerability_discovery',
        description: 'Scan for vulnerabilities',
        tools_needed: ['nikto', 'sqlmap'],
        expected_outcomes: 'Identify security vulnerabilities',
      },
      {
        phase_name: 'exploitation',
        description: goal === 'rce' ? 'Attempt to achieve RCE' : 'Exploit vulnerabilities',
        tools_needed: ['metasploit'],
        expected_outcomes: goal === 'rce' ? 'Remote code execution' : 'Successful exploitation',
      },
    ],
  };
}

module.exports = {
  createAttackPlan,
  buildAttackChain,
};

