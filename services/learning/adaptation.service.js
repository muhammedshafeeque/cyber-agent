/**
 * Learning and Adaptation Service
 * Learns from scan results, errors, and successes to improve next attempts
 */

const logger = require('../../cli/utils/logger');
const { createDocument, queryAQL } = require('../graph.service');
const { createAgentMemory } = require('../../models/graph.models');

/**
 * Analyze scan result and extract learnings
 */
async function learnFromScanResult(scanResult, context = {}) {
  const learnings = {
    successes: [],
    failures: [],
    patterns: [],
    recommendations: [],
    errors: [],
  };

  try {
    // Analyze what worked
    if (scanResult.success) {
      learnings.successes.push({
        tool: scanResult.tool,
        action: 'Scan execution',
        outcome: 'Success',
        details: `Tool ${scanResult.tool} executed successfully`,
      });
    }

    // Analyze vulnerabilities found
    if (scanResult.vulnerabilities && scanResult.vulnerabilities.length > 0) {
      learnings.successes.push({
        tool: scanResult.tool,
        action: 'Vulnerability detection',
        outcome: `Found ${scanResult.vulnerabilities.length} vulnerabilities`,
        details: scanResult.vulnerabilities.map(v => v.type).join(', '),
      });

      // Learn patterns
      scanResult.vulnerabilities.forEach(vuln => {
        learnings.patterns.push({
          type: vuln.type,
          severity: vuln.severity,
          context: context.target || 'unknown',
          tool: scanResult.tool,
        });
      });
    }

    // Analyze ports/services discovered
    if (scanResult.parsed) {
      if (scanResult.parsed.ports && scanResult.parsed.ports.length > 0) {
        learnings.successes.push({
          action: 'Port discovery',
          outcome: `Found ${scanResult.parsed.ports.length} open ports`,
          ports: scanResult.parsed.ports,
        });

        // Learn what services are running
        if (scanResult.parsed.services) {
          learnings.patterns.push({
            type: 'service_detection',
            services: scanResult.parsed.services.map(s => s.name || s),
            context: context.target,
          });
        }
      }
    }

    // Analyze errors
    if (scanResult.error) {
      learnings.errors.push({
        tool: scanResult.tool,
        error: scanResult.error,
        context: context,
        lesson: extractLessonFromError(scanResult.error),
      });
    }

    // Generate recommendations based on learnings
    learnings.recommendations = generateRecommendations(learnings, context);

    // Store in knowledge graph
    await storeLearnings(learnings, context);

    return learnings;
  } catch (error) {
    logger.error('Error learning from scan result:', error);
    return learnings;
  }
}

/**
 * Learn from errors and adapt
 */
async function learnFromError(error, action, context = {}) {
  const errorLearning = {
    error: error.message || error,
    action,
    context,
    timestamp: new Date().toISOString(),
    adaptation: null,
  };

  try {
    // Analyze error type and suggest adaptation
    errorLearning.adaptation = suggestAdaptationFromError(error, action);

    // Store error learning
    const memory = createAgentMemory(
      action,
      `Error encountered: ${error.message || error}`,
      context,
      { error: error.message, adaptation: errorLearning.adaptation }
    );
    await createDocument('agent_memory', memory);

    logger.info(`Learned from error: ${error.message}`);
    if (errorLearning.adaptation) {
      logger.step(`Suggested adaptation: ${errorLearning.adaptation.suggestion}`);
    }

    return errorLearning;
  } catch (err) {
    logger.error('Error in learning from error:', err);
    return errorLearning;
  }
}

/**
 * Extract lesson from error message
 */
function extractLessonFromError(errorMessage) {
  const error = errorMessage.toLowerCase();
  const lessons = [];

  if (error.includes('timeout')) {
    lessons.push({
      issue: 'Timeout',
      lesson: 'Scan took too long',
      suggestion: 'Use quicker scan profile or increase timeout',
    });
  }

  if (error.includes('permission') || error.includes('denied')) {
    lessons.push({
      issue: 'Permission denied',
      lesson: 'Insufficient permissions',
      suggestion: 'Run with sudo or use non-privileged scan options',
    });
  }

  if (error.includes('not found') || error.includes('command not found')) {
    lessons.push({
      issue: 'Tool not found',
      lesson: 'Tool is not installed',
      suggestion: 'Install tool or use alternative',
    });
  }

  if (error.includes('connection refused') || error.includes('refused')) {
    lessons.push({
      issue: 'Connection refused',
      lesson: 'Target not accepting connections',
      suggestion: 'Check if service is running or firewall blocking',
    });
  }

  if (error.includes('no route to host') || error.includes('unreachable')) {
    lessons.push({
      issue: 'Host unreachable',
      lesson: 'Cannot reach target',
      suggestion: 'Verify target IP/URL and network connectivity',
    });
  }

  return lessons;
}

/**
 * Suggest adaptation based on error
 */
function suggestAdaptationFromError(error, action) {
  const errorMsg = (error.message || error).toLowerCase();
  const adaptation = {
    suggestion: null,
    nextAction: null,
    toolAlternative: null,
    parameterChange: null,
  };

  if (errorMsg.includes('timeout')) {
    adaptation.suggestion = 'Use faster scan profile with fewer ports';
    adaptation.nextAction = 'retry_with_quick_scan';
    adaptation.parameterChange = { ports: '80,443,22' };
  }

  if (errorMsg.includes('permission')) {
    adaptation.suggestion = 'Try non-privileged scan options';
    adaptation.nextAction = 'retry_without_root';
    adaptation.parameterChange = { skipPrivileged: true };
  }

  if (errorMsg.includes('not found')) {
    adaptation.suggestion = 'Use alternative tool or install missing tool';
    adaptation.nextAction = 'try_alternative_tool';
  }

  if (errorMsg.includes('connection refused')) {
    adaptation.suggestion = 'Target service may be down or filtered';
    adaptation.nextAction = 'verify_service_status';
  }

  return adaptation;
}

/**
 * Generate recommendations based on learnings
 */
function generateRecommendations(learnings, context) {
  const recommendations = [];

  // If we found web services, recommend web-specific tools
  const hasWebService = learnings.patterns.some(p => 
    p.type === 'service_detection' && 
    p.services && 
    p.services.some(s => s.toLowerCase().includes('http') || s.toLowerCase().includes('apache') || s.toLowerCase().includes('nginx'))
  );

  if (hasWebService && !learnings.successes.some(s => s.tool === 'nikto')) {
    recommendations.push({
      type: 'tool_suggestion',
      tool: 'nikto',
      reason: 'Web service detected but not yet scanned',
      priority: 'high',
    });
  }

  // If we found SQL ports, recommend SQL tools
  const hasSQL = learnings.patterns.some(p =>
    p.type === 'service_detection' &&
    p.services &&
    p.services.some(s => s.toLowerCase().includes('mysql') || s.toLowerCase().includes('postgres'))
  );

  if (hasSQL && !learnings.successes.some(s => s.tool === 'sqlmap')) {
    recommendations.push({
      type: 'tool_suggestion',
      tool: 'sqlmap',
      reason: 'SQL service detected but not yet tested',
      priority: 'medium',
    });
  }

  // If we found vulnerabilities, recommend exploitation
  const hasVulnerabilities = learnings.successes.some(s => 
    s.action === 'Vulnerability detection'
  );

  if (hasVulnerabilities) {
    recommendations.push({
      type: 'next_action',
      action: 'exploitation',
      reason: 'Vulnerabilities found - ready for exploitation',
      priority: 'high',
    });
  }

  // Learn from errors - suggest alternatives
  learnings.errors.forEach(error => {
    if (error.lesson && error.lesson.length > 0) {
      error.lesson.forEach(lesson => {
        recommendations.push({
          type: 'adaptation',
          action: lesson.suggestion,
          reason: lesson.issue,
          priority: 'medium',
        });
      });
    }
  });

  return recommendations;
}

/**
 * Store learnings in knowledge graph
 */
async function storeLearnings(learnings, context) {
  try {
    // Store as agent memory
    const memory = createAgentMemory(
      'scan_learning',
      JSON.stringify(learnings.recommendations),
      context,
      {
        successes: learnings.successes.length,
        failures: learnings.failures.length,
        patterns: learnings.patterns.length,
        recommendations: learnings.recommendations,
      }
    );
    await createDocument('agent_memory', memory);

    logger.info(`Stored ${learnings.patterns.length} patterns and ${learnings.recommendations.length} recommendations`);
  } catch (error) {
    logger.error('Error storing learnings:', error);
  }
}

/**
 * Get previous learnings for context
 */
async function getPreviousLearnings(target, limit = 5) {
  try {
    const query = `
      FOR memory IN agent_memory
        FILTER memory.context.target == @target OR memory.context == @target
        SORT memory.timestamp DESC
        LIMIT @limit
        RETURN memory
    `;
    
    const results = await queryAQL(query, { target, limit });
    return results || [];
  } catch (error) {
    logger.error('Error getting previous learnings:', error);
    return [];
  }
}

/**
 * Analyze and adapt based on all previous learnings
 */
async function adaptStrategy(target, previousResults = []) {
  const adaptations = {
    toolChanges: [],
    parameterChanges: [],
    skipTools: [],
    addTools: [],
    strategy: 'quick', // Default to quick
  };

  try {
    // Get previous learnings
    const learnings = await getPreviousLearnings(target, 10);

    // Analyze patterns
    const errorPatterns = [];
    const successPatterns = [];

    learnings.forEach(learning => {
      if (learning.result && learning.result.errors) {
        errorPatterns.push(...learning.result.errors);
      }
      if (learning.result && learning.result.successes) {
        successPatterns.push(...learning.result.successes);
      }
    });

    // Adapt based on errors
    errorPatterns.forEach(error => {
      if (error.tool) {
        // If tool consistently fails, suggest alternative
        if (error.error.includes('not found')) {
          adaptations.skipTools.push(error.tool);
        }
        
        // If tool times out, use quicker parameters
        if (error.error.includes('timeout')) {
          adaptations.parameterChanges.push({
            tool: error.tool,
            change: { timeout: 60000 }, // Reduce timeout
          });
        }
      }
    });

    // Adapt based on successes
    successPatterns.forEach(success => {
      if (success.tool && !adaptations.addTools.includes(success.tool)) {
        // Tools that worked well
        adaptations.addTools.push(success.tool);
      }
    });

    // Determine strategy
    if (errorPatterns.length > successPatterns.length) {
      adaptations.strategy = 'conservative'; // More careful approach
    } else if (successPatterns.length > 3) {
      adaptations.strategy = 'aggressive'; // Can be more aggressive
    }

    logger.info(`Adaptation: Strategy=${adaptations.strategy}, Skip=${adaptations.skipTools.length} tools, Add=${adaptations.addTools.length} tools`);

    return adaptations;
  } catch (error) {
    logger.error('Error adapting strategy:', error);
    return adaptations;
  }
}

/**
 * Think before executing - analyze what simple actions can be done first
 */
async function thinkBeforeAction(target, discoveredServices = [], previousErrors = []) {
  const plan = {
    simpleActions: [],
    complexActions: [],
    riskAssessment: 'low',
    estimatedTime: 0,
  };

  try {
    // Simple actions that are fast and low-risk
    plan.simpleActions.push({
      action: 'quick_port_scan',
      tool: 'nmap',
      params: { ports: '80,443,22,21,25' },
      time: 30,
      risk: 'low',
      reason: 'Fast way to discover what services are running',
    });

    // If web service found, simple web scan
    if (discoveredServices.some(s => s.port === 80 || s.port === 443 || s.port === 8080)) {
      plan.simpleActions.push({
        action: 'basic_web_scan',
        tool: 'nikto',
        params: {},
        time: 60,
        risk: 'low',
        reason: 'Quick web vulnerability check',
      });
    }

    // Complex actions (only if simple ones succeed)
    plan.complexActions.push({
      action: 'deep_port_scan',
      tool: 'nmap',
      params: { ports: '1-65535' },
      time: 600,
      risk: 'medium',
      reason: 'Comprehensive port scan - only if needed',
    });

    // Learn from previous errors
    previousErrors.forEach(error => {
      if (error.includes('timeout')) {
        // Skip complex actions if previous timeout
        plan.complexActions = plan.complexActions.filter(a => a.time < 300);
      }
    });

    plan.estimatedTime = plan.simpleActions.reduce((sum, a) => sum + a.time, 0);

    logger.info(`Planning: ${plan.simpleActions.length} simple actions (~${plan.estimatedTime}s), ${plan.complexActions.length} complex actions available`);
    
    return plan;
  } catch (error) {
    logger.error('Error in thinking before action:', error);
    return plan;
  }
}

module.exports = {
  learnFromScanResult,
  learnFromError,
  adaptStrategy,
  thinkBeforeAction,
  getPreviousLearnings,
};

