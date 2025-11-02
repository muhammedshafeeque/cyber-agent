/**
 * Utility functions for parsing JSON from AI responses
 * Handles control characters and malformed JSON
 */

function cleanJSONString(jsonStr) {
  // First pass: remove control characters except those that should be escaped
  let cleaned = jsonStr
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '') // Remove control chars except \t, \n, \r
    .replace(/\n/g, '\\n') // Escape newlines
    .replace(/\r/g, '\\r') // Escape carriage returns
    .replace(/\t/g, '\\t'); // Escape tabs
  
  return cleaned;
}

function parseAIJSON(response) {
  try {
    // Try to extract JSON from response
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return null;
    }
    
    // First attempt with cleaned string
    let jsonStr = cleanJSONString(jsonMatch[0]);
    
    try {
      return JSON.parse(jsonStr);
    } catch (parseError) {
      // Second attempt: more aggressive cleaning
      jsonStr = jsonMatch[0].replace(/[\x00-\x1F]/g, '');
      try {
        return JSON.parse(jsonStr);
      } catch (e) {
        // Third attempt: fix common issues
        jsonStr = jsonStr
          .replace(/,(\s*[}\]])/g, '$1') // Remove trailing commas
          .replace(/'/g, '"') // Replace single quotes with double
          .replace(/(\w+):/g, '"$1":'); // Quote unquoted keys
        
        try {
          return JSON.parse(jsonStr);
        } catch (finalError) {
          return null;
        }
      }
    }
  } catch (error) {
    return null;
  }
}

module.exports = {
  cleanJSONString,
  parseAIJSON,
};

