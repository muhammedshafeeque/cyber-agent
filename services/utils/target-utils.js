/**
 * Utility functions for handling target input (IP addresses and URLs)
 */

/**
 * Check if target is an IP address
 */
function isIPAddress(target) {
  // IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  // IPv6 pattern (simplified)
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  
  return ipv4Pattern.test(target) || ipv6Pattern.test(target);
}

/**
 * Check if target is a URL
 */
function isURL(target) {
  try {
    const url = new URL(target);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (e) {
    return false;
  }
}

/**
 * Normalize target to handle both IPs and URLs
 */
function normalizeTarget(target) {
  // Remove any trailing slashes
  target = target.trim().replace(/\/+$/, '');
  
  // If it's an IP address without protocol, assume http
  if (isIPAddress(target)) {
    return `http://${target}`;
  }
  
  // If it's already a URL, return as-is
  if (isURL(target)) {
    return target;
  }
  
  // If it doesn't have protocol but has domain-like structure, add http://
  if (target.includes('.') && !target.includes('://')) {
    return `http://${target}`;
  }
  
  // Return as-is (might be hostname)
  return target;
}

/**
 * Get base URL from target (for web tools like sqlmap)
 */
function getBaseURL(target) {
  const normalized = normalizeTarget(target);
  
  try {
    const url = new URL(normalized);
    return `${url.protocol}//${url.host}`;
  } catch (e) {
    return normalized;
  }
}

/**
 * Get IP address from target (for network tools like nmap)
 */
function getIPAddress(target) {
  if (isIPAddress(target)) {
    return target;
  }
  
  try {
    const url = new URL(normalizeTarget(target));
    return url.hostname;
  } catch (e) {
    // If parsing fails, try to extract IP-like pattern
    const ipMatch = target.match(/(\d{1,3}\.){3}\d{1,3}/);
    if (ipMatch) {
      return ipMatch[0];
    }
    return target;
  }
}

/**
 * Get hostname/IP for tools that need it
 */
function getHostname(target) {
  if (isIPAddress(target)) {
    return target;
  }
  
  try {
    const url = new URL(normalizeTarget(target));
    return url.hostname;
  } catch (e) {
    return target.split('/')[0].split(':')[0];
  }
}

/**
 * Check if target is suitable for web-specific tools
 */
function isWebTarget(target) {
  const normalized = normalizeTarget(target);
  return normalized.startsWith('http://') || normalized.startsWith('https://');
}

module.exports = {
  isIPAddress,
  isURL,
  normalizeTarget,
  getBaseURL,
  getIPAddress,
  getHostname,
  isWebTarget,
};

