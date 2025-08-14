/**
 * SMS Utilities for Threat Detection
 * Functions for analyzing SMS content and validating senders
 */

interface SmsMetadata {
  sender: string;
  timestamp: Date;
  carrier?: string;
  messageId?: string;
}

/**
 * Analyzes SMS content for suspicious patterns
 */
export function analyzeSmsContent(content: string): {
  isSuspicious: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  let isSuspicious = false;

  // Check for common SMS scam patterns
  const scamPatterns = [
    /congratulations.*won/i,
    /click.*link.*claim/i,
    /verify.*account.*immediately/i,
    /suspended.*account/i,
    /free.*gift.*card/i,
    /lottery.*winner/i,
    /cash.*prize/i,
    /limited.*time.*offer/i,
    /act.*now.*expires/i,
    /call.*immediately/i
  ];

  for (const pattern of scamPatterns) {
    if (pattern.test(content)) {
      reasons.push(`Scam pattern detected: ${pattern.source}`);
      isSuspicious = true;
    }
  }

  // Check for suspicious URLs
  const urlPattern = /https?:\/\/[^\s]+/gi;
  const urls = content.match(urlPattern);
  if (urls) {
    for (const url of urls) {
      if (isSuspiciousUrl(url)) {
        reasons.push('Suspicious URL detected');
        isSuspicious = true;
      }
    }
  }

  // Check for urgency indicators
  const urgencyWords = ['urgent', 'immediate', 'expires', 'hurry', 'now', 'today only'];
  const urgencyCount = urgencyWords.filter(word => 
    content.toLowerCase().includes(word)
  ).length;

  if (urgencyCount >= 2) {
    reasons.push('Multiple urgency indicators detected');
    isSuspicious = true;
  }

  // Check for financial terms
  const financialTerms = ['bank', 'credit card', 'ssn', 'social security', 'wire transfer', 'bitcoin'];
  const hasFinancialTerms = financialTerms.some(term => 
    content.toLowerCase().includes(term)
  );

  if (hasFinancialTerms) {
    reasons.push('Financial-related content detected');
    isSuspicious = true;
  }

  return { isSuspicious, reasons };
}

/**
 * Validates SMS sender ID against known patterns
 */
export function validateSenderId(senderId: string): boolean {
  if (!senderId) {
    return false;
  }

  // Check for legitimate sender patterns
  const legitimatePatterns = [
    /^\+1[0-9]{10}$/, // US phone number
    /^[A-Z0-9]{2,11}$/, // Alphanumeric sender ID
    /^[0-9]{5,6}$/ // Short code
  ];

  const isValidFormat = legitimatePatterns.some(pattern => pattern.test(senderId));
  
  if (!isValidFormat) {
    return false;
  }

  // Check against known scam sender IDs
  const knownScamSenders = [
    'SCAM',
    'FAKE',
    'PHISH',
    'VIRUS',
    '00000',
    '11111',
    '99999'
  ];

  if (knownScamSenders.includes(senderId.toUpperCase())) {
    return false;
  }

  // Check for spoofed bank/service names
  const spoofedServices = [
    'PAYPAL',
    'AMAZON',
    'APPLE',
    'GOOGLE',
    'MICROSOFT',
    'FACEBOOK',
    'INSTAGRAM',
    'TWITTER',
    'NETFLIX',
    'SPOTIFY'
  ];

  const suspiciousSpoofing = spoofedServices.some(service => 
    senderId.toUpperCase().includes(service) && !isVerifiedSender(senderId, service)
  );

  if (suspiciousSpoofing) {
    return false;
  }

  return true;
}

/**
 * Checks if an SMS sender is verified for a specific service
 */
function isVerifiedSender(senderId: string, service: string): boolean {
  // Placeholder for verified sender checking
  // In real implementation, this would check against a database of verified senders
  const verifiedSenders: Record<string, string[]> = {
    'PAYPAL': ['PAYPAL', '729725'],
    'AMAZON': ['AMAZON', '262966'],
    'APPLE': ['APPLE', '20737'],
    'GOOGLE': ['GOOGLE', '22000'],
    // Add more verified senders
  };

  const verified = verifiedSenders[service.toUpperCase()] || [];
  return verified.includes(senderId.toUpperCase());
}

/**
 * Checks if a URL in SMS is suspicious
 */
function isSuspiciousUrl(url: string): boolean {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();

    // Check for URL shorteners (common in SMS phishing)
    const shorteners = [
      'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
      'short.link', 'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly'
    ];

    if (shorteners.includes(domain)) {
      return true;
    }

    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.zip'];
    if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
      return true;
    }

    // Check for IP addresses instead of domains
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(domain)) {
      return true;
    }

    // Check for suspicious subdomains
    const suspiciousSubdomains = ['secure', 'verify', 'update', 'confirm', 'login'];
    const parts = domain.split('.');
    if (parts.length > 2) {
      const subdomain = parts[0];
      if (suspiciousSubdomains.includes(subdomain)) {
        return true;
      }
    }

    // Check for lookalike domains
    const legitimateDomains = ['paypal.com', 'amazon.com', 'apple.com', 'google.com'];
    for (const legitDomain of legitimateDomains) {
      if (isLookAlikeDomain(domain, legitDomain)) {
        return true;
      }
    }

    return false;
  } catch {
    // If URL parsing fails, consider it suspicious
    return true;
  }
}

/**
 * Checks if a domain is a lookalike of a legitimate domain
 */
function isLookAlikeDomain(domain: string, legitimateDomain: string): boolean {
  // Simple Levenshtein distance check
  const distance = levenshteinDistance(domain, legitimateDomain);
  const maxDistance = Math.floor(legitimateDomain.length * 0.2); // 20% difference allowed
  
  return distance > 0 && distance <= maxDistance;
}

/**
 * Calculates Levenshtein distance between two strings
 */
function levenshteinDistance(str1: string, str2: string): number {
  const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));

  for (let i = 0; i <= str1.length; i++) {
    matrix[0][i] = i;
  }

  for (let j = 0; j <= str2.length; j++) {
    matrix[j][0] = j;
  }

  for (let j = 1; j <= str2.length; j++) {
    for (let i = 1; i <= str1.length; i++) {
      const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1, // deletion
        matrix[j - 1][i] + 1, // insertion
        matrix[j - 1][i - 1] + indicator // substitution
      );
    }
  }

  return matrix[str2.length][str1.length];
}
