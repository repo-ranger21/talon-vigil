/**
 * Email Utilities for Threat Detection
 * Functions for analyzing email headers, attachments, and URLs
 */

interface EmailHeaders {
  from: string;
  to: string;
  subject: string;
  'return-path'?: string;
  'received'?: string[];
  'dkim-signature'?: string;
  'spf'?: string;
}

interface Attachment {
  filename: string;
  contentType: string;
  size: number;
  hash?: string;
}

/**
 * Analyzes email headers for suspicious patterns
 */
export function analyzeEmailHeaders(headers: EmailHeaders): boolean {
  if (!headers || !headers.from || !headers.to) {
    return false;
  }

  // Check for spoofed return-path
  if (headers['return-path'] && !headers['return-path'].includes(extractDomain(headers.from))) {
    return false;
  }

  // Check for missing SPF/DKIM
  if (!headers['dkim-signature'] && !headers.spf) {
    return false;
  }

  // Check for suspicious received headers
  if (headers.received && headers.received.length > 10) {
    return false;
  }

  return true;
}

/**
 * Scans attachments for malicious content
 */
export async function scanAttachments(attachments: Attachment[]): Promise<boolean> {
  if (!attachments || attachments.length === 0) {
    return false;
  }

  const dangerousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js'];
  const suspiciousTypes = ['application/x-msdownload', 'application/x-executable'];

  for (const attachment of attachments) {
    // Check dangerous file extensions
    const hasEvilExtension = dangerousExtensions.some(ext => 
      attachment.filename.toLowerCase().endsWith(ext)
    );

    // Check suspicious MIME types
    const hasSuspiciousType = suspiciousTypes.includes(attachment.contentType);

    // Check file size (very large files might be suspicious)
    const isTooLarge = attachment.size > 50 * 1024 * 1024; // 50MB

    if (hasEvilExtension || hasSuspiciousType || isTooLarge) {
      return true;
    }

    // If we have a hash, check against known malware database
    if (attachment.hash && await checkMalwareHash(attachment.hash)) {
      return true;
    }
  }

  return false;
}

/**
 * Checks URL reputation against threat intelligence feeds
 */
export async function checkUrlReputation(content: string): Promise<boolean> {
  const urlPattern = /https?:\/\/[^\s<>"']+/gi;
  const urls = content.match(urlPattern);

  if (!urls || urls.length === 0) {
    return false;
  }

  for (const url of urls) {
    try {
      const domain = extractDomain(url);
      
      // Check against known phishing domains
      if (await isPhishingDomain(domain)) {
        return true;
      }

      // Check for URL shorteners (potential redirect attacks)
      if (isUrlShortener(domain)) {
        return true;
      }

      // Check for suspicious TLDs
      if (hasSuspiciousTLD(domain)) {
        return true;
      }

      // Check domain age (very new domains might be suspicious)
      if (await isDomainTooNew(domain)) {
        return true;
      }

    } catch (error) {
      console.error('Error checking URL reputation:', error);
      // If we can't verify, treat as suspicious
      return true;
    }
  }

  return false;
}

// Helper functions
function extractDomain(urlOrEmail: string): string {
  if (urlOrEmail.includes('@')) {
    return urlOrEmail.split('@')[1];
  }
  try {
    const url = new URL(urlOrEmail);
    return url.hostname;
  } catch {
    return urlOrEmail;
  }
}

async function checkMalwareHash(hash: string): Promise<boolean> {
  // Placeholder for malware hash checking
  // In real implementation, this would query VirusTotal, etc.
  const knownMalwareHashes = [
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    // Add more known malicious hashes
  ];
  
  return knownMalwareHashes.includes(hash);
}

async function isPhishingDomain(domain: string): Promise<boolean> {
  // Placeholder for phishing domain checking
  // In real implementation, this would query threat intelligence feeds
  const knownPhishingDomains = [
    'phishing-example.com',
    'fake-bank.net',
    'malicious-site.org'
  ];
  
  return knownPhishingDomains.includes(domain.toLowerCase());
}

function isUrlShortener(domain: string): boolean {
  const shorteners = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
  ];
  
  return shorteners.includes(domain.toLowerCase());
}

function hasSuspiciousTLD(domain: string): boolean {
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download'];
  return suspiciousTlds.some(tld => domain.toLowerCase().endsWith(tld));
}

async function isDomainTooNew(domain: string): Promise<boolean> {
  // Placeholder for domain age checking
  // In real implementation, this would query WHOIS data
  try {
    // Simulate domain age check
    const creationDate = new Date('2024-01-01'); // Placeholder
    const now = new Date();
    const daysSinceCreation = (now.getTime() - creationDate.getTime()) / (1000 * 3600 * 24);
    
    return daysSinceCreation < 30; // Domain less than 30 days old
  } catch {
    return true; // If we can't determine age, treat as suspicious
  }
}
