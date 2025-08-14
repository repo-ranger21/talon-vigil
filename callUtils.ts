/**
 * Call Utilities for Threat Detection
 * Functions for analyzing call reputation and transcripts
 */

interface CallMetadata {
  callerId: string;
  duration: number;
  timestamp: Date;
  callType?: 'incoming' | 'outgoing';
  carrier?: string;
}

interface CallerReputation {
  isKnownScammer: boolean;
  riskScore: number; // 0-100, higher is more risky
  reportCount: number;
  categories: string[];
}

/**
 * Checks caller reputation against scam databases
 */
export function checkCallerReputation(callerId: string): boolean {
  if (!callerId) {
    return false;
  }

  // Normalize phone number (remove formatting)
  const normalizedNumber = normalizePhoneNumber(callerId);
  
  // Check against known scam numbers
  if (isKnownScamNumber(normalizedNumber)) {
    return false;
  }

  // Check for suspicious patterns
  if (hasSuspiciousPattern(normalizedNumber)) {
    return false;
  }

  // Check reputation score
  const reputation = getCallerReputation(normalizedNumber);
  if (reputation.riskScore > 70) {
    return false;
  }

  return true;
}

/**
 * Analyzes call transcript for impersonation and manipulation
 */
export function analyzeCallTranscript(transcript: string): boolean {
  if (!transcript || transcript.trim().length === 0) {
    return false;
  }

  const suspiciousPatterns = [
    // Impersonation patterns
    /this is.*from.*irs/i,
    /calling from.*microsoft/i,
    /amazon.*security/i,
    /apple.*support/i,
    /google.*verification/i,
    /paypal.*security/i,
    /bank.*fraud.*department/i,
    /social.*security.*administration/i,
    
    // Urgency and pressure tactics
    /urgent.*action.*required/i,
    /account.*will.*be.*closed/i,
    /suspended.*immediately/i,
    /legal.*action.*will.*be.*taken/i,
    /arrest.*warrant/i,
    /final.*notice/i,
    /act.*within.*24.*hours/i,
    
    // Financial manipulation
    /wire.*transfer/i,
    /gift.*card/i,
    /bitcoin/i,
    /cryptocurrency/i,
    /send.*money/i,
    /payment.*verification/i,
    /refund.*processing/i,
    
    // Information harvesting
    /verify.*social.*security/i,
    /confirm.*credit.*card/i,
    /update.*banking.*information/i,
    /provide.*password/i,
    /account.*number/i,
    /security.*code/i,
    
    // Tech support scams
    /computer.*virus/i,
    /malware.*detected/i,
    /remote.*access/i,
    /screen.*sharing/i,
    /download.*software/i,
    /install.*program/i
  ];

  // Check for suspicious patterns
  const matchedPatterns = suspiciousPatterns.filter(pattern => pattern.test(transcript));
  if (matchedPatterns.length > 0) {
    return true;
  }

  // Check for emotional manipulation indicators
  if (hasEmotionalManipulation(transcript)) {
    return true;
  }

  // Check for script-like language (robocalls)
  if (isScriptLike(transcript)) {
    return true;
  }

  // Check for inconsistencies in claimed identity
  if (hasIdentityInconsistencies(transcript)) {
    return true;
  }

  return false;
}

/**
 * Gets caller reputation from threat intelligence
 */
function getCallerReputation(phoneNumber: string): CallerReputation {
  // Placeholder implementation
  // In real implementation, this would query threat intelligence APIs
  
  const knownScamNumbers = getKnownScamNumbers();
  
  if (knownScamNumbers.includes(phoneNumber)) {
    return {
      isKnownScammer: true,
      riskScore: 95,
      reportCount: 100,
      categories: ['robocall', 'scam', 'fraud']
    };
  }

  // Simulate reputation lookup
  const riskScore = Math.random() * 100;
  return {
    isKnownScammer: false,
    riskScore,
    reportCount: Math.floor(riskScore / 10),
    categories: riskScore > 50 ? ['suspicious'] : ['legitimate']
  };
}

/**
 * Normalizes phone number format
 */
function normalizePhoneNumber(phoneNumber: string): string {
  // Remove all non-digit characters
  const digits = phoneNumber.replace(/\D/g, '');
  
  // Handle US numbers with country code
  if (digits.length === 11 && digits.startsWith('1')) {
    return digits.substring(1);
  }
  
  return digits;
}

/**
 * Checks if phone number is in known scam database
 */
function isKnownScamNumber(phoneNumber: string): boolean {
  const knownScamNumbers = getKnownScamNumbers();
  return knownScamNumbers.includes(phoneNumber);
}

/**
 * Gets list of known scam phone numbers
 */
function getKnownScamNumbers(): string[] {
  // Placeholder for scam number database
  return [
    '8005551234',
    '8885551234',
    '8775551234',
    '2025551234',
    '3125551234'
  ];
}

/**
 * Checks for suspicious phone number patterns
 */
function hasSuspiciousPattern(phoneNumber: string): boolean {
  // Check for sequential numbers
  if (/(\d)\1{4,}/.test(phoneNumber)) {
    return true;
  }
  
  // Check for ascending/descending sequences
  const sequences = ['1234567890', '0987654321'];
  for (const seq of sequences) {
    if (phoneNumber.includes(seq.substring(0, 5))) {
      return true;
    }
  }
  
  // Check for common fake numbers
  const fakePatterns = [
    /555\d{4}/, // 555 numbers (often fake)
    /000\d{4}/, // Starting with 000
    /111\d{4}/, // Starting with 111
    /999\d{4}/  // Starting with 999
  ];
  
  return fakePatterns.some(pattern => pattern.test(phoneNumber));
}

/**
 * Detects emotional manipulation in transcript
 */
function hasEmotionalManipulation(transcript: string): boolean {
  const emotionalTriggers = [
    /don't.*worry/i,
    /trust.*me/i,
    /help.*you/i,
    /protect.*you/i,
    /save.*money/i,
    /special.*offer/i,
    /limited.*time/i,
    /exclusive.*deal/i,
    /congratulations/i,
    /you.*won/i,
    /selected.*winner/i
  ];
  
  const triggerCount = emotionalTriggers.filter(trigger => trigger.test(transcript)).length;
  return triggerCount >= 2;
}

/**
 * Detects script-like robocall language
 */
function isScriptLike(transcript: string): boolean {
  const scriptIndicators = [
    /press.*1.*to/i,
    /press.*2.*to/i,
    /to.*speak.*representative/i,
    /to.*remove.*from.*list/i,
    /recorded.*message/i,
    /automated.*message/i,
    /pre.*recorded/i,
    /this.*is.*not.*sales.*call/i
  ];
  
  return scriptIndicators.some(indicator => indicator.test(transcript));
}

/**
 * Detects inconsistencies in claimed identity
 */
function hasIdentityInconsistencies(transcript: string): boolean {
  const organizations = [
    'irs', 'microsoft', 'amazon', 'apple', 'google', 'paypal', 
    'bank', 'visa', 'mastercard', 'social security'
  ];
  
  const mentionedOrgs = organizations.filter(org => 
    transcript.toLowerCase().includes(org)
  );
  
  // If multiple organizations are mentioned, it's suspicious
  if (mentionedOrgs.length > 1) {
    return true;
  }
  
  // Check for vague language when claiming to be from an organization
  const vagueLanguage = [
    /calling.*from.*your.*bank/i,
    /this.*is.*from.*security/i,
    /calling.*about.*your.*account/i
  ];
  
  return vagueLanguage.some(pattern => pattern.test(transcript));
}
