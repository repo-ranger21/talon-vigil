/**
 * EGI Threat Detection Engine
 * Multi-channel threat analysis for Email, SMS, and Calls
 * Detects malware, phishing, impersonation, and social engineering
 */

import { analyzeEmailHeaders, scanAttachments, checkUrlReputation } from './emailUtils';
import { analyzeSmsContent, validateSenderId } from './smsUtils';
import { checkCallerReputation, analyzeCallTranscript } from './callUtils';
import { logThreatEvent, quarantineMessage, notifyUser } from './threatActions';

type MessageType = 'email' | 'sms' | 'call';

interface ThreatDetectionInput {
  type: MessageType;
  content: string;
  metadata: Record<string, any>;
}

interface ThreatDetectionResult {
  threatLevel: 'safe' | 'suspicious' | 'malicious';
  reasons: string[];
  recommendedAction: 'pass' | 'flag' | 'quarantine';
}

export async function detectThreat(input: ThreatDetectionInput): Promise<ThreatDetectionResult> {
  const { type, content, metadata } = input;
  let reasons: string[] = [];
  let threatLevel: ThreatDetectionResult['threatLevel'] = 'safe';

  if (type === 'email') {
    if (!analyzeEmailHeaders(metadata.headers)) reasons.push('Suspicious headers');
    if (await scanAttachments(metadata.attachments)) reasons.push('Malicious attachment detected');
    if (await checkUrlReputation(content)) reasons.push('Phishing link detected');
    if (detectSocialEngineering(content)) reasons.push('Manipulative language detected');
  }

  if (type === 'sms') {
    if (!validateSenderId(metadata.sender)) reasons.push('Unverified sender');
    if (await checkUrlReputation(content)) reasons.push('Suspicious link in SMS');
    if (detectSocialEngineering(content)) reasons.push('Scam language detected');
    
    const smsAnalysis = analyzeSmsContent(content);
    if (smsAnalysis.isSuspicious) {
      reasons.push(...smsAnalysis.reasons);
    }
  }

  if (type === 'call') {
    if (!checkCallerReputation(metadata.callerId)) reasons.push('Known scam caller');
    if (analyzeCallTranscript(content)) reasons.push('Impersonation or manipulation detected');
  }

  if (reasons.length > 0) {
    threatLevel = reasons.length > 2 ? 'malicious' : 'suspicious';
  }

  const recommendedAction = threatLevel === 'malicious' ? 'quarantine' : threatLevel === 'suspicious' ? 'flag' : 'pass';

  await logThreatEvent({ type, content, metadata, threatLevel, reasons });
  if (recommendedAction === 'quarantine') await quarantineMessage(input);
  if (recommendedAction !== 'pass') notifyUser({ type, threatLevel, reasons });

  return { threatLevel, reasons, recommendedAction };
}

// Helper function to detect social engineering language
function detectSocialEngineering(text: string): boolean {
  const patterns = [
    /urgent/i,
    /wire transfer/i,
    /click here/i,
    /CEO/i,
    /don't tell anyone/i,
    /reset your password/i,
    /you've won/i,
    /act now/i
  ];
  return patterns.some(p => p.test(text));
}
