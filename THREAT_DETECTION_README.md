# EGI Threat Detection Engine

A comprehensive multi-channel threat analysis system for detecting malware, phishing, impersonation, and social engineering attacks across Email, SMS, and Voice communications.

## 🎯 Overview

The EGI Threat Detection Engine provides real-time threat analysis across multiple communication channels:

- **📧 Email Security**: Header analysis, attachment scanning, URL reputation checking
- **📱 SMS Security**: Content analysis, sender validation, link verification  
- **📞 Call Security**: Caller reputation, transcript analysis, impersonation detection

## ✨ Features

### Email Protection
- **Header Analysis**: SPF, DKIM, DMARC validation
- **Attachment Scanning**: Malware detection, suspicious file types
- **URL Reputation**: Phishing link detection, domain reputation
- **Social Engineering**: Manipulative language detection

### SMS Protection  
- **Sender Validation**: Verified sender checking, spoofing detection
- **Content Analysis**: Scam pattern recognition, urgency indicators
- **Link Analysis**: Suspicious URL detection, shortener analysis
- **Fraud Detection**: Lottery scams, financial fraud patterns

### Call Protection
- **Caller Reputation**: Scam number database, risk scoring
- **Transcript Analysis**: Impersonation detection, script identification
- **Emotional Manipulation**: Pressure tactics, social engineering
- **Identity Verification**: Inconsistency detection

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd talon-vigil

# Install dependencies
npm install typescript @types/node

# Build the project
npm run build
```

### Basic Usage

```typescript
import { detectThreat } from './threat_detection_engine';

// Analyze an email
const emailResult = await detectThreat({
  type: 'email',
  content: 'Click here to verify your account...',
  metadata: {
    headers: { from: 'suspicious@domain.com', to: 'user@company.com' },
    attachments: []
  }
});

console.log(emailResult.threatLevel); // 'safe' | 'suspicious' | 'malicious'
console.log(emailResult.recommendedAction); // 'pass' | 'flag' | 'quarantine'
```

## 📊 API Reference

### Main Function

#### `detectThreat(input: ThreatDetectionInput): Promise<ThreatDetectionResult>`

Analyzes communication content for threats across multiple channels.

**Parameters:**
- `input.type`: Communication type (`'email' | 'sms' | 'call'`)
- `input.content`: Message content to analyze
- `input.metadata`: Channel-specific metadata

**Returns:**
```typescript
{
  threatLevel: 'safe' | 'suspicious' | 'malicious',
  reasons: string[],
  recommendedAction: 'pass' | 'flag' | 'quarantine'
}
```

### Utility Functions

#### Email Utils (`emailUtils.ts`)
- `analyzeEmailHeaders(headers)`: Validates email authentication
- `scanAttachments(attachments)`: Detects malicious attachments  
- `checkUrlReputation(content)`: Analyzes URLs for threats

#### SMS Utils (`smsUtils.ts`)
- `analyzeSmsContent(content)`: Detects SMS scam patterns
- `validateSenderId(senderId)`: Verifies sender legitimacy

#### Call Utils (`callUtils.ts`)
- `checkCallerReputation(callerId)`: Validates caller identity
- `analyzeCallTranscript(transcript)`: Detects manipulation

#### Threat Actions (`threatActions.ts`)
- `logThreatEvent(event)`: Security event logging
- `quarantineMessage(input)`: Message quarantine
- `notifyUser(notification)`: User alerts

## 🧪 Testing

Run the test suite to see the engine in action:

```bash
# Build and run tests
npm run build
node dist/threat_detection_test.js

# Or run TypeScript directly
npx tsx threat_detection_test.ts
```

### Test Cases Included
- ✅ Malicious email with phishing links and malware
- ✅ SMS scam with suspicious sender
- ✅ Robocall impersonation attempt
- ✅ Legitimate communication (safe)

## 🔧 Configuration

### Environment Variables

```bash
# Logging configuration
LOGGING_ENDPOINT=https://your-logging-system.com/api/logs

# Threat intelligence APIs
VIRUSTOTAL_API_KEY=your_api_key
PHISHING_DATABASE_URL=https://threat-intel.com/api

# Security settings
QUARANTINE_ENABLED=true
USER_NOTIFICATIONS_ENABLED=true
```

### Threat Detection Thresholds

Customize detection sensitivity in each utility module:

- **Email**: Modify patterns in `emailUtils.ts`
- **SMS**: Adjust scam patterns in `smsUtils.ts`  
- **Calls**: Update manipulation indicators in `callUtils.ts`

## 📈 Threat Levels

| Level | Description | Action |
|-------|-------------|---------|
| **Safe** | No threats detected | Pass through |
| **Suspicious** | Potential threats found | Flag for review |
| **Malicious** | High-confidence threats | Quarantine immediately |

## 🛡️ Security Features

- **Multi-layered Analysis**: Combines multiple detection techniques
- **Real-time Processing**: Immediate threat assessment
- **Quarantine System**: Automatic threat isolation
- **Audit Logging**: Complete security event tracking
- **User Notifications**: Immediate threat alerts

## 🔍 Detection Capabilities

### Social Engineering Patterns
- Urgency indicators (`urgent`, `act now`, `limited time`)
- Authority impersonation (`CEO`, `IRS`, `Microsoft`)
- Financial manipulation (`wire transfer`, `gift card`)
- Information harvesting (`verify account`, `update password`)

### Technical Indicators
- Suspicious file types (`.exe`, `.scr`, `.bat`)
- Phishing domains and URL shorteners
- Missing email authentication (SPF/DKIM)
- Caller ID spoofing and reputation issues

## 🚨 Integration

### SIEM Integration
```typescript
// Custom logging integration
await logThreatEvent({
  type: 'email',
  threatLevel: 'malicious',
  reasons: ['Phishing link detected'],
  // ... additional metadata
});
```

### Email Gateway Integration
```typescript
// Integrate with email security gateway
const emailGateway = new EmailGateway();
emailGateway.onMessage(async (message) => {
  const result = await detectThreat({
    type: 'email',
    content: message.body,
    metadata: { headers: message.headers }
  });
  
  if (result.recommendedAction === 'quarantine') {
    await emailGateway.quarantine(message);
  }
});
```

## 📚 Architecture

```
threat_detection_engine.ts     # Main detection logic
├── emailUtils.ts             # Email-specific analysis  
├── smsUtils.ts               # SMS-specific analysis
├── callUtils.ts              # Call-specific analysis
└── threatActions.ts          # Response actions
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-detection`
3. Add your threat detection logic
4. Include tests for new patterns
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Threat intelligence community
- Security research organizations
- Open source security tools

---

**EGI Threat Detection Engine** - *Protecting communications across all channels*
