/**
 * EGI Threat Detection Engine - Test Examples
 * Demonstrates usage of the multi-channel threat detection system
 */

import { detectThreat } from './threat_detection_engine';

async function runThreatDetectionTests() {
  console.log('🔍 EGI Threat Detection Engine - Test Suite');
  console.log('=' .repeat(50));

  // Test 1: Malicious Email
  console.log('\n📧 Testing Email Threat Detection:');
  const emailTest = await detectThreat({
    type: 'email',
    content: 'URGENT! Your account will be suspended. Click here to verify: http://phishing-site.com/verify',
    metadata: {
      headers: {
        from: 'security@fake-bank.com',
        to: 'user@company.com',
        subject: 'Urgent Account Verification Required'
      },
      attachments: [
        {
          filename: 'document.exe',
          contentType: 'application/x-msdownload',
          size: 1024000
        }
      ]
    }
  });
  
  console.log(`Threat Level: ${emailTest.threatLevel}`);
  console.log(`Recommended Action: ${emailTest.recommendedAction}`);
  console.log(`Reasons: ${emailTest.reasons.join(', ')}`);

  // Test 2: Suspicious SMS
  console.log('\n📱 Testing SMS Threat Detection:');
  const smsTest = await detectThreat({
    type: 'sms',
    content: 'Congratulations! You\'ve won $1000! Click here to claim your prize: http://bit.ly/fake-prize',
    metadata: {
      sender: 'SCAM',
      timestamp: new Date(),
      carrier: 'Unknown'
    }
  });
  
  console.log(`Threat Level: ${smsTest.threatLevel}`);
  console.log(`Recommended Action: ${smsTest.recommendedAction}`);
  console.log(`Reasons: ${smsTest.reasons.join(', ')}`);

  // Test 3: Malicious Call
  console.log('\n📞 Testing Call Threat Detection:');
  const callTest = await detectThreat({
    type: 'call',
    content: 'This is Microsoft calling about virus detected on your computer. We need remote access to fix it immediately.',
    metadata: {
      callerId: '8005551234',
      duration: 300,
      timestamp: new Date(),
      callType: 'incoming'
    }
  });
  
  console.log(`Threat Level: ${callTest.threatLevel}`);
  console.log(`Recommended Action: ${callTest.recommendedAction}`);
  console.log(`Reasons: ${callTest.reasons.join(', ')}`);

  // Test 4: Safe Email
  console.log('\n✅ Testing Safe Email:');
  const safeEmailTest = await detectThreat({
    type: 'email',
    content: 'Hi, this is a reminder about our team meeting tomorrow at 2 PM.',
    metadata: {
      headers: {
        from: 'colleague@company.com',
        to: 'user@company.com',
        subject: 'Team Meeting Reminder',
        'dkim-signature': 'valid'
      },
      attachments: []
    }
  });
  
  console.log(`Threat Level: ${safeEmailTest.threatLevel}`);
  console.log(`Recommended Action: ${safeEmailTest.recommendedAction}`);
  console.log(`Reasons: ${safeEmailTest.reasons.length > 0 ? safeEmailTest.reasons.join(', ') : 'No threats detected'}`);

  console.log('\n🏁 Test suite completed!');
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runThreatDetectionTests().catch(console.error);
}

export { runThreatDetectionTests };
