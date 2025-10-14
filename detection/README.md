# Hybrid Email Threat Detection Engine

A comprehensive email threat detection system that combines heuristic rules with AI scoring for accurate threat assessment.

## Features

- **Hybrid Approach**: Combines rule-based heuristics with AI-powered analysis
- **Comprehensive Analysis**: Evaluates email headers, body content, attachments, and URLs
- **Configurable Weights**: Adjustable balance between heuristic and AI scoring
- **Extensible Rules**: YAML-based heuristic rules for easy customization
- **Multiple Threat Categories**: Header authentication, content analysis, attachment scanning, URL reputation
- **Human-Readable Results**: Detailed reasoning and explanations for decisions

## Quick Start

```python
from detection.hybrid_engine import analyze_email_threat

# Analyze an email
email_data = {
    'headers': {'Authentication-Results': 'spf=fail'},
    'body': 'URGENT: Click here immediately',
    'attachments': [{'filename': 'document.exe'}],
    'urls': ['http://bit.ly/suspicious'],
    'sender': 'attacker@malware.com',
    'subject': 'Security Alert'
}

result = analyze_email_threat(email_data)
print(f"Threat: {result.threat_level.value}, Score: {result.final_score:.3f}")
```

## Architecture

### Components

1. **HeuristicEngine**: Loads and applies YAML-based detection rules
2. **AIEngine**: Provides ML-based threat scoring (mock implementation)
3. **HybridDetectionEngine**: Combines both approaches with configurable weights

### Heuristic Rules

Located in `detection/heuristics/heuristics.yml`, organized by category:

- **Header Rules**: Authentication failures, sender reputation
- **Body Rules**: Social engineering, urgency patterns, financial fraud
- **Attachment Rules**: Dangerous file extensions, suspicious documents
- **URL Rules**: Shorteners, malicious domains, unencrypted links

### Threat Classification

- **Threat Levels**: SAFE, SUSPICIOUS, MALICIOUS
- **Risk Levels**: LOW, MEDIUM, HIGH, CRITICAL
- **Scoring**: 0.0-1.0 range with configurable thresholds

## Testing

Run the comprehensive test suite:

```bash
pytest tests/test_hybrid_engine.py -v
```

Or run the demonstration:

```bash
python demo_hybrid_engine.py
```

## Configuration

Customize the detection behavior:

```python
from detection.hybrid_engine import HybridDetectionEngine

# Custom weight configuration
engine = HybridDetectionEngine(
    heuristic_weight=0.7,  # 70% heuristics
    ai_weight=0.3          # 30% AI
)

# Custom heuristics file
engine = HybridDetectionEngine(
    heuristics_file="path/to/custom_rules.yml"
)
```

## Example Rules

```yaml
header:
  HDR-001:
    category: "header"
    pattern: "spf_fail"
    weight: 0.3
    description: "SPF authentication failure detected"

body:
  BOD-001:
    category: "body"
    pattern: "urgent.*action.*required"
    weight: 0.3
    description: "Urgency-related social engineering language"
```

## Test Coverage

- ✅ Rule loading and validation
- ✅ Email content analysis
- ✅ Score blending algorithms
- ✅ Edge cases and error handling
- ✅ Different weight configurations
- ✅ AI engine integration

The system provides robust, extensible email threat detection suitable for production environments.