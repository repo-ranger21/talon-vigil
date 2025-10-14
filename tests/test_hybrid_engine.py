"""
Comprehensive test suite for the Hybrid Detection Engine

This module contains pytest-based tests to validate the functionality of the hybrid
detection engine, including heuristics rule loading, rule application, and AI integration.
"""

import pytest
import tempfile
import os
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import modules to test
from detection.hybrid_engine import (
    HybridDetectionEngine, 
    HeuristicEngine, 
    AIEngine,
    EmailContent, 
    DetectionResult, 
    ThreatLevel, 
    RiskLevel,
    HeuristicRule,
    analyze_email_threat
)


class TestHeuristicRulesLoading:
    """Test heuristic rules loading functionality"""
    
    @pytest.fixture
    def sample_heuristics_file(self):
        """Create a temporary heuristics file for testing"""
        test_rules = {
            'header': {
                'HDR-TEST-001': {
                    'category': 'header',
                    'pattern': 'spf_fail',
                    'weight': 0.3,
                    'description': 'Test SPF failure rule'
                }
            },
            'body': {
                'BOD-TEST-001': {
                    'category': 'body',
                    'pattern': 'urgent.*action.*required',
                    'weight': 0.4,
                    'description': 'Test urgency pattern'
                }
            },
            'attachment': {
                'ATT-TEST-001': {
                    'category': 'attachment',
                    'pattern': r'\.exe$',
                    'weight': 0.8,
                    'description': 'Test executable attachment'
                }
            },
            'url': {
                'URL-TEST-001': {
                    'category': 'url',
                    'pattern': 'bit\\.ly',
                    'weight': 0.3,
                    'description': 'Test URL shortener'
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(test_rules, f)
            temp_file = f.name
        
        yield temp_file
        
        # Cleanup
        os.unlink(temp_file)
    
    def test_heuristic_engine_initialization(self, sample_heuristics_file):
        """Test that heuristic engine initializes correctly"""
        engine = HeuristicEngine(sample_heuristics_file)
        
        assert len(engine.rules) == 4
        assert 'HDR-TEST-001' in engine.rules
        assert 'BOD-TEST-001' in engine.rules
        assert 'ATT-TEST-001' in engine.rules
        assert 'URL-TEST-001' in engine.rules
    
    def test_heuristic_rule_loading(self, sample_heuristics_file):
        """Test that individual rules are loaded correctly"""
        engine = HeuristicEngine(sample_heuristics_file)
        
        rule = engine.rules['HDR-TEST-001']
        assert rule.rule_id == 'HDR-TEST-001'
        assert rule.category == 'header'
        assert rule.pattern == 'spf_fail'
        assert rule.weight == 0.3
        assert rule.description == 'Test SPF failure rule'
    
    def test_missing_heuristics_file_raises_error(self):
        """Test that missing heuristics file raises FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            HeuristicEngine('/nonexistent/file.yml')
    
    def test_invalid_yaml_raises_error(self):
        """Test that invalid YAML content raises YAMLError"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write('invalid: yaml: content: [')
            temp_file = f.name
        
        try:
            with pytest.raises(yaml.YAMLError):
                HeuristicEngine(temp_file)
        finally:
            os.unlink(temp_file)


# Global fixtures for email content
@pytest.fixture
def safe_email():
    """Sample email that should trigger no rules"""
    return EmailContent(
        headers={
            'From': 'legitimate@company.com',
            'Authentication-Results': 'spf=pass dkim=pass dmarc=pass',
            'Return-Path': '<legitimate@company.com>'
        },
        body='Thank you for your business. Here is your receipt.',
        attachments=[
            {'filename': 'receipt.pdf', 'content_type': 'application/pdf'}
        ],
        urls=['https://company.com/support'],
        sender='legitimate@company.com',
        subject='Receipt for your purchase'
    )

@pytest.fixture
def suspicious_email():
    """Sample email that should trigger some rules"""
    return EmailContent(
        headers={
            'From': 'admin@suspicious.com',
            'Authentication-Results': 'spf=fail dkim=pass dmarc=pass',
            'Return-Path': '<different@domain.com>'
        },
        body='URGENT ACTION REQUIRED: Your account will be suspended. Click here immediately.',
        attachments=[
            {'filename': 'invoice.zip', 'content_type': 'application/zip'}
        ],
        urls=['http://bit.ly/suspicious', 'https://phishing.net/login'],
        sender='admin@suspicious.com',
        subject='Account Suspension Warning'
    )

@pytest.fixture
def malicious_email():
    """Sample email that should trigger multiple high-weight rules"""
    return EmailContent(
        headers={
            'From': 'ceo@malware.com',
            'Authentication-Results': 'spf=fail dkim=fail dmarc=fail',
            'Return-Path': '<attacker@different.com>'
        },
        body='Confidential urgent request from CEO. Wire transfer needed immediately. Bank details attached.',
        attachments=[
            {'filename': 'malware.exe', 'content_type': 'application/octet-stream'},
            {'filename': 'invoice.doc', 'content_type': 'application/msword'}
        ],
        urls=['http://192.168.1.1/malware', 'https://paypal-verify.phish.org'],
        sender='ceo@malware.com',
        subject='URGENT: Wire Transfer Required'
    )

@pytest.fixture
def ai_engine():
    """Create AI engine instance"""
    return AIEngine()

@pytest.fixture
def hybrid_engine():
    """Create hybrid engine with default settings"""
    heuristics_path = Path(__file__).parent.parent / 'detection' / 'heuristics' / 'heuristics.yml'
    return HybridDetectionEngine(str(heuristics_path))


class TestEmailContentFixtures:
    """Test fixtures for sample email objects"""
    pass


class TestHeuristicRuleApplication:
    """Test heuristic rule application for different email types"""
    
    @pytest.fixture
    def engine(self):
        """Create heuristic engine with default rules"""
        # Use the actual heuristics file we created
        heuristics_path = Path(__file__).parent.parent / 'detection' / 'heuristics' / 'heuristics.yml'
        return HeuristicEngine(str(heuristics_path))
    
    def test_safe_email_triggers_no_rules(self, engine, safe_email):
        """Test that safe email triggers no or minimal rules"""
        header_score, header_rules = engine.apply_header_rules(safe_email.headers)
        body_score, body_rules = engine.apply_body_rules(safe_email.body)
        attachment_score, attachment_rules = engine.apply_attachment_rules(safe_email.attachments)
        url_score, url_rules = engine.apply_url_rules(safe_email.urls)
        
        total_score = header_score + body_score + attachment_score + url_score
        total_rules = len(header_rules + body_rules + attachment_rules + url_rules)
        
        assert total_score <= 0.3  # Should be minimal score
        assert total_rules <= 1    # Should trigger very few rules
    
    def test_suspicious_email_triggers_some_rules(self, engine, suspicious_email):
        """Test that suspicious email triggers some rules"""
        header_score, header_rules = engine.apply_header_rules(suspicious_email.headers)
        body_score, body_rules = engine.apply_body_rules(suspicious_email.body)
        attachment_score, attachment_rules = engine.apply_attachment_rules(suspicious_email.attachments)
        url_score, url_rules = engine.apply_url_rules(suspicious_email.urls)
        
        total_score = header_score + body_score + attachment_score + url_score
        total_rules = len(header_rules + body_rules + attachment_rules + url_rules)
        
        assert total_score > 0.3   # Should have moderate score
        assert total_rules >= 2    # Should trigger multiple rules
        
        # Check specific rule categories triggered
        assert len(header_rules) >= 1  # SPF failure should trigger
        assert len(body_rules) >= 1    # Urgency language should trigger
        assert len(url_rules) >= 1     # URL shortener should trigger
    
    def test_malicious_email_triggers_many_rules(self, engine, malicious_email):
        """Test that malicious email triggers many high-weight rules"""
        header_score, header_rules = engine.apply_header_rules(malicious_email.headers)
        body_score, body_rules = engine.apply_body_rules(malicious_email.body)
        attachment_score, attachment_rules = engine.apply_attachment_rules(malicious_email.attachments)
        url_score, url_rules = engine.apply_url_rules(malicious_email.urls)
        
        total_score = header_score + body_score + attachment_score + url_score
        total_rules = len(header_rules + body_rules + attachment_rules + url_rules)
        
        assert total_score > 1.0   # Should have high cumulative score
        assert total_rules >= 4    # Should trigger many rules
        
        # Check that high-weight rules are triggered
        assert len(attachment_rules) >= 1  # Executable attachment
        assert len(body_rules) >= 1        # BEC language
        assert len(header_rules) >= 1      # Authentication failures
    
    def test_header_authentication_failures(self, engine):
        """Test specific header authentication failure detection"""
        headers_with_failures = {
            'Authentication-Results': 'spf=fail dkim=fail dmarc=fail'
        }
        
        score, rules = engine.apply_header_rules(headers_with_failures)
        
        assert score > 0.5  # Should have significant score for multiple failures
        assert len(rules) >= 2  # Should trigger multiple auth failure rules
    
    def test_attachment_file_extension_detection(self, engine):
        """Test attachment file extension pattern matching"""
        dangerous_attachments = [
            {'filename': 'malware.exe', 'content_type': 'application/octet-stream'},
            {'filename': 'script.js', 'content_type': 'application/javascript'},
            {'filename': 'document.scr', 'content_type': 'application/octet-stream'}
        ]
        
        score, rules = engine.apply_attachment_rules(dangerous_attachments)
        
        assert score > 1.0  # Should have high score for multiple dangerous files
        assert len(rules) >= 2  # Should trigger multiple attachment rules


class TestAIEngineIntegration:
    """Test AI engine functionality"""
    
    def test_ai_engine_scoring_range(self, ai_engine, safe_email, suspicious_email, malicious_email):
        """Test that AI engine returns scores in valid range [0, 1]"""
        safe_score = ai_engine.score_email(safe_email)
        suspicious_score = ai_engine.score_email(suspicious_email)
        malicious_score = ai_engine.score_email(malicious_email)
        
        assert 0.0 <= safe_score <= 1.0
        assert 0.0 <= suspicious_score <= 1.0
        assert 0.0 <= malicious_score <= 1.0
    
    def test_ai_engine_score_progression(self, ai_engine, safe_email, suspicious_email, malicious_email):
        """Test that AI scores increase with threat level"""
        safe_score = ai_engine.score_email(safe_email)
        suspicious_score = ai_engine.score_email(suspicious_email)
        malicious_score = ai_engine.score_email(malicious_email)
        
        # Scores should generally increase with threat level
        assert malicious_score >= suspicious_score
        assert suspicious_score >= safe_score


class TestHybridEngineIntegration:
    """Test complete hybrid engine functionality"""
    
    def test_hybrid_engine_initialization(self, hybrid_engine):
        """Test hybrid engine initializes with correct weights"""
        assert hybrid_engine.heuristic_weight + hybrid_engine.ai_weight == pytest.approx(1.0, rel=1e-9)
        assert hasattr(hybrid_engine, 'heuristic_engine')
        assert hasattr(hybrid_engine, 'ai_engine')
    
    def test_analyze_safe_email(self, hybrid_engine, safe_email):
        """Test analysis of safe email"""
        result = hybrid_engine.analyze_email(safe_email)
        
        assert isinstance(result, DetectionResult)
        assert result.threat_level in [ThreatLevel.SAFE, ThreatLevel.SUSPICIOUS]
        assert result.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]
        assert 0.0 <= result.final_score <= 1.0
        assert isinstance(result.reasoning, list)
        assert len(result.reasoning) > 0
    
    def test_analyze_suspicious_email(self, hybrid_engine, suspicious_email):
        """Test analysis of suspicious email"""
        result = hybrid_engine.analyze_email(suspicious_email)
        
        assert result.threat_level in [ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS]
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert result.final_score > 0.3
        assert len(result.triggered_rules) >= 1
    
    def test_analyze_malicious_email(self, hybrid_engine, malicious_email):
        """Test analysis of malicious email"""
        result = hybrid_engine.analyze_email(malicious_email)
        
        assert result.threat_level == ThreatLevel.MALICIOUS
        assert result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert result.final_score > 0.6
        assert len(result.triggered_rules) >= 3
    
    def test_score_blending_logic(self, hybrid_engine, suspicious_email):
        """Test that heuristic and AI scores are properly blended"""
        result = hybrid_engine.analyze_email(suspicious_email)
        
        # Final score should be weighted combination
        expected_score = (result.heuristic_score * hybrid_engine.heuristic_weight + 
                         result.ai_score * hybrid_engine.ai_weight)
        
        assert result.final_score == pytest.approx(expected_score, rel=1e-9)
        assert 0.0 <= result.final_score <= 1.0


class TestEdgeCasesAndWeights:
    """Test edge cases and different weight configurations"""
    
    def test_zero_heuristic_weight(self, suspicious_email):
        """Test hybrid engine with zero heuristic weight (AI only)"""
        heuristics_path = Path(__file__).parent.parent / 'detection' / 'heuristics' / 'heuristics.yml'
        engine = HybridDetectionEngine(str(heuristics_path), heuristic_weight=0.0, ai_weight=1.0)
        
        result = engine.analyze_email(suspicious_email)
        
        # Final score should equal AI score when heuristic weight is 0
        assert result.final_score == pytest.approx(result.ai_score, rel=1e-9)
    
    def test_zero_ai_weight(self, suspicious_email):
        """Test hybrid engine with zero AI weight (heuristics only)"""
        heuristics_path = Path(__file__).parent.parent / 'detection' / 'heuristics' / 'heuristics.yml'
        engine = HybridDetectionEngine(str(heuristics_path), heuristic_weight=1.0, ai_weight=0.0)
        
        result = engine.analyze_email(suspicious_email)
        
        # Final score should equal normalized heuristic score when AI weight is 0
        normalized_heuristic = min(1.0, result.heuristic_score)
        assert result.final_score == pytest.approx(normalized_heuristic, rel=1e-9)
    
    def test_equal_weights(self, suspicious_email):
        """Test hybrid engine with equal weights"""
        heuristics_path = Path(__file__).parent.parent / 'detection' / 'heuristics' / 'heuristics.yml'
        engine = HybridDetectionEngine(str(heuristics_path), heuristic_weight=0.5, ai_weight=0.5)
        
        result = engine.analyze_email(suspicious_email)
        
        # Verify weights are normalized to 0.5 each
        assert engine.heuristic_weight == 0.5
        assert engine.ai_weight == 0.5
        
        # Final score should be average of both scores
        expected = (min(1.0, result.heuristic_score) * 0.5) + (result.ai_score * 0.5)
        assert result.final_score == pytest.approx(expected, rel=1e-9)
    
    def test_unnormalized_weights_are_normalized(self):
        """Test that unnormalized weights are automatically normalized"""
        heuristics_path = Path(__file__).parent.parent / 'detection' / 'heuristics' / 'heuristics.yml'
        engine = HybridDetectionEngine(str(heuristics_path), heuristic_weight=3.0, ai_weight=2.0)
        
        # Weights should be normalized to sum to 1.0
        assert engine.heuristic_weight == pytest.approx(0.6, rel=1e-9)  # 3/(3+2)
        assert engine.ai_weight == pytest.approx(0.4, rel=1e-9)         # 2/(3+2)
    
    def test_empty_email_content(self, hybrid_engine):
        """Test analysis of empty email content"""
        empty_email = EmailContent(
            headers={},
            body='',
            attachments=[],
            urls=[],
            sender='',
            subject=''
        )
        
        result = hybrid_engine.analyze_email(empty_email)
        
        assert result.threat_level == ThreatLevel.SAFE
        assert result.risk_level == RiskLevel.LOW
        assert result.final_score < 0.3
        assert len(result.triggered_rules) == 0
    
    def test_high_volume_attachments_and_urls(self, hybrid_engine):
        """Test email with many attachments and URLs"""
        high_volume_email = EmailContent(
            headers={'From': 'test@example.com'},
            body='Check out these files and links',
            attachments=[
                {'filename': f'file{i}.pdf', 'content_type': 'application/pdf'} 
                for i in range(10)
            ],
            urls=[f'https://example{i}.com' for i in range(15)],
            sender='test@example.com',
            subject='Many attachments and links'
        )
        
        result = hybrid_engine.analyze_email(high_volume_email)
        
        # AI engine should flag this as suspicious due to high volume
        # But may be classified as safe due to no heuristic rule triggers
        assert result.ai_score > 0.15  # Should have some AI concern for volume
        assert 0.0 <= result.final_score <= 1.0


class TestConvenienceFunction:
    """Test the convenience function for easy usage"""
    
    def test_analyze_email_threat_function(self):
        """Test the convenience function works correctly"""
        email_data = {
            'headers': {'From': 'test@example.com'},
            'body': 'URGENT ACTION REQUIRED: Click here immediately',
            'attachments': [{'filename': 'malware.exe'}],
            'urls': ['http://bit.ly/suspicious'],
            'sender': 'test@example.com',
            'subject': 'Urgent Security Alert'
        }
        
        result = analyze_email_threat(email_data)
        
        assert isinstance(result, DetectionResult)
        assert result.threat_level in [ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS]
        assert len(result.triggered_rules) >= 1
    
    def test_analyze_email_threat_with_custom_heuristics(self, sample_heuristics_file):
        """Test convenience function with custom heuristics file"""
        email_data = {
            'headers': {'Authentication-Results': 'spf=fail'},
            'body': 'urgent action required',
            'attachments': [{'filename': 'test.exe'}],
            'urls': ['http://bit.ly/test'],
            'sender': 'test@example.com',
            'subject': 'Test'
        }
        
        result = analyze_email_threat(email_data, sample_heuristics_file)
        
        assert isinstance(result, DetectionResult)
        assert len(result.triggered_rules) >= 2  # Should trigger test rules


# Integration test fixtures
@pytest.fixture
def sample_heuristics_file():
    """Shared fixture for sample heuristics file"""
    test_rules = {
        'header': {
            'HDR-TEST-001': {
                'category': 'header',
                'pattern': 'spf_fail',
                'weight': 0.3,
                'description': 'Test SPF failure rule'
            }
        },
        'body': {
            'BOD-TEST-001': {
                'category': 'body',
                'pattern': 'urgent.*action.*required',
                'weight': 0.4,
                'description': 'Test urgency pattern'
            }
        },
        'attachment': {
            'ATT-TEST-001': {
                'category': 'attachment',
                'pattern': r'\.exe$',
                'weight': 0.8,
                'description': 'Test executable attachment'
            }
        },
        'url': {
            'URL-TEST-001': {
                'category': 'url',
                'pattern': 'bit\\.ly',
                'weight': 0.3,
                'description': 'Test URL shortener'
            }
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(test_rules, f)
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    os.unlink(temp_file)