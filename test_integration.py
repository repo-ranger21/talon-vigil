"""
Integration tests for TalonVigil advanced security features
"""

import pytest
import asyncio
import json
import tempfile
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, AsyncMock

from app import create_app
from models import db, User, Role, UserRole, init_db
from config import Config
from zero_trust import ZeroTrustManager
from federated_threat_intelligence import (
    FederatedThreatIntelligence, ThreatIndicator, ThreatCategory, 
    ThreatLevel, ConfidenceLevel, MISPSource
)
from adaptive_threat_scoring import AdaptiveThreatScorer
from soar_integration import SOARManager
from chaos_engineering import ChaosEngineering

class TestConfig(Config):
    """Test configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SECRET_KEY = 'test-secret-key'
    JWT_SECRET_KEY = 'test-jwt-secret'
    WTF_CSRF_ENABLED = False
    AZURE_TENANT_ID = 'test-tenant'
    AZURE_CLIENT_ID = 'test-client'
    AZURE_CLIENT_SECRET = 'test-secret'
    ENABLE_MFA = False
    ENABLE_CONDITIONAL_ACCESS = False

@pytest.fixture
def app():
    """Create application for testing"""
    app = create_app(TestConfig)
    
    with app.app_context():
        init_db()
        yield app

@pytest.fixture
def client(app):
    """Test client"""
    return app.test_client()

@pytest.fixture
def auth_headers(app, client):
    """Get authentication headers"""
    with app.app_context():
        # Create test user
        user = User(
            email='test@example.com',
            username='testuser',
            name='Test User'
        )
        user.set_password('testpass123')
        db.session.add(user)
        
        # Add analyst role
        analyst_role = Role.query.filter_by(name='analyst').first()
        if analyst_role:
            user_role = UserRole(user_id=user.id, role_id=analyst_role.id)
            db.session.add(user_role)
        
        db.session.commit()
        
        # Login and get token
        response = client.post('/auth/login', json={
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        
        if response.status_code == 200:
            token = response.json.get('access_token')
            return {'Authorization': f'Bearer {token}'}
    
    return {}

class TestZeroTrustIntegration:
    """Test Zero Trust architecture integration"""
    
    def test_zero_trust_initialization(self, app):
        """Test Zero Trust manager initialization"""
        with app.app_context():
            zt_manager = app.extensions.get('zero_trust')
            assert zt_manager is not None
            assert isinstance(zt_manager, ZeroTrustManager)
    
    @patch('zero_trust.requests.get')
    def test_azure_jwt_validation(self, mock_get, app):
        """Test Azure JWT validation"""
        # Mock JWKS response
        mock_get.return_value.json.return_value = {
            'keys': [{
                'kid': 'test-key-id',
                'kty': 'RSA',
                'use': 'sig',
                'n': 'test-modulus',
                'e': 'AQAB'
            }]
        }
        
        with app.app_context():
            zt_manager = app.extensions.get('zero_trust')
            
            # Test invalid token
            result = zt_manager.validate_azure_jwt('invalid-token')
            assert result is None
    
    def test_device_compliance_check(self, app):
        """Test device compliance validation"""
        with app.app_context():
            zt_manager = app.extensions.get('zero_trust')
            
            # Test compliant device
            device_info = {
                'device_id': 'test-device',
                'compliance_status': 'compliant',
                'trust_level': 'high'
            }
            
            result = zt_manager.verify_device_compliance(device_info)
            assert result is True
            
            # Test non-compliant device
            device_info['compliance_status'] = 'non_compliant'
            result = zt_manager.verify_device_compliance(device_info)
            assert result is False

class TestThreatIntelligenceIntegration:
    """Test threat intelligence integration"""
    
    def test_threat_intel_initialization(self, app):
        """Test threat intelligence initialization"""
        with app.app_context():
            threat_intel = app.extensions.get('threat_intel')
            assert threat_intel is not None
            assert isinstance(threat_intel, FederatedThreatIntelligence)
    
    @pytest.mark.asyncio
    async def test_indicator_enrichment(self, app):
        """Test threat indicator enrichment"""
        with app.app_context():
            threat_intel = app.extensions.get('threat_intel')
            
            # Create test indicator
            indicator = ThreatIndicator(
                id='test-001',
                type='ip',
                value='192.168.1.100',
                category=ThreatCategory.MALWARE,
                level=ThreatLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                first_seen=datetime.now(timezone.utc),
                source='test'
            )
            
            await threat_intel.add_indicator(indicator)
            
            # Check if indicator was added
            result = threat_intel.check_indicator('192.168.1.100', 'ip')
            assert result is not None
            assert result.value == '192.168.1.100'
    
    def test_threat_intel_api_endpoints(self, client, auth_headers):
        """Test threat intelligence API endpoints"""
        # Test enrichment endpoint
        response = client.post(
            '/api/v1/threat-intel/enrich',
            json={
                'indicator': '192.168.1.100',
                'type': 'ip'
            },
            headers=auth_headers
        )
        
        # Should return 404 if no intelligence found
        assert response.status_code in [200, 404]
        
        # Test search endpoint
        response = client.get(
            '/api/v1/threat-intel/search?q=malware&limit=10',
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'results' in data
        assert 'total' in data

class TestAdaptiveThreatScoring:
    """Test adaptive threat scoring integration"""
    
    def test_threat_scorer_initialization(self, app):
        """Test threat scorer initialization"""
        with app.app_context():
            scorer = app.extensions.get('adaptive_scorer')
            assert scorer is not None
            assert isinstance(scorer, AdaptiveThreatScorer)
    
    def test_threat_scoring_api(self, client, auth_headers):
        """Test threat scoring API"""
        threat_data = {
            'event_type': 'network_intrusion',
            'source_ip': '10.0.0.1',
            'destination_ip': '192.168.1.100',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'metadata': {
                'protocol': 'TCP',
                'port': 443,
                'bytes': 1024
            }
        }
        
        response = client.post(
            '/api/v1/threat-scoring/score',
            json=threat_data,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'raw_score' in data
        assert 'adjusted_score' in data
        assert 'confidence' in data
    
    def test_feedback_api(self, client, auth_headers):
        """Test threat scoring feedback API"""
        feedback_data = {
            'event_id': 'test-event-001',
            'true_label': 'malicious',
            'analyst_notes': 'Confirmed C2 communication'
        }
        
        response = client.post(
            '/api/v1/threat-scoring/feedback',
            json=feedback_data,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'Feedback recorded successfully'

class TestSOARIntegration:
    """Test SOAR integration"""
    
    def test_soar_manager_initialization(self, app):
        """Test SOAR manager initialization"""
        with app.app_context():
            soar_manager = app.extensions.get('soar')
            assert soar_manager is not None
            assert isinstance(soar_manager, SOARManager)
    
    def test_incident_creation_api(self, client, auth_headers):
        """Test SOAR incident creation API"""
        # Update headers to admin role for incident creation
        with client.application.app_context():
            admin_user = User.query.filter_by(email='admin@talonvigil.com').first()
            if admin_user:
                # Login as admin
                response = client.post('/auth/login', json={
                    'email': 'admin@talonvigil.com',
                    'password': 'TalonVigil2025!'
                })
                
                if response.status_code == 200:
                    token = response.json.get('access_token')
                    admin_headers = {'Authorization': f'Bearer {token}'}
                    
                    incident_data = {
                        'title': 'Test Security Incident',
                        'description': 'This is a test incident for validation',
                        'severity': 'medium',
                        'tags': ['test', 'validation']
                    }
                    
                    response = client.post(
                        '/api/v1/soar/incidents',
                        json=incident_data,
                        headers=admin_headers
                    )
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    assert 'incident_id' in data
                    assert data['message'] == 'Incident created successfully'

class TestChaosEngineering:
    """Test chaos engineering integration"""
    
    def test_chaos_engine_initialization(self, app):
        """Test chaos engine initialization"""
        with app.app_context():
            chaos_engine = app.extensions.get('chaos_engine')
            assert chaos_engine is not None
            assert isinstance(chaos_engine, ChaosEngineering)
    
    def test_chaos_experiment_api(self, client, auth_headers):
        """Test chaos experiment creation API"""
        experiment_data = {
            'id': 'test-chaos-001',
            'name': 'Test Network Latency',
            'description': 'Test network latency injection',
            'chaos_type': 'network_latency',
            'duration': 60,
            'target': 'service:test-service',
            'parameters': {
                'latency_ms': 100,
                'jitter_ms': 10
            }
        }
        
        # Need admin role for chaos experiments
        with client.application.app_context():
            admin_user = User.query.filter_by(email='admin@talonvigil.com').first()
            if admin_user:
                response = client.post('/auth/login', json={
                    'email': 'admin@talonvigil.com',
                    'password': 'TalonVigil2025!'
                })
                
                if response.status_code == 200:
                    token = response.json.get('access_token')
                    admin_headers = {'Authorization': f'Bearer {token}'}
                    
                    response = client.post(
                        '/api/v1/chaos/experiments',
                        json=experiment_data,
                        headers=admin_headers
                    )
                    
                    assert response.status_code == 200
                    data = response.get_json()
                    assert data['message'] == 'Experiment created successfully'

class TestHealthAndMonitoring:
    """Test health checks and monitoring"""
    
    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'status' in data
        assert 'timestamp' in data
        assert 'components' in data
    
    def test_readiness_probe(self, client):
        """Test Kubernetes readiness probe"""
        response = client.get('/health/ready')
        assert response.status_code in [200, 503]
        
        data = response.get_json()
        assert 'status' in data
    
    def test_liveness_probe(self, client):
        """Test Kubernetes liveness probe"""
        response = client.get('/health/live')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['status'] == 'alive'

class TestSecurityHeaders:
    """Test security headers implementation"""
    
    def test_security_headers_present(self, client):
        """Test that security headers are present"""
        response = client.get('/health')
        
        # Check for important security headers
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        
        assert 'X-Frame-Options' in response.headers
        assert response.headers['X-Frame-Options'] == 'DENY'
        
        assert 'X-XSS-Protection' in response.headers
        assert response.headers['X-XSS-Protection'] == '1; mode=block'
        
        if 'Content-Security-Policy' in response.headers:
            csp = response.headers['Content-Security-Policy']
            assert 'default-src' in csp

class TestInputSanitization:
    """Test input sanitization"""
    
    def test_sql_injection_protection(self, client, auth_headers):
        """Test SQL injection protection"""
        # Attempt SQL injection in search parameter
        malicious_query = "'; DROP TABLE users; --"
        
        response = client.get(
            f'/api/v1/threat-intel/search?q={malicious_query}',
            headers=auth_headers
        )
        
        # Should not cause an error and should sanitize input
        assert response.status_code == 200
    
    def test_xss_protection(self, client, auth_headers):
        """Test XSS protection"""
        xss_payload = '<script>alert("xss")</script>'
        
        response = client.post(
            '/api/v1/threat-scoring/feedback',
            json={
                'event_id': 'test-001',
                'true_label': 'benign',
                'analyst_notes': xss_payload
            },
            headers=auth_headers
        )
        
        # Should handle XSS attempts gracefully
        assert response.status_code in [200, 400]

@pytest.mark.asyncio
async def test_misp_integration():
    """Test MISP integration"""
    with patch('aiohttp.ClientSession.get') as mock_get:
        # Mock MISP response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            'response': {
                'Attribute': [{
                    'id': '123',
                    'type': 'ip-dst',
                    'value': '192.168.1.100',
                    'category': 'Network activity',
                    'timestamp': '2024-01-01T00:00:00Z',
                    'comment': 'Test indicator',
                    'Tag': [{'name': 'malware'}],
                    'event_id': '456'
                }]
            }
        })
        mock_get.return_value.__aenter__.return_value = mock_response
        
        # Test MISP source
        misp_source = MISPSource('https://misp.example.com', 'test-api-key')
        indicators = await misp_source.fetch_indicators()
        
        assert len(indicators) == 1
        assert indicators[0].value == '192.168.1.100'
        assert indicators[0].type == 'ip-dst'

def test_environment_configuration():
    """Test environment-specific configuration"""
    # Test that sensitive information is not exposed
    app = create_app(TestConfig)
    
    with app.app_context():
        # Should not expose sensitive config in debug mode
        assert not app.config.get('SECRET_KEY', '').startswith('dev-')
        assert app.config.get('TESTING') is True

if __name__ == '__main__':
    pytest.main(['-v', __file__])
