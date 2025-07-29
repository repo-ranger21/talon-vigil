"""
TalonVigil - Advanced Cybersecurity Platform
Main application with integrated Zero Trust, AI, SOAR, and DevSecOps features
"""

import os
import asyncio
import logging
import sys
from datetime import datetime
from typing import Optional
from flask import Flask, request, jsonify, render_template
from flask_login import login_required, current_user
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.exceptions import HTTPException

# Import configurations
from config import Config

# Import security components
from security_headers import setup_security_headers
from input_sanitization import setup_input_sanitization
from jwt_auth import setup_jwt_auth
from zero_trust import ZeroTrustManager
from soar_integration import SOARManager, SOARPlatform
from federated_threat_intelligence import FederatedThreatIntelligence
from adaptive_threat_scoring import AdaptiveThreatScorer
from chaos_engineering import ChaosEngineering
from observability import setup_observability

# Import existing components
from models import db, User, Role
from rbac import role_required
from automation_tasks import execute_playbook_step_automation

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('talon_vigil.log')
    ]
)
logger = logging.getLogger(__name__)

# Global managers (will be initialized in create_app)
zero_trust_manager: Optional[ZeroTrustManager] = None
soar_manager: Optional[SOARManager] = None
threat_intel: Optional[FederatedThreatIntelligence] = None
adaptive_scorer: Optional[AdaptiveThreatScorer] = None
chaos_engine: Optional[ChaosEngineering] = None

def create_app(config_class=Config) -> Flask:
    """Create and configure the advanced TalonVigil application"""
    global zero_trust_manager, soar_manager, threat_intel, adaptive_scorer, chaos_engine
    
    # Create Flask app
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize database
    db.init_app(app)
    
    # Setup security components
    setup_security_headers(app)
    setup_input_sanitization(app)
    setup_jwt_auth(app)
    
    # Setup observability and monitoring
    setup_observability(app)
    
    # Initialize advanced security components
    with app.app_context():
        try:
            # Initialize Zero Trust Manager
            zero_trust_config = {
                'azure_tenant_id': app.config.get('AZURE_TENANT_ID'),
                'azure_client_id': app.config.get('AZURE_CLIENT_ID'),
                'azure_client_secret': app.config.get('AZURE_CLIENT_SECRET'),
                'jwks_url': app.config.get('AZURE_JWKS_URL'),
                'issuer': app.config.get('AZURE_ISSUER'),
                'audience': app.config.get('AZURE_AUDIENCE'),
                'enable_mfa': app.config.get('ENABLE_MFA', True),
                'enable_conditional_access': app.config.get('ENABLE_CONDITIONAL_ACCESS', True),
                'trusted_locations': app.config.get('TRUSTED_LOCATIONS', []),
                'device_compliance_required': app.config.get('DEVICE_COMPLIANCE_REQUIRED', True)
            }
            zero_trust_manager = ZeroTrustManager(zero_trust_config)
            app.extensions['zero_trust'] = zero_trust_manager
            logger.info("Zero Trust Manager initialized")
            
            # Initialize SOAR Manager
            soar_manager = SOARManager()
            app.extensions['soar'] = soar_manager
            logger.info("SOAR Manager initialized")
            
            # Initialize Federated Threat Intelligence
            threat_intel = FederatedThreatIntelligence(
                node_id=app.config.get('NODE_ID', 'talon-vigil-primary'),
                federation_config={
                    'enable_federation': app.config.get('ENABLE_FEDERATION', True),
                    'trust_threshold': app.config.get('FEDERATION_TRUST_THRESHOLD', 0.7),
                    'max_peers': app.config.get('FEDERATION_MAX_PEERS', 10)
                }
            )
            app.extensions['threat_intel'] = threat_intel
            logger.info("Federated Threat Intelligence initialized")
            
            # Initialize Adaptive Threat Scorer
            adaptive_scorer = AdaptiveThreatScorer(
                model_config={
                    'model_type': app.config.get('ML_MODEL_TYPE', 'xgboost'),
                    'retrain_interval': app.config.get('ML_RETRAIN_INTERVAL', 86400),
                    'feedback_threshold': app.config.get('ML_FEEDBACK_THRESHOLD', 10)
                }
            )
            app.extensions['adaptive_scorer'] = adaptive_scorer
            logger.info("Adaptive Threat Scorer initialized")
            
            # Initialize Chaos Engineering
            chaos_engine = ChaosEngineering(
                config={
                    'safety_checks': app.config.get('CHAOS_SAFETY_CHECKS', True),
                    'max_concurrent_experiments': app.config.get('CHAOS_MAX_EXPERIMENTS', 3),
                    'environment': app.config.get('ENVIRONMENT', 'development')
                }
            )
            app.extensions['chaos_engine'] = chaos_engine
            logger.info("Chaos Engineering initialized")
            
            # Start background services
            if not app.config.get('TESTING', False):
                start_background_services(app)
            
        except Exception as e:
            logger.error(f"Error initializing advanced components: {e}")
            # Continue with basic functionality if advanced features fail
    
    # Register blueprints and routes
    register_routes(app)
    register_error_handlers(app)
    
    return app

def start_background_services(_app: Flask):
    """Start background services for threat intelligence and scoring"""
    try:
        # Start threat intelligence feeds
        if threat_intel:
            task1 = asyncio.create_task(threat_intel.start_background_sync())
            logger.info("Started threat intelligence background sync")
        
        # Start adaptive scoring background tasks
        if adaptive_scorer:
            task2 = asyncio.create_task(adaptive_scorer.start_background_training())
            logger.info("Started adaptive scoring background training")
            
    except Exception as e:
        logger.error(f"Error starting background services: {e}")

def register_routes(app: Flask):
    """Register application routes"""
    
    # Constants
    MISSING_FIELDS_ERROR = 'Missing required fields'
    
    # Health check endpoints
    @app.route('/health')
    def health_check():
        """Comprehensive health check"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': app.config.get('VERSION', '1.0.0'),
            'components': {}
        }
        
        # Check database
        try:
            db.engine.execute('SELECT 1')
            health_status['components']['database'] = 'healthy'
        except Exception as e:
            health_status['components']['database'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'degraded'
        
        # Check Zero Trust
        if zero_trust_manager:
            try:
                zt_status = zero_trust_manager.verify_device_compliance({})
                health_status['components']['zero_trust'] = 'healthy' if zt_status else 'unhealthy'
            except Exception:
                health_status['components']['zero_trust'] = 'unhealthy'
        
        # Check Threat Intelligence
        if threat_intel:
            ti_stats = threat_intel.get_statistics()
            health_status['components']['threat_intel'] = 'healthy'
            health_status['components']['threat_intel_indicators'] = ti_stats.get('total_indicators', 0)
        
        return jsonify(health_status)
    
    @app.route('/health/ready')
    def readiness_check():
        """Kubernetes readiness probe"""
        try:
            # Check critical components
            db.engine.execute('SELECT 1')
            return jsonify({'status': 'ready'}), 200
        except Exception:
            return jsonify({'status': 'not ready'}), 503
    
    @app.route('/health/live')
    def liveness_check():
        """Kubernetes liveness probe"""
        return jsonify({'status': 'alive'}), 200
    
    # Dashboard
    @app.route('/')
    @login_required
    def dashboard():
        """Main security dashboard"""
        dashboard_data = {
            'user': current_user.username if hasattr(current_user, 'username') else 'Unknown',
            'timestamp': datetime.now().isoformat(),
            'threat_summary': {},
            'recent_alerts': []
        }
        
        # Get threat intelligence summary
        if threat_intel:
            ti_stats = threat_intel.get_statistics()
            dashboard_data['threat_summary'] = {
                'total_indicators': ti_stats.get('total_indicators', 0),
                'last_update': ti_stats.get('last_update'),
                'federated_nodes': ti_stats.get('federated_nodes', 0)
            }
        
        return render_template('dashboard.html', data=dashboard_data)

def register_threat_intel_routes(app: Flask):
    """Register threat intelligence API routes"""
    
    @app.route('/api/v1/threat-intel/enrich', methods=['POST'])
    @login_required
    @role_required('analyst')
    def enrich_indicator():
        """Enrich an indicator with threat intelligence"""
        if not threat_intel:
            return jsonify({'error': 'Threat intelligence not available'}), 503
        
        data = request.get_json()
        if not data or 'indicator' not in data or 'type' not in data:
            return jsonify({'error': 'Missing indicator or type'}), 400
        
        try:
            # Run enrichment
            result = asyncio.run(
                threat_intel.enrich_indicator(data['indicator'], data['type'])
            )
            
            if result:
                return jsonify({
                    'indicator': result['indicator'],
                    'type': result['type'],
                    'confidence': result.get('confidence', 0.0),
                    'sources': result.get('sources', []),
                    'last_seen': result.get('last_seen'),
                    'tags': result.get('tags', []),
                    'metadata': result.get('metadata', {})
                })
            else:
                return jsonify({'message': 'No intelligence found'}), 404
                
        except Exception as e:
            logger.error(f"Error enriching indicator: {e}")
            return jsonify({'error': 'Enrichment failed'}), 500
    
    @app.route('/api/v1/threat-intel/search', methods=['GET'])
    @login_required
    @role_required('analyst')
    def search_indicators():
        """Search threat intelligence indicators"""
        if not threat_intel:
            return jsonify({'error': 'Threat intelligence not available'}), 503
        
        query = request.args.get('q', '')
        limit = min(int(request.args.get('limit', 50)), 1000)
        
        try:
            results = threat_intel.search_indicators(query=query, limit=limit)
            
            return jsonify({
                'results': results,
                'total': len(results)
            })
            
        except Exception as e:
            logger.error(f"Error searching indicators: {e}")
            return jsonify({'error': 'Search failed'}), 500

def register_threat_scoring_routes(app: Flask):
    """Register threat scoring API routes"""
    
    @app.route('/api/v1/threat-scoring/score', methods=['POST'])
    @login_required
    @role_required('analyst')
    def score_threat():
        """Score a threat event"""
        if not adaptive_scorer:
            return jsonify({'error': 'Threat scoring not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        try:
            # Score the event
            scored_event = adaptive_scorer.score_threat_event(data)
            
            return jsonify({
                'raw_score': scored_event.get('raw_score', 0.0),
                'adjusted_score': scored_event.get('adjusted_score', 0.0),
                'confidence': scored_event.get('confidence', 0.0),
                'risk_level': scored_event.get('risk_level', 'unknown'),
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error scoring threat: {e}")
            return jsonify({'error': 'Scoring failed'}), 500
    
    @app.route('/api/v1/threat-scoring/feedback', methods=['POST'])
    @login_required
    @role_required('analyst')
    def provide_feedback():
        """Provide feedback for threat scoring model"""
        if not adaptive_scorer:
            return jsonify({'error': 'Threat scoring not available'}), 503
        
        data = request.get_json()
        required_fields = ['event_id', 'true_label', 'analyst_notes']
        
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        try:
            adaptive_scorer.add_feedback(
                data['event_id'],
                data['true_label'],
                data['analyst_notes']
            )
            
            return jsonify({'message': 'Feedback recorded successfully'})
            
        except Exception as e:
            logger.error(f"Error providing feedback: {e}")
            return jsonify({'error': 'Feedback failed'}), 500

def register_soar_routes(app: Flask):
    """Register SOAR integration API routes"""
    
    @app.route('/api/v1/soar/incidents', methods=['POST'])
    @login_required
    @role_required('admin')
    def create_soar_incident():
        """Create incident in SOAR platform"""
        if not soar_manager:
            return jsonify({'error': 'SOAR integration not available'}), 503
        
        data = request.get_json()
        if not data or 'title' not in data or 'description' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        
        try:
            incident_data = {
                'id': data.get('id', f"talon_{datetime.now().strftime('%Y%m%d_%H%M%S')}"),
                'title': data['title'],
                'description': data['description'],
                'severity': data.get('severity', 'medium'),
                'tags': data.get('tags', []),
                'custom_fields': data.get('custom_fields', {})
            }
            
            # Create incident
            result = asyncio.run(soar_manager.create_incident(incident_data))
            
            return jsonify({
                'incident_id': incident_data['id'],
                'platform_ids': result.get('platform_ids', {}),
                'message': 'Incident created successfully'
            })
            
        except Exception as e:
            logger.error(f"Error creating SOAR incident: {e}")
            return jsonify({'error': 'Incident creation failed'}), 500

def register_chaos_routes(app: Flask):
    """Register chaos engineering API routes"""
    
    @app.route('/api/v1/chaos/experiments', methods=['POST'])
    @login_required
    @role_required('admin')
    def create_chaos_experiment():
        """Create a chaos experiment"""
        if not chaos_engine:
            return jsonify({'error': 'Chaos engineering not available'}), 503
        
        data = request.get_json()
        required_fields = ['id', 'name', 'chaos_type', 'duration', 'target']
        
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        try:
            experiment = {
                'id': data['id'],
                'name': data['name'],
                'description': data.get('description', ''),
                'chaos_type': data['chaos_type'],
                'parameters': data.get('parameters', {}),
                'duration': data['duration'],
                'target': data['target']
            }
            
            success = asyncio.run(chaos_engine.create_experiment(experiment))
            
            if success:
                return jsonify({'message': 'Experiment created successfully'})
            else:
                return jsonify({'error': 'Experiment creation failed'}), 500
                
        except Exception as e:
            logger.error(f"Error creating chaos experiment: {e}")
            return jsonify({'error': 'Experiment creation failed'}), 500
    
    # Register all route groups
    register_threat_intel_routes(app)
    register_threat_scoring_routes(app)
    register_soar_routes(app)
    register_chaos_routes(app)

    
    # Legacy playbook automation endpoint
    @app.route("/playbooks/steps/<int:step_id>/execute_automation", methods=["POST"])
    @login_required
    @role_required('admin')
    def execute_step_automation(step_id):
        """Execute playbook step automation (legacy endpoint)"""
        try:
            from db_manager import PlaybookStep, Playbook
            step = PlaybookStep.query.get_or_404(step_id)
            playbook = Playbook.query.get(step.playbook_id)
            
            # Ensure user has permission
            if playbook.user_id != current_user.id and not current_user.is_admin():
                return jsonify({"success": False, "message": "Unauthorized"}), 403
            
            # Require explicit consent
            if not (request.args.get("confirm") == "true" or request.json.get("confirm") is True):
                return jsonify({"success": False, "message": "Consent required"}), 400
            
            # Enqueue the Celery task
            execute_playbook_step_automation.delay(step_id)
            step.execution_status = "Pending"
            db.session.commit()
            
            return jsonify({"success": True, "message": "Automation initiated. Refresh to see status."})
        except Exception as e:
            logger.error(f"Error executing playbook automation: {e}")
            return jsonify({"success": False, "message": "Execution failed"}), 500

def register_error_handlers(app: Flask):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        return jsonify({'error': error.description}), error.code

# Create the application
app = create_app()

if __name__ == '__main__':
    # Development server
    app.run(
        host=app.config.get('HOST', '0.0.0.0'),
        port=app.config.get('PORT', 5000),
        debug=app.config.get('DEBUG', False),
        threaded=True
    )