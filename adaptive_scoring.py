"""
Adaptive Threat Scoring for TalonVigil
ML-based threat scoring system that adapts to evolving threats
"""

import numpy as np
import pandas as pd
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import pickle
import hashlib
from pathlib import Path
import threading

# ML imports
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.feature_extraction.text import TfidfVectorizer
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("ML libraries not available. Install scikit-learn and numpy for full functionality.")

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    """Categories of threats for scoring"""
    MALWARE = "malware"
    PHISHING = "phishing"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    COMMAND_CONTROL = "command_control"
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ACCESS = "credential_access"

class RiskLevel(Enum):
    """Risk levels for threats"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatEvent:
    """Individual threat event for scoring"""
    id: str
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    event_type: str = ""
    event_data: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    raw_score: float = 0.0
    adjusted_score: float = 0.0
    category: Optional[ThreatCategory] = None
    risk_level: Optional[RiskLevel] = None
    confidence: float = 0.0
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ThreatFeatures:
    """Extracted features for ML scoring"""
    # Network features
    source_ip_reputation: float = 0.0
    destination_ip_reputation: float = 0.0
    geo_anomaly_score: float = 0.0
    port_anomaly_score: float = 0.0
    traffic_volume_anomaly: float = 0.0
    
    # Temporal features
    time_anomaly_score: float = 0.0
    frequency_anomaly_score: float = 0.0
    
    # User behavior features
    user_anomaly_score: float = 0.0
    access_pattern_anomaly: float = 0.0
    privilege_anomaly_score: float = 0.0
    
    # Content features
    payload_entropy: float = 0.0
    suspicious_keywords_score: float = 0.0
    file_reputation_score: float = 0.0
    
    # Contextual features
    threat_intel_match: float = 0.0
    historical_pattern_match: float = 0.0
    attack_chain_score: float = 0.0
    
    def to_array(self) -> np.ndarray:
        """Convert features to numpy array for ML"""
        return np.array([
            self.source_ip_reputation,
            self.destination_ip_reputation,
            self.geo_anomaly_score,
            self.port_anomaly_score,
            self.traffic_volume_anomaly,
            self.time_anomaly_score,
            self.frequency_anomaly_score,
            self.user_anomaly_score,
            self.access_pattern_anomaly,
            self.privilege_anomaly_score,
            self.payload_entropy,
            self.suspicious_keywords_score,
            self.file_reputation_score,
            self.threat_intel_match,
            self.historical_pattern_match,
            self.attack_chain_score
        ])

class FeatureExtractor:
    """Extract features from threat events for ML scoring"""
    
    def __init__(self):
        self.ip_reputation_cache = {}
        self.user_baselines = {}
        self.geo_baseline = {}
        self.port_baseline = {}
        self.suspicious_keywords = [
            'powershell', 'cmd.exe', 'rundll32', 'regsvr32', 'wscript',
            'cscript', 'mshta', 'certutil', 'bitsadmin', 'wget', 'curl',
            'base64', 'encoded', 'obfuscated', 'malware', 'backdoor',
            'payload', 'shellcode', 'exploit', 'vulnerability'
        ]
        self.tfidf_vectorizer = None
        if ML_AVAILABLE:
            self.tfidf_vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
    
    def extract_features(self, event: ThreatEvent, context: Dict[str, Any] = None) -> ThreatFeatures:
        """Extract features from a threat event"""
        features = ThreatFeatures()
        
        # Network features
        if event.source_ip:
            features.source_ip_reputation = self._get_ip_reputation(event.source_ip)
            features.geo_anomaly_score = self._calculate_geo_anomaly(event.source_ip, context)
        
        if event.destination_ip:
            features.destination_ip_reputation = self._get_ip_reputation(event.destination_ip)
        
        # Extract port information from event data
        port = event.event_data.get('destination_port') or event.event_data.get('port')
        if port:
            features.port_anomaly_score = self._calculate_port_anomaly(port, context)
        
        # Traffic volume features
        traffic_volume = event.event_data.get('bytes_transferred', 0)
        features.traffic_volume_anomaly = self._calculate_traffic_anomaly(traffic_volume, context)
        
        # Temporal features
        features.time_anomaly_score = self._calculate_time_anomaly(event.timestamp, context)
        features.frequency_anomaly_score = self._calculate_frequency_anomaly(event, context)
        
        # User behavior features
        if event.user_id:
            features.user_anomaly_score = self._calculate_user_anomaly(event.user_id, event, context)
            features.access_pattern_anomaly = self._calculate_access_pattern_anomaly(event.user_id, event, context)
            features.privilege_anomaly_score = self._calculate_privilege_anomaly(event.user_id, event, context)
        
        # Content features
        payload = event.event_data.get('payload') or event.event_data.get('command') or ""
        if payload:
            features.payload_entropy = self._calculate_entropy(payload)
            features.suspicious_keywords_score = self._calculate_keyword_score(payload)
        
        # File reputation
        file_hash = (event.event_data.get('file_hash') or 
                    event.event_data.get('md5') or 
                    event.event_data.get('sha256'))
        if file_hash:
            features.file_reputation_score = self._get_file_reputation(file_hash)
        
        # Threat intelligence matching
        features.threat_intel_match = self._calculate_threat_intel_match(event, context)
        
        # Historical pattern matching
        features.historical_pattern_match = self._calculate_historical_match(event, context)
        
        # Attack chain scoring
        features.attack_chain_score = self._calculate_attack_chain_score(event, context)
        
        return features
    
    def _get_ip_reputation(self, ip: str) -> float:
        """Get IP reputation score (0-1, higher = more malicious)"""
        # Check cache first
        if ip in self.ip_reputation_cache:
            return self.ip_reputation_cache[ip]
        
        # Simple heuristics (in production, integrate with threat intel)
        score = 0.0
        
        # Private/internal IPs get lower scores
        if ip.startswith(('10.', '192.168.', '172.')):
            score = 0.1
        elif ip.startswith('127.'):
            score = 0.0
        else:
            # External IP - would query threat intelligence here
            score = 0.3  # Default neutral score
        
        self.ip_reputation_cache[ip] = score
        return score
    
    def _calculate_geo_anomaly(self, ip: str, context: Dict[str, Any]) -> float:
        """Calculate geographical anomaly score"""
        # In production, would use GeoIP database
        # For now, simple heuristic
        if context and 'expected_countries' in context:
            # Would check if IP's country is in expected list
            return 0.2  # Default low anomaly
        return 0.0
    
    def _calculate_port_anomaly(self, port: int, context: Dict[str, Any]) -> float:
        """Calculate port usage anomaly score"""
        # Common ports get lower scores
        common_ports = {80, 443, 22, 21, 25, 53, 110, 143, 993, 995}
        suspicious_ports = {1433, 3389, 5432, 6379, 27017}  # Database, RDP, etc.
        
        if port in common_ports:
            return 0.1
        elif port in suspicious_ports:
            return 0.7
        elif port > 49152:  # Dynamic/private ports
            return 0.4
        else:
            return 0.3
    
    def _calculate_traffic_anomaly(self, volume: int, context: Dict[str, Any]) -> float:
        """Calculate traffic volume anomaly"""
        if volume == 0:
            return 0.0
        
        # Large transfers might be suspicious
        if volume > 100 * 1024 * 1024:  # 100MB
            return 0.8
        elif volume > 10 * 1024 * 1024:  # 10MB
            return 0.5
        else:
            return 0.2
    
    def _calculate_time_anomaly(self, timestamp: datetime, context: Dict[str, Any]) -> float:
        """Calculate temporal anomaly score"""
        hour = timestamp.hour
        
        # Activity during off-hours is suspicious
        if hour < 6 or hour > 22:  # Outside normal business hours
            return 0.6
        elif hour < 8 or hour > 18:  # Early/late business hours
            return 0.3
        else:
            return 0.1
    
    def _calculate_frequency_anomaly(self, event: ThreatEvent, context: Dict[str, Any]) -> float:
        """Calculate frequency-based anomaly"""
        # Would analyze historical frequency patterns
        # For now, simple heuristic
        return 0.2
    
    def _calculate_user_anomaly(self, user_id: str, event: ThreatEvent, context: Dict[str, Any]) -> float:
        """Calculate user behavior anomaly"""
        # Would compare against user's historical behavior
        baseline = self.user_baselines.get(user_id, {})
        
        # Simple checks
        score = 0.0
        
        # Check if user typically accesses this type of resource
        if event.event_data.get('resource_type') not in baseline.get('typical_resources', []):
            score += 0.3
        
        # Check access time patterns
        hour = event.timestamp.hour
        if hour not in baseline.get('typical_hours', range(8, 18)):
            score += 0.4
        
        return min(score, 1.0)
    
    def _calculate_access_pattern_anomaly(self, user_id: str, event: ThreatEvent, context: Dict[str, Any]) -> float:
        """Calculate access pattern anomaly"""
        # Would analyze access patterns
        return 0.2
    
    def _calculate_privilege_anomaly(self, user_id: str, event: ThreatEvent, context: Dict[str, Any]) -> float:
        """Calculate privilege usage anomaly"""
        # Check if user is using elevated privileges unusually
        if event.event_data.get('elevated_privileges'):
            return 0.7
        return 0.1
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        # Normalize to 0-1 range (assuming max entropy ~8 for typical text)
        return min(entropy / 8.0, 1.0)
    
    def _calculate_keyword_score(self, text: str) -> float:
        """Calculate suspicious keyword score"""
        if not text:
            return 0.0
        
        text_lower = text.lower()
        matches = sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
        
        # Normalize by total keywords
        return min(matches / len(self.suspicious_keywords), 1.0)
    
    def _get_file_reputation(self, file_hash: str) -> float:
        """Get file reputation score"""
        # Would integrate with VirusTotal, etc.
        # For now, simple heuristic
        return 0.3
    
    def _calculate_threat_intel_match(self, event: ThreatEvent, context: Dict[str, Any]) -> float:
        """Calculate threat intelligence match score"""
        score = 0.0
        
        # Check if any indicators match threat intel
        for indicator in event.indicators:
            # Would query threat intelligence database
            # For now, assume some matches
            if any(keyword in indicator.lower() for keyword in ['malware', 'suspicious', 'threat']):
                score += 0.5
        
        return min(score, 1.0)
    
    def _calculate_historical_match(self, event: ThreatEvent, context: Dict[str, Any]) -> float:
        """Calculate historical pattern match score"""
        # Would compare against historical attack patterns
        return 0.2
    
    def _calculate_attack_chain_score(self, event: ThreatEvent, context: Dict[str, Any]) -> float:
        """Calculate attack chain progression score"""
        # Would analyze if event fits known attack chains
        return 0.3

class AdaptiveThreatScorer:
    """
    ML-based adaptive threat scoring system
    Uses ensemble methods and continuous learning
    """
    
    def __init__(self, model_dir: str = "./models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        
        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler() if ML_AVAILABLE else None
        self.label_encoder = LabelEncoder() if ML_AVAILABLE else None
        
        # Ensemble models
        self.models = {}
        self.model_weights = {}
        self.model_performance = {}
        
        # Training data buffer
        self.training_buffer = []
        self.max_buffer_size = 10000
        self.retrain_threshold = 1000
        
        # Model lock for thread safety
        self.model_lock = threading.Lock()
        
        # Initialize models if ML is available
        if ML_AVAILABLE:
            self._initialize_models()
            self._load_models()
    
    def _initialize_models(self):
        """Initialize ML models"""
        if not ML_AVAILABLE:
            return
        
        # Isolation Forest for anomaly detection
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Random Forest for classification
        self.models['random_forest'] = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight='balanced'
        )
        
        # Gradient Boosting for regression (threat score)
        self.models['gradient_boosting'] = GradientBoostingClassifier(
            n_estimators=100,
            random_state=42,
            learning_rate=0.1
        )
        
        # Initialize equal weights
        for model_name in self.models:
            self.model_weights[model_name] = 1.0 / len(self.models)
            self.model_performance[model_name] = {'accuracy': 0.5, 'last_updated': datetime.utcnow()}
    
    def score_threat(self, event: ThreatEvent, context: Dict[str, Any] = None) -> ThreatEvent:
        """Score a threat event using adaptive ML models"""
        if not ML_AVAILABLE:
            # Fallback to rule-based scoring
            return self._rule_based_score(event, context)
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(event, context)
            feature_array = features.to_array().reshape(1, -1)
            
            # Scale features
            if self.scaler and hasattr(self.scaler, 'transform'):
                feature_array = self.scaler.transform(feature_array)
            
            # Get predictions from ensemble
            scores = []
            confidences = []
            
            with self.model_lock:
                for model_name, model in self.models.items():
                    if hasattr(model, 'predict_proba'):
                        try:
                            # Get probability of being malicious
                            proba = model.predict_proba(feature_array)[0]
                            if len(proba) > 1:
                                score = proba[1]  # Probability of positive class
                            else:
                                score = proba[0]
                            
                            weight = self.model_weights.get(model_name, 1.0)
                            scores.append(score * weight)
                            confidences.append(max(proba))
                            
                        except Exception as e:
                            logger.warning(f"Model {model_name} prediction failed: {e}")
                    
                    elif hasattr(model, 'decision_function'):
                        try:
                            # Anomaly detection (Isolation Forest)
                            decision = model.decision_function(feature_array)[0]
                            # Convert to 0-1 score (negative = anomaly)
                            score = max(0, 1 + decision)  # decision is typically [-1, 1]
                            
                            weight = self.model_weights.get(model_name, 1.0)
                            scores.append(score * weight)
                            confidences.append(abs(decision))
                            
                        except Exception as e:
                            logger.warning(f"Model {model_name} anomaly detection failed: {e}")
            
            # Combine scores
            if scores:
                final_score = np.mean(scores)
                final_confidence = np.mean(confidences)
            else:
                # Fallback to rule-based
                return self._rule_based_score(event, context)
            
            # Update event with scores
            event.raw_score = final_score
            event.adjusted_score = self._apply_contextual_adjustments(final_score, event, context)
            event.confidence = final_confidence
            
            # Determine risk level and category
            event.risk_level = self._score_to_risk_level(event.adjusted_score)
            event.category = self._predict_threat_category(features, context)
            
            return event
            
        except Exception as e:
            logger.error(f"Error in ML threat scoring: {e}")
            return self._rule_based_score(event, context)
    
    def _rule_based_score(self, event: ThreatEvent, context: Dict[str, Any] = None) -> ThreatEvent:
        """Fallback rule-based scoring when ML is not available"""
        features = self.feature_extractor.extract_features(event, context)
        
        # Simple weighted scoring
        score = (
            features.source_ip_reputation * 0.2 +
            features.destination_ip_reputation * 0.15 +
            features.threat_intel_match * 0.25 +
            features.user_anomaly_score * 0.15 +
            features.time_anomaly_score * 0.1 +
            features.suspicious_keywords_score * 0.15
        )
        
        event.raw_score = score
        event.adjusted_score = self._apply_contextual_adjustments(score, event, context)
        event.confidence = 0.6  # Lower confidence for rule-based
        event.risk_level = self._score_to_risk_level(event.adjusted_score)
        event.category = ThreatCategory.ANOMALOUS_BEHAVIOR  # Default category
        
        return event
    
    def _apply_contextual_adjustments(self, base_score: float, event: ThreatEvent, context: Dict[str, Any]) -> float:
        """Apply contextual adjustments to base score"""
        adjusted_score = base_score
        
        # Time-based adjustments
        hour = event.timestamp.hour
        if hour < 6 or hour > 22:  # Off-hours
            adjusted_score *= 1.2
        
        # User context adjustments
        if event.user_id and context:
            user_risk = context.get('user_risk_scores', {}).get(event.user_id, 0.5)
            adjusted_score = (adjusted_score + user_risk) / 2
        
        # Asset criticality adjustments
        if context and 'asset_criticality' in context:
            criticality = context['asset_criticality']
            if criticality == 'critical':
                adjusted_score *= 1.3
            elif criticality == 'high':
                adjusted_score *= 1.2
            elif criticality == 'low':
                adjusted_score *= 0.9
        
        # Recent threat activity adjustments
        if context and context.get('recent_threats', 0) > 5:
            adjusted_score *= 1.1
        
        return min(adjusted_score, 1.0)
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level"""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.65:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.VERY_LOW
    
    def _predict_threat_category(self, features: ThreatFeatures, context: Dict[str, Any]) -> ThreatCategory:
        """Predict threat category based on features"""
        # Simple heuristic-based categorization
        # In production, would use a dedicated classifier
        
        if features.suspicious_keywords_score > 0.5:
            return ThreatCategory.MALWARE
        elif features.user_anomaly_score > 0.6:
            return ThreatCategory.PRIVILEGE_ESCALATION
        elif features.traffic_volume_anomaly > 0.7:
            return ThreatCategory.DATA_EXFILTRATION
        elif features.threat_intel_match > 0.5:
            return ThreatCategory.COMMAND_CONTROL
        else:
            return ThreatCategory.ANOMALOUS_BEHAVIOR
    
    def add_feedback(self, event: ThreatEvent, true_label: bool, analyst_notes: str = ""):
        """Add feedback for model training"""
        if not ML_AVAILABLE:
            return
        
        # Convert event to training sample
        features = self.feature_extractor.extract_features(event, event.context)
        
        training_sample = {
            'features': features.to_array(),
            'label': 1 if true_label else 0,
            'timestamp': datetime.utcnow(),
            'event_id': event.id,
            'analyst_notes': analyst_notes
        }
        
        self.training_buffer.append(training_sample)
        
        # Trigger retraining if buffer is full
        if len(self.training_buffer) >= self.retrain_threshold:
            self._retrain_models()
        
        logger.info(f"Added feedback for event {event.id}: {'positive' if true_label else 'negative'}")
    
    def _retrain_models(self):
        """Retrain models with accumulated feedback"""
        if not ML_AVAILABLE or len(self.training_buffer) < 100:
            return
        
        try:
            logger.info(f"Retraining models with {len(self.training_buffer)} samples")
            
            # Prepare training data
            X = np.array([sample['features'] for sample in self.training_buffer])
            y = np.array([sample['label'] for sample in self.training_buffer])
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Fit scaler
            self.scaler.fit(X_train)
            X_train_scaled = self.scaler.transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Retrain each model
            with self.model_lock:
                for model_name, model in self.models.items():
                    try:
                        if model_name == 'isolation_forest':
                            # Anomaly detection - only use normal data for training
                            normal_data = X_train_scaled[y_train == 0]
                            if len(normal_data) > 10:
                                model.fit(normal_data)
                        else:
                            # Supervised models
                            model.fit(X_train_scaled, y_train)
                        
                        # Evaluate model
                        if hasattr(model, 'predict'):
                            y_pred = model.predict(X_test_scaled)
                            accuracy = accuracy_score(y_test, y_pred)
                            
                            # Update model performance
                            self.model_performance[model_name] = {
                                'accuracy': accuracy,
                                'last_updated': datetime.utcnow()
                            }
                            
                            logger.info(f"Model {model_name} retrained with accuracy: {accuracy:.3f}")
                    
                    except Exception as e:
                        logger.error(f"Error retraining model {model_name}: {e}")
            
            # Update model weights based on performance
            self._update_model_weights()
            
            # Save models
            self._save_models()
            
            # Clear buffer (keep some recent samples)
            keep_samples = min(1000, len(self.training_buffer) // 2)
            self.training_buffer = self.training_buffer[-keep_samples:]
            
            logger.info("Model retraining completed")
            
        except Exception as e:
            logger.error(f"Error during model retraining: {e}")
    
    def _update_model_weights(self):
        """Update ensemble weights based on model performance"""
        total_accuracy = sum(perf['accuracy'] for perf in self.model_performance.values())
        
        if total_accuracy > 0:
            for model_name, performance in self.model_performance.items():
                self.model_weights[model_name] = performance['accuracy'] / total_accuracy
        else:
            # Equal weights if no performance data
            for model_name in self.models:
                self.model_weights[model_name] = 1.0 / len(self.models)
    
    def _save_models(self):
        """Save trained models to disk"""
        if not ML_AVAILABLE:
            return
        
        try:
            # Save individual models
            for model_name, model in self.models.items():
                model_path = self.model_dir / f"{model_name}.pkl"
                joblib.dump(model, model_path)
            
            # Save scaler
            if self.scaler:
                scaler_path = self.model_dir / "scaler.pkl"
                joblib.dump(self.scaler, scaler_path)
            
            # Save metadata
            metadata = {
                'model_weights': self.model_weights,
                'model_performance': {
                    name: {
                        'accuracy': perf['accuracy'],
                        'last_updated': perf['last_updated'].isoformat()
                    }
                    for name, perf in self.model_performance.items()
                },
                'training_buffer_size': len(self.training_buffer),
                'last_save': datetime.utcnow().isoformat()
            }
            
            metadata_path = self.model_dir / "metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("Models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def _load_models(self):
        """Load trained models from disk"""
        if not ML_AVAILABLE:
            return
        
        try:
            # Load metadata
            metadata_path = self.model_dir / "metadata.json"
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                self.model_weights = metadata.get('model_weights', {})
                
                # Load performance data
                perf_data = metadata.get('model_performance', {})
                for name, perf in perf_data.items():
                    self.model_performance[name] = {
                        'accuracy': perf['accuracy'],
                        'last_updated': datetime.fromisoformat(perf['last_updated'])
                    }
            
            # Load individual models
            for model_name in self.models:
                model_path = self.model_dir / f"{model_name}.pkl"
                if model_path.exists():
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"Loaded model: {model_name}")
            
            # Load scaler
            scaler_path = self.model_dir / "scaler.pkl"
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded feature scaler")
            
            logger.info("Models loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get current model status and performance"""
        return {
            'ml_available': ML_AVAILABLE,
            'models': list(self.models.keys()) if ML_AVAILABLE else [],
            'model_weights': self.model_weights,
            'model_performance': {
                name: {
                    'accuracy': perf['accuracy'],
                    'last_updated': perf['last_updated'].isoformat()
                }
                for name, perf in self.model_performance.items()
            },
            'training_buffer_size': len(self.training_buffer),
            'scaler_fitted': self.scaler is not None and hasattr(self.scaler, 'mean_') if ML_AVAILABLE else False
        }
    
    def batch_score_threats(self, events: List[ThreatEvent], 
                           context: Dict[str, Any] = None) -> List[ThreatEvent]:
        """Score multiple threat events efficiently"""
        if not ML_AVAILABLE:
            return [self._rule_based_score(event, context) for event in events]
        
        try:
            # Extract features for all events
            feature_arrays = []
            for event in events:
                features = self.feature_extractor.extract_features(event, context)
                feature_arrays.append(features.to_array())
            
            if not feature_arrays:
                return events
            
            # Batch prediction
            X = np.array(feature_arrays)
            if self.scaler and hasattr(self.scaler, 'transform'):
                X = self.scaler.transform(X)
            
            # Get ensemble predictions
            all_scores = []
            all_confidences = []
            
            with self.model_lock:
                for model_name, model in self.models.items():
                    if hasattr(model, 'predict_proba'):
                        try:
                            probas = model.predict_proba(X)
                            scores = probas[:, 1] if probas.shape[1] > 1 else probas[:, 0]
                            confidences = np.max(probas, axis=1)
                            
                            weight = self.model_weights.get(model_name, 1.0)
                            all_scores.append(scores * weight)
                            all_confidences.append(confidences)
                            
                        except Exception as e:
                            logger.warning(f"Batch prediction failed for {model_name}: {e}")
                    
                    elif hasattr(model, 'decision_function'):
                        try:
                            decisions = model.decision_function(X)
                            scores = np.maximum(0, 1 + decisions)
                            confidences = np.abs(decisions)
                            
                            weight = self.model_weights.get(model_name, 1.0)
                            all_scores.append(scores * weight)
                            all_confidences.append(confidences)
                            
                        except Exception as e:
                            logger.warning(f"Batch anomaly detection failed for {model_name}: {e}")
            
            # Combine scores
            if all_scores:
                final_scores = np.mean(all_scores, axis=0)
                final_confidences = np.mean(all_confidences, axis=0)
            else:
                # Fallback
                return [self._rule_based_score(event, context) for event in events]
            
            # Update events with scores
            for i, event in enumerate(events):
                event.raw_score = final_scores[i]
                event.adjusted_score = self._apply_contextual_adjustments(final_scores[i], event, context)
                event.confidence = final_confidences[i]
                event.risk_level = self._score_to_risk_level(event.adjusted_score)
                
                # Predict category (simplified for batch)
                features = self.feature_extractor.extract_features(event, context)
                event.category = self._predict_threat_category(features, context)
            
            return events
            
        except Exception as e:
            logger.error(f"Error in batch threat scoring: {e}")
            return [self._rule_based_score(event, context) for event in events]


# Utility functions
def create_threat_event_from_log(log_entry: Dict[str, Any]) -> ThreatEvent:
    """Create ThreatEvent from log entry"""
    event_id = log_entry.get('id') or hashlib.md5(str(log_entry).encode()).hexdigest()
    
    return ThreatEvent(
        id=event_id,
        timestamp=datetime.fromisoformat(log_entry.get('timestamp', datetime.utcnow().isoformat())),
        source_ip=log_entry.get('source_ip'),
        destination_ip=log_entry.get('destination_ip'),
        user_id=log_entry.get('user_id'),
        event_type=log_entry.get('event_type', ''),
        event_data=log_entry.get('data', {}),
        indicators=log_entry.get('indicators', [])
    )

def score_threat_events(scorer: AdaptiveThreatScorer, 
                       log_entries: List[Dict[str, Any]],
                       context: Dict[str, Any] = None) -> List[ThreatEvent]:
    """Score multiple log entries as threat events"""
    events = [create_threat_event_from_log(entry) for entry in log_entries]
    return scorer.batch_score_threats(events, context)

def get_high_risk_events(events: List[ThreatEvent], 
                        min_risk_level: RiskLevel = RiskLevel.HIGH) -> List[ThreatEvent]:
    """Filter events by minimum risk level"""
    risk_order = ["very_low", "low", "medium", "high", "critical"]
    min_index = risk_order.index(min_risk_level.value)
    
    return [
        event for event in events 
        if event.risk_level and risk_order.index(event.risk_level.value) >= min_index
    ]

def export_threat_scores(events: List[ThreatEvent], filename: str):
    """Export threat scores to CSV for analysis"""
    if not events:
        return
    
    data = []
    for event in events:
        data.append({
            'id': event.id,
            'timestamp': event.timestamp.isoformat(),
            'source_ip': event.source_ip,
            'destination_ip': event.destination_ip,
            'user_id': event.user_id,
            'event_type': event.event_type,
            'raw_score': event.raw_score,
            'adjusted_score': event.adjusted_score,
            'confidence': event.confidence,
            'risk_level': event.risk_level.value if event.risk_level else '',
            'category': event.category.value if event.category else ''
        })
    
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False)
    logger.info(f"Exported {len(events)} threat scores to {filename}")
