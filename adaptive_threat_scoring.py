"""
Adaptive Threat Scoring Engine for TalonVigil
Implements machine learning-based threat scoring with continuous adaptation
"""

import asyncio
import json
import logging
import pickle
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
from enum import Enum
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.cluster import DBSCAN
import joblib
import hashlib

logger = logging.getLogger(__name__)

class ThreatType(Enum):
    """Types of threats for scoring"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    APT = "apt"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RECONNAISSANCE = "reconnaissance"

class RiskLevel(Enum):
    """Risk levels for threat scoring"""
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5
    CRITICAL = 6

@dataclass
class ThreatFeatures:
    """Feature vector for threat scoring"""
    # Network features
    source_ip: str = ""
    destination_ip: str = ""
    port: int = 0
    protocol: str = ""
    bytes_transferred: int = 0
    connection_duration: float = 0.0
    
    # Behavioral features
    request_frequency: float = 0.0
    unique_endpoints: int = 0
    failed_auth_attempts: int = 0
    privilege_escalation_attempts: int = 0
    
    # Content features
    payload_entropy: float = 0.0
    suspicious_keywords: int = 0
    obfuscation_detected: bool = False
    encryption_detected: bool = False
    
    # Temporal features
    time_of_day: int = 0
    day_of_week: int = 0
    is_business_hours: bool = True
    
    # Reputation features
    source_reputation: float = 0.5
    destination_reputation: float = 0.5
    domain_age: int = 0
    
    # Historical features
    previous_incidents: int = 0
    source_history_score: float = 0.5
    pattern_match_score: float = 0.0
    
    # Metadata
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_system: str = ""
    alert_id: str = ""
    
    def to_vector(self) -> np.ndarray:
        """Convert features to numerical vector"""
        return np.array([
            self.port,
            self.bytes_transferred,
            self.connection_duration,
            self.request_frequency,
            self.unique_endpoints,
            self.failed_auth_attempts,
            self.privilege_escalation_attempts,
            self.payload_entropy,
            self.suspicious_keywords,
            float(self.obfuscation_detected),
            float(self.encryption_detected),
            self.time_of_day,
            self.day_of_week,
            float(self.is_business_hours),
            self.source_reputation,
            self.destination_reputation,
            self.domain_age,
            self.previous_incidents,
            self.source_history_score,
            self.pattern_match_score
        ])
    
    @classmethod
    def get_feature_names(cls) -> List[str]:
        """Get list of feature names"""
        return [
            'port', 'bytes_transferred', 'connection_duration',
            'request_frequency', 'unique_endpoints', 'failed_auth_attempts',
            'privilege_escalation_attempts', 'payload_entropy', 'suspicious_keywords',
            'obfuscation_detected', 'encryption_detected', 'time_of_day',
            'day_of_week', 'is_business_hours', 'source_reputation',
            'destination_reputation', 'domain_age', 'previous_incidents',
            'source_history_score', 'pattern_match_score'
        ]

@dataclass
class ThreatScore:
    """Threat scoring result"""
    score: float  # 0.0 to 1.0
    risk_level: RiskLevel
    threat_type: ThreatType
    confidence: float  # 0.0 to 1.0
    reasoning: List[str] = field(default_factory=list)
    contributing_factors: Dict[str, float] = field(default_factory=dict)
    model_version: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['risk_level'] = self.risk_level.value
        data['threat_type'] = self.threat_type.value
        data['timestamp'] = self.timestamp.isoformat()
        return data

@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_samples: int
    validation_samples: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
class ThreatScoringModel(ABC):
    """Abstract base class for threat scoring models"""
    
    @abstractmethod
    def train(self, features: np.ndarray, labels: np.ndarray) -> ModelMetrics:
        """Train the model"""
        pass
    
    @abstractmethod
    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict threat scores and confidence"""
        pass
    
    @abstractmethod
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        pass
    
    @abstractmethod
    def save_model(self, filepath: str) -> bool:
        """Save model to file"""
        pass
    
    @abstractmethod
    def load_model(self, filepath: str) -> bool:
        """Load model from file"""
        pass

class RandomForestThreatModel(ThreatScoringModel):
    """Random Forest-based threat scoring model"""
    
    def __init__(self, n_estimators: int = 100, random_state: int = 42):
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=random_state,
            class_weight='balanced',
            min_samples_leaf=2,
            max_features='sqrt'
        )
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        
    def train(self, features: np.ndarray, labels: np.ndarray) -> ModelMetrics:
        """Train the Random Forest model"""
        try:
            # Split data
            x_train, x_val, y_train, y_val = train_test_split(
                features, labels, test_size=0.2, random_state=self.random_state
            )
            
            # Scale features
            x_train_scaled = self.scaler.fit_transform(x_train)
            x_val_scaled = self.scaler.transform(x_val)
            
            # Encode labels
            y_train_encoded = self.label_encoder.fit_transform(y_train)
            y_val_encoded = self.label_encoder.transform(y_val)
            
            # Train model
            self.model.fit(x_train_scaled, y_train_encoded)
            self.is_trained = True
            
            # Validate
            y_pred = self.model.predict(x_val_scaled)
            
            # Calculate metrics
            metrics = ModelMetrics(
                accuracy=accuracy_score(y_val_encoded, y_pred),
                precision=precision_score(y_val_encoded, y_pred, average='weighted'),
                recall=recall_score(y_val_encoded, y_pred, average='weighted'),
                f1_score=f1_score(y_val_encoded, y_pred, average='weighted'),
                training_samples=len(x_train),
                validation_samples=len(x_val)
            )
            
            logger.info(f"Model trained with accuracy: {metrics.accuracy:.3f}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            raise
    
    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict threat scores and confidence"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        try:
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Get predictions and probabilities
            probabilities = self.model.predict_proba(features_scaled)
            
            # Convert to scores (0-1) and confidence
            scores = np.max(probabilities, axis=1)
            confidence = scores  # Use max probability as confidence
            
            return scores, confidence
            
        except Exception as e:
            logger.error(f"Error making predictions: {e}")
            raise
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        if not self.is_trained:
            return {}
        
        feature_names = ThreatFeatures.get_feature_names()
        importances = self.model.feature_importances_
        
        return dict(zip(feature_names, importances))
    
    def save_model(self, filepath: str) -> bool:
        """Save model to file"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'is_trained': self.is_trained,
                'n_estimators': self.n_estimators,
                'random_state': self.random_state
            }
            joblib.dump(model_data, filepath)
            logger.info(f"Model saved to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self, filepath: str) -> bool:
        """Load model from file"""
        try:
            model_data = joblib.load(filepath)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.label_encoder = model_data['label_encoder']
            self.is_trained = model_data['is_trained']
            self.n_estimators = model_data['n_estimators']
            self.random_state = model_data['random_state']
            logger.info(f"Model loaded from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False

class AnomalyDetectionModel:
    """Isolation Forest-based anomaly detection for threat scoring"""
    
    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state
        )
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def train(self, features: np.ndarray) -> bool:
        """Train the anomaly detection model"""
        try:
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Train model
            self.model.fit(features_scaled)
            self.is_trained = True
            
            logger.info("Anomaly detection model trained")
            return True
            
        except Exception as e:
            logger.error(f"Error training anomaly model: {e}")
            return False
    
    def predict_anomaly_score(self, features: np.ndarray) -> np.ndarray:
        """Predict anomaly scores"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        try:
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Get anomaly scores (-1 to 1, lower = more anomalous)
            scores = self.model.decision_function(features_scaled)
            
            # Convert to 0-1 scale (higher = more anomalous)
            normalized_scores = (1 - scores) / 2
            
            return normalized_scores
            
        except Exception as e:
            logger.error(f"Error predicting anomaly scores: {e}")
            raise

class AdaptiveThreatScoring:
    """
    Adaptive threat scoring engine with continuous learning
    """
    
    def __init__(self, model_dir: str = "./models"):
        self.model_dir = model_dir
        self.models: Dict[ThreatType, ThreatScoringModel] = {}
        self.anomaly_detector = AnomalyDetectionModel()
        self.feature_extractors: List[callable] = []
        self.feedback_data: List[Tuple[ThreatFeatures, ThreatScore, bool]] = []
        self.retraining_threshold = 100  # Retrain after N feedback samples
        self.model_version = self._generate_model_version()
        
        # Initialize models for each threat type
        self._initialize_models()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _generate_model_version(self) -> str:
        """Generate unique model version"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"adaptive_v{timestamp}"
    
    def _initialize_models(self):
        """Initialize threat scoring models"""
        for threat_type in ThreatType:
            self.models[threat_type] = RandomForestThreatModel()
    
    def register_feature_extractor(self, extractor: callable):
        """Register a feature extractor function"""
        self.feature_extractors.append(extractor)
    
    async def score_threat(self, features: ThreatFeatures) -> ThreatScore:
        """Score a threat based on features"""
        try:
            # Extract additional features
            enriched_features = await self._enrich_features(features)
            
            # Convert to vector
            feature_vector = enriched_features.to_vector().reshape(1, -1)
            
            # Get anomaly score
            anomaly_score = 0.0
            if self.anomaly_detector.is_trained:
                anomaly_scores = self.anomaly_detector.predict_anomaly_score(feature_vector)
                anomaly_score = anomaly_scores[0]
            
            # Get threat type predictions from all models
            threat_scores = {}
            threat_confidences = {}
            
            for threat_type, model in self.models.items():
                if model.is_trained:
                    try:
                        scores, confidences = model.predict(feature_vector)
                        threat_scores[threat_type] = scores[0]
                        threat_confidences[threat_type] = confidences[0]
                    except Exception as e:
                        logger.warning(f"Error scoring with {threat_type} model: {e}")
                        threat_scores[threat_type] = 0.5
                        threat_confidences[threat_type] = 0.0
                else:
                    # Use rule-based scoring if model not trained
                    threat_scores[threat_type] = self._rule_based_score(enriched_features, threat_type)
                    threat_confidences[threat_type] = 0.5
            
            # Determine primary threat type and score
            primary_threat_type = max(threat_scores, key=threat_scores.get)
            base_score = threat_scores[primary_threat_type]
            confidence = threat_confidences[primary_threat_type]
            
            # Combine with anomaly score
            final_score = self._combine_scores(base_score, anomaly_score)
            
            # Determine risk level
            risk_level = self._score_to_risk_level(final_score)
            
            # Generate reasoning
            reasoning = self._generate_reasoning(enriched_features, threat_scores, anomaly_score)
            
            # Get contributing factors
            contributing_factors = self._get_contributing_factors(enriched_features, primary_threat_type)
            
            threat_score = ThreatScore(
                score=final_score,
                risk_level=risk_level,
                threat_type=primary_threat_type,
                confidence=confidence,
                reasoning=reasoning,
                contributing_factors=contributing_factors,
                model_version=self.model_version
            )
            
            logger.debug(f"Threat scored: {final_score:.3f} ({risk_level.name}) - {primary_threat_type.value}")
            return threat_score
            
        except Exception as e:
            logger.error(f"Error scoring threat: {e}")
            # Return default score
            return ThreatScore(
                score=0.5,
                risk_level=RiskLevel.MEDIUM,
                threat_type=ThreatType.RECONNAISSANCE,
                confidence=0.0,
                reasoning=["Error in scoring process"],
                model_version=self.model_version
            )
    def provide_feedback(self, features: ThreatFeatures, score: ThreatScore,
                        is_true_positive: bool):
        """Provide feedback for model adaptation"""
        try:
            # Store feedback
            self.feedback_data.append((features, score, is_true_positive))
            
            logger.info(f"Feedback received: {score.threat_type.value} - {is_true_positive}")
            
            # Check if retraining is needed
            if len(self.feedback_data) >= self.retraining_threshold:
                self._retrain_models()
                self.feedback_data.clear()
                
        except Exception as e:
            logger.error(f"Error processing feedback: {e}")
    
    def train_models(self, training_data: List[Tuple[ThreatFeatures, ThreatType]]):
        """Train models with initial training data"""
        try:
            # Group data by threat type
            type_data = {}
            for features, threat_type in training_data:
                if threat_type not in type_data:
                    type_data[threat_type] = []
                type_data[threat_type].append(features)
            
            # Train each model
            for threat_type, feature_list in type_data.items():
                if len(feature_list) < 10:  # Need minimum samples
                    logger.warning(f"Insufficient data for {threat_type}: {len(feature_list)} samples")
                    continue
                
                # Convert to arrays
                X = np.array([f.to_vector() for f in feature_list])
                y = np.array([threat_type.value] * len(feature_list))
                
                # Train model
                model = self.models[threat_type]
                metrics = model.train(X, y)
                
                logger.info(f"Trained {threat_type} model: {metrics.accuracy:.3f} accuracy")
                
                # Save model
                model_path = f"{self.model_dir}/{threat_type.value}_model.joblib"
                model.save_model(model_path)
            
            # Train anomaly detector with all data
            all_features = np.array([f.to_vector() for f, _ in training_data])
            self.anomaly_detector.train(all_features)
            
            logger.info("Initial model training completed")
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
    
    def get_model_metrics(self) -> Dict[str, Any]:
        """Get model performance metrics"""
        metrics = {
            'model_version': self.model_version,
            'trained_models': 0,
            'feedback_samples': len(self.feedback_data),
            'anomaly_detector_trained': self.anomaly_detector.is_trained,
            'feature_importance': {}
        }
        
        for threat_type, model in self.models.items():
            if model.is_trained:
                metrics['trained_models'] += 1
                importance = model.get_feature_importance()
                metrics['feature_importance'][threat_type.value] = importance
        
        return metrics
    
    async def _enrich_features(self, features: ThreatFeatures) -> ThreatFeatures:
        """Enrich features with additional extractors"""
        enriched = features
        
        for extractor in self.feature_extractors:
            try:
                additional_features = await extractor(features)
                # Merge additional features (simplified)
                if hasattr(additional_features, 'source_reputation'):
                    enriched.source_reputation = additional_features.source_reputation
                if hasattr(additional_features, 'pattern_match_score'):
                    enriched.pattern_match_score = additional_features.pattern_match_score
            except Exception as e:
                logger.warning(f"Feature extractor error: {e}")
        
        return enriched
    
    def _rule_based_score(self, features: ThreatFeatures, _threat_type: ThreatType) -> float:
        """Rule-based scoring fallback"""
        score = 0.5  # Base score
        
        # Network-based rules
        if features.port in [22, 23, 135, 139, 445, 3389]:  # Common attack ports
            score += 0.1
        
        if features.bytes_transferred > 1000000:  # Large data transfer
            score += 0.1
        
        # Behavioral rules
        if features.failed_auth_attempts > 3:
            score += 0.2
        
        if features.privilege_escalation_attempts > 0:
            score += 0.3
        
        # Content rules
        if features.payload_entropy > 0.8:  # High entropy = possible encryption/obfuscation
            score += 0.1
        
        if features.suspicious_keywords > 5:
            score += 0.1
        
        if features.obfuscation_detected:
            score += 0.2
        
        # Reputation rules
        if features.source_reputation < 0.3:
            score += 0.2
        
        # Time-based rules
        if not features.is_business_hours:
            score += 0.1
        
        # Historical rules
        if features.previous_incidents > 2:
            score += 0.1
        
        return min(1.0, score)
    
    def _combine_scores(self, base_score: float, anomaly_score: float) -> float:
        """Combine base score with anomaly score"""
        # Weighted combination
        combined = 0.7 * base_score + 0.3 * anomaly_score
        return min(1.0, max(0.0, combined))
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert score to risk level"""
        if score < 0.15:
            return RiskLevel.VERY_LOW
        elif score < 0.3:
            return RiskLevel.LOW
        elif score < 0.5:
            return RiskLevel.MEDIUM
        elif score < 0.7:
            return RiskLevel.HIGH
        elif score < 0.9:
            return RiskLevel.VERY_HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _generate_reasoning(self, features: ThreatFeatures, 
                           threat_scores: Dict[ThreatType, float],
                           anomaly_score: float) -> List[str]:
        """Generate human-readable reasoning"""
        reasoning = []
        
        # High-scoring threat types
        high_threat_types = [t for t, s in threat_scores.items() if s > 0.7]
        if high_threat_types:
            reasoning.append(f"High confidence for: {', '.join([t.value for t in high_threat_types])}")
        
        # Anomaly detection
        if anomaly_score > 0.7:
            reasoning.append("Anomalous behavior detected")
        
        # Specific factors
        if features.failed_auth_attempts > 3:
            reasoning.append(f"Multiple failed authentication attempts: {features.failed_auth_attempts}")
        
        if features.privilege_escalation_attempts > 0:
            reasoning.append("Privilege escalation attempts detected")
        
        if features.source_reputation < 0.3:
            reasoning.append("Low source reputation")
        
        if features.suspicious_keywords > 5:
            reasoning.append(f"Multiple suspicious keywords: {features.suspicious_keywords}")
        
        if features.obfuscation_detected:
            reasoning.append("Code obfuscation detected")
        
        if not features.is_business_hours:
            reasoning.append("Activity outside business hours")
        
        if features.previous_incidents > 2:
            reasoning.append(f"Source has previous incidents: {features.previous_incidents}")
        
        return reasoning if reasoning else ["No specific threats identified"]
    
    def _get_contributing_factors(self, features: ThreatFeatures, 
                                 threat_type: ThreatType) -> Dict[str, float]:
        """Get contributing factors for the score"""
        factors = {}
        
        if threat_type in self.models and self.models[threat_type].is_trained:
            importance = self.models[threat_type].get_feature_importance()
            feature_vector = features.to_vector()
            
            for i, (name, imp) in enumerate(importance.items()):
                if i < len(feature_vector):
                    # Normalize feature value and combine with importance
                    normalized_value = min(1.0, feature_vector[i] / 100.0)  # Simple normalization
                    factors[name] = imp * normalized_value
        
        return factors
    
    def _retrain_models(self):
        """Retrain models with feedback data"""
        try:
            if not self.feedback_data:
                return
            
            # Group feedback by threat type
            type_feedback = {}
            for features, score, is_correct in self.feedback_data:
                threat_type = score.threat_type
                if threat_type not in type_feedback:
                    type_feedback[threat_type] = []
                
                # Create label based on feedback
                label = threat_type.value if is_correct else "negative"
                type_feedback[threat_type].append((features, label))
            
            # Retrain models with sufficient data
            for threat_type, feedback_list in type_feedback.items():
                if len(feedback_list) < 10:
                    continue
                
                # Prepare training data
                X = np.array([f.to_vector() for f, _ in feedback_list])
                y = np.array([label for _, label in feedback_list])
                
                # Retrain model
                model = self.models[threat_type]
                metrics = model.train(X, y)
                
                logger.info(f"Retrained {threat_type} model: {metrics.accuracy:.3f} accuracy")
                
                # Save updated model
                model_path = f"{self.model_dir}/{threat_type.value}_model.joblib"
                model.save_model(model_path)
            
            # Update model version
            self.model_version = self._generate_model_version()
            
            logger.info("Model retraining completed")
            
        except Exception as e:
            logger.error(f"Error retraining models: {e}")
    
    def _start_background_tasks(self):
        """Start background tasks"""
        self._cleanup_task = asyncio.create_task(self._cleanup_worker())
    
    async def _cleanup_worker(self):
        """Background cleanup worker"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Clean up old feedback data
                if len(self.feedback_data) > 1000:
                    self.feedback_data = self.feedback_data[-500:]  # Keep recent 500
                
                logger.debug("Cleanup completed")
                
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")

# Utility functions
def create_sample_features() -> List[ThreatFeatures]:
    """Create sample features for testing"""
    return [
        ThreatFeatures(
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            port=22,
            protocol="tcp",
            bytes_transferred=1024,
            connection_duration=30.0,
            request_frequency=0.5,
            failed_auth_attempts=5,
            payload_entropy=0.9,
            suspicious_keywords=3,
            obfuscation_detected=True,
            source_reputation=0.2,
            previous_incidents=3,
            is_business_hours=False
        ),
        ThreatFeatures(
            source_ip="203.0.113.1",
            destination_ip="192.168.1.50",
            port=80,
            protocol="tcp",
            bytes_transferred=512,
            connection_duration=5.0,
            request_frequency=2.0,
            payload_entropy=0.3,
            suspicious_keywords=1,
            source_reputation=0.8,
            is_business_hours=True
        )
    ]

def create_sample_training_data() -> List[Tuple[ThreatFeatures, ThreatType]]:
    """Create sample training data"""
    features = create_sample_features()
    return [
        (features[0], ThreatType.MALWARE),
        (features[1], ThreatType.RECONNAISSANCE)
    ]

async def demo_adaptive_scoring():
    """Demonstration of adaptive threat scoring"""
    # Initialize scoring engine
    scorer = AdaptiveThreatScoring()
    
    # Create training data
    training_data = create_sample_training_data()
    
    # Train models
    scorer.train_models(training_data)
    
    # Score new threats
    test_features = create_sample_features()[0]
    score = await scorer.score_threat(test_features)
    
    print(f"Threat Score: {score.score:.3f}")
    print(f"Risk Level: {score.risk_level.name}")
    print(f"Threat Type: {score.threat_type.value}")
    print(f"Confidence: {score.confidence:.3f}")
    print(f"Reasoning: {score.reasoning}")
    
    # Provide feedback
    scorer.provide_feedback(test_features, score, True)
    
    # Get metrics
    metrics = scorer.get_model_metrics()
    print(f"Model Metrics: {metrics}")

if __name__ == "__main__":
    asyncio.run(demo_adaptive_scoring())
