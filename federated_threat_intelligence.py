"""
Federated Threat Intelligence for TalonVigil
Implements federated learning and threat intelligence aggregation
"""

import asyncio
import json
import logging
import hashlib
import hmac
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Set, Union
from enum import Enum
import aiohttp
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatCategory(Enum):
    """Threat categories"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    APT = "apt"
    VULNERABILITY = "vulnerability"
    INDICATOR = "indicator"
    ATTACK_PATTERN = "attack_pattern"

class ConfidenceLevel(Enum):
    """Confidence levels for threat intelligence"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4

@dataclass
class ThreatIndicator:
    """Threat indicator data structure"""
    id: str
    type: str  # ip, domain, hash, url, etc.
    value: str
    category: ThreatCategory
    level: ThreatLevel
    confidence: ConfidenceLevel
    first_seen: datetime
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    ttl: int = 86400  # Time to live in seconds
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        data['category'] = self.category.value
        data['level'] = self.level.value
        data['confidence'] = self.confidence.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatIndicator':
        """Create from dictionary"""
        data['first_seen'] = datetime.fromisoformat(data['first_seen'])
        data['last_seen'] = datetime.fromisoformat(data['last_seen'])
        data['category'] = ThreatCategory(data['category'])
        data['level'] = ThreatLevel(data['level'])
        data['confidence'] = ConfidenceLevel(data['confidence'])
        return cls(**data)

@dataclass
class FederatedModel:
    """Federated learning model data"""
    model_id: str
    version: int
    weights: np.ndarray
    metrics: Dict[str, float]
    training_samples: int
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    node_id: str = ""
    encrypted: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transmission"""
        return {
            'model_id': self.model_id,
            'version': self.version,
            'weights': self.weights.tolist() if not self.encrypted else self.weights,
            'metrics': self.metrics,
            'training_samples': self.training_samples,
            'created_at': self.created_at.isoformat(),
            'node_id': self.node_id,
            'encrypted': self.encrypted
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FederatedModel':
        """Create from dictionary"""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        if not data.get('encrypted', False):
            data['weights'] = np.array(data['weights'])
        return cls(**data)

@dataclass
class FederationNode:
    """Federated threat intelligence node"""
    node_id: str
    name: str
    endpoint: str
    public_key: str
    trust_level: ConfidenceLevel
    capabilities: List[str] = field(default_factory=list)
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True
    reputation_score: float = 1.0
    shared_indicators: int = 0
    received_indicators: int = 0

class ThreatIntelligenceSource(ABC):
    """Abstract base class for threat intelligence sources"""
    
    @abstractmethod
    async def fetch_indicators(self, since: datetime = None) -> List[ThreatIndicator]:
        """Fetch threat indicators from source"""
        pass
    
    @abstractmethod
    async def submit_indicator(self, indicator: ThreatIndicator) -> bool:
        """Submit indicator to source"""
        pass

class MISPSource(ThreatIntelligenceSource):
    """MISP (Malware Information Sharing Platform) source"""
    
    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = None
    
    def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if not self.session:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            self.session = aiohttp.ClientSession(
                connector=connector,
                headers={
                    'Authorization': self.api_key,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            )
        return self.session
    
    async def fetch_indicators(self, since: datetime = None) -> List[ThreatIndicator]:
        """Fetch indicators from MISP"""
        try:
            session = self._get_session()
            
            params = {
                'returnFormat': 'json',
                'type': 'attributes',
                'to_ids': '1'
            }
            
            if since:
                params['timestamp'] = int(since.timestamp())
            
            async with session.get(f"{self.base_url}/attributes/restSearch", params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_misp_attributes(data.get('response', {}).get('Attribute', []))
                else:
                    logger.error(f"MISP fetch failed: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error fetching from MISP: {e}")
            return []
    
    async def submit_indicator(self, indicator: ThreatIndicator) -> bool:
        """Submit indicator to MISP"""
        try:
            session = self._get_session()
            
            misp_attribute = {
                'type': self._map_indicator_type(indicator.type),
                'value': indicator.value,
                'category': indicator.category.value,
                'to_ids': True,
                'comment': indicator.description,
                'tags': [{'name': tag} for tag in indicator.tags]
            }
            
            async with session.post(f"{self.base_url}/attributes/add", json=misp_attribute) as response:
                if response.status in [200, 201]:
                    logger.info(f"Submitted indicator to MISP: {indicator.id}")
                    return True
                else:
                    logger.error(f"MISP submission failed: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error submitting to MISP: {e}")
            return False
    
    def _parse_misp_attributes(self, attributes: List[Dict]) -> List[ThreatIndicator]:
        """Parse MISP attributes to ThreatIndicators"""
        indicators = []
        
        for attr in attributes:
            try:
                indicator = ThreatIndicator(
                    id=f"misp-{attr['id']}",
                    type=attr['type'],
                    value=attr['value'],
                    category=self._map_misp_category(attr.get('category', 'other')),
                    level=ThreatLevel.MEDIUM,  # Default, could be enhanced
                    confidence=ConfidenceLevel.MEDIUM,
                    first_seen=datetime.fromisoformat(attr['timestamp']),
                    source='misp',
                    description=attr.get('comment', ''),
                    tags=[tag['name'] for tag in attr.get('Tag', [])],
                    metadata={'event_id': attr.get('event_id')}
                )
                indicators.append(indicator)
                
            except Exception as e:
                logger.warning(f"Failed to parse MISP attribute: {e}")
                continue
        
        return indicators
    
    def _map_indicator_type(self, indicator_type: str) -> str:
        """Map internal indicator type to MISP type"""
        mapping = {
            'ip': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
            'md5': 'md5',
            'sha1': 'sha1',
            'sha256': 'sha256',
            'email': 'email-dst'
        }
        return mapping.get(indicator_type, indicator_type)
    
    def _map_misp_category(self, category: str) -> ThreatCategory:
        """Map MISP category to internal category"""
        mapping = {
            'payload delivery': ThreatCategory.MALWARE,
            'network activity': ThreatCategory.INDICATOR,
            'persistence mechanism': ThreatCategory.APT,
            'social engineering': ThreatCategory.PHISHING
        }
        return mapping.get(category.lower(), ThreatCategory.INDICATOR)

class OpenCTISource(ThreatIntelligenceSource):
    """OpenCTI threat intelligence source"""
    
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
    
    async def fetch_indicators(self, since: datetime = None) -> List[ThreatIndicator]:
        """Fetch indicators from OpenCTI"""
        try:
            headers = {'Authorization': f'Bearer {self.api_token}'}
            
            query = '''
            query GetIndicators($first: Int, $after: String) {
                indicators(first: $first, after: $after) {
                    edges {
                        node {
                            id
                            pattern
                            indicator_types
                            valid_from
                            valid_until
                            confidence
                            labels {
                                edges {
                                    node {
                                        value
                                    }
                                }
                            }
                        }
                    }
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                }
            }
            '''
            
            variables = {'first': 100}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/graphql",
                    headers=headers,
                    json={'query': query, 'variables': variables}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_opencti_indicators(data.get('data', {}).get('indicators', {}).get('edges', []))
                    else:
                        logger.error(f"OpenCTI fetch failed: {response.status}")
                        return []
                        
        except Exception as e:
            logger.error(f"Error fetching from OpenCTI: {e}")
            return []
    
    async def submit_indicator(self, indicator: ThreatIndicator) -> bool:
        """Submit indicator to OpenCTI"""
        # Implementation would depend on OpenCTI API for creating indicators
        # This is a simplified version
        return True
    
    def _parse_opencti_indicators(self, edges: List[Dict]) -> List[ThreatIndicator]:
        """Parse OpenCTI indicators"""
        indicators = []
        
        for edge in edges:
            node = edge['node']
            try:
                # Parse STIX pattern
                pattern = node['pattern']
                indicator_type, value = self._parse_stix_pattern(pattern)
                
                if indicator_type and value:
                    indicator = ThreatIndicator(
                        id=f"opencti-{node['id']}",
                        type=indicator_type,
                        value=value,
                        category=ThreatCategory.INDICATOR,
                        level=ThreatLevel.MEDIUM,
                        confidence=ConfidenceLevel(min(4, max(1, node.get('confidence', 2)))),
                        first_seen=datetime.fromisoformat(node['valid_from']),
                        source='opencti',
                        tags=[label['node']['value'] for label in node.get('labels', {}).get('edges', [])]
                    )
                    indicators.append(indicator)
                    
            except Exception as e:
                logger.warning(f"Failed to parse OpenCTI indicator: {e}")
                continue
        
        return indicators
    
    def _parse_stix_pattern(self, pattern: str) -> tuple:
        """Parse STIX pattern to extract type and value"""
        # Simplified STIX pattern parser
        # Real implementation would use a proper STIX parser
        try:
            if "file:hashes.MD5" in pattern:
                value = pattern.split("'")[1]
                return "md5", value
            elif "file:hashes.SHA-256" in pattern:
                value = pattern.split("'")[1]
                return "sha256", value
            elif "domain-name:value" in pattern:
                value = pattern.split("'")[1]
                return "domain", value
            elif "ipv4-addr:value" in pattern:
                value = pattern.split("'")[1]
                return "ip", value
            elif "url:value" in pattern:
                value = pattern.split("'")[1]
                return "url", value
        except Exception:
            pass
        
        return None, None

class FederatedThreatIntelligence:
    """
    Federated threat intelligence aggregator and coordinator
    """
    
    def __init__(self, node_id: str, encryption_key: Optional[str] = None):
        self.node_id = node_id
        self.encryption_key = encryption_key or self._generate_key()
        self.cipher = Fernet(self.encryption_key.encode() if isinstance(self.encryption_key, str) else self.encryption_key)
        
        # Data stores
        self.local_indicators: Dict[str, ThreatIndicator] = {}
        self.federated_indicators: Dict[str, ThreatIndicator] = {}
        self.federation_nodes: Dict[str, FederationNode] = {}
        self.sources: Dict[str, ThreatIntelligenceSource] = {}
        
        # Models
        self.local_models: Dict[str, FederatedModel] = {}
        self.global_models: Dict[str, FederatedModel] = {}
        
        # Configuration
        self.aggregation_interval = 3600  # 1 hour
        self.max_indicators_per_sync = 1000
        self.trust_threshold = 0.5
        
        # Start background tasks
        self._start_background_tasks()
    
    def _generate_key(self) -> bytes:
        """Generate encryption key"""
        password = os.urandom(32)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def register_source(self, name: str, source: ThreatIntelligenceSource):
        """Register a threat intelligence source"""
        self.sources[name] = source
        logger.info(f"Registered threat intelligence source: {name}")
    
    def register_federation_node(self, node: FederationNode):
        """Register a federation node"""
        self.federation_nodes[node.node_id] = node
        logger.info(f"Registered federation node: {node.name}")
    
    async def add_indicator(self, indicator: ThreatIndicator):
        """Add local threat indicator"""
        # Validate and enrich indicator
        enriched_indicator = self._enrich_indicator(indicator)
        
        # Store locally
        self.local_indicators[indicator.id] = enriched_indicator
        
        # Share with federation if confidence is high enough
        if enriched_indicator.confidence.value >= ConfidenceLevel.MEDIUM.value:
            await self._share_indicator(enriched_indicator)
        
        logger.info(f"Added threat indicator: {indicator.id}")
    def get_indicators(self,
                       indicator_type: str = None,
                       category: ThreatCategory = None,
                       min_confidence: ConfidenceLevel = ConfidenceLevel.LOW,
                       include_federated: bool = True) -> List[ThreatIndicator]:
        """Get threat indicators with filtering"""
        indicators = list(self.local_indicators.values())
        
        if include_federated:
            indicators.extend(self.federated_indicators.values())
        
        # Apply filters
        if indicator_type:
            indicators = [i for i in indicators if i.type == indicator_type]
        
        if category:
            indicators = [i for i in indicators if i.category == category]
        
        indicators = [i for i in indicators if i.confidence.value >= min_confidence.value]
        
        # Sort by confidence and recency
        indicators.sort(key=lambda x: (x.confidence.value, x.last_seen), reverse=True)
        
        return indicators
    
    def check_indicator(self, value: str, indicator_type: str = None) -> Optional[ThreatIndicator]:
        """Check if a value is a known threat indicator"""
        all_indicators = list(self.local_indicators.values()) + list(self.federated_indicators.values())
        
        for indicator in all_indicators:
            if indicator.value == value:
                if not indicator_type or indicator.type == indicator_type:
                    # Check if indicator is still valid (not expired)
                    if self._is_indicator_valid(indicator):
                        return indicator
        
        return None
    
    async def sync_with_sources(self):
        """Sync with external threat intelligence sources"""
        for source_name, source in self.sources.items():
            try:
                # Get indicators since last sync
                since = datetime.now(timezone.utc) - timedelta(hours=24)
                indicators = await source.fetch_indicators(since)
                
                logger.info(f"Fetched {len(indicators)} indicators from {source_name}")
                
                for indicator in indicators:
                    # Add to local store if not already present
                    if indicator.id not in self.local_indicators:
                        await self.add_indicator(indicator)
                        
            except Exception as e:
                logger.error(f"Error syncing with source {source_name}: {e}")
    
    async def sync_with_federation(self):
        """Sync with federation nodes"""
        for node_id, node in self.federation_nodes.items():
            if not node.active:
                continue
            
            try:
                # Request indicators from node
                indicators = self._request_indicators_from_node(node)
                
                for indicator in indicators:
                    # Validate and add to federated store
                    if self._validate_federated_indicator(indicator, node):
                        self.federated_indicators[indicator.id] = indicator
                        node.received_indicators += 1
                
                # Update node last seen
                node.last_seen = datetime.now(timezone.utc)
                
                logger.info(f"Synced {len(indicators)} indicators from node {node.name}")
                
            except Exception as e:
                logger.error(f"Error syncing with federation node {node.name}: {e}")
                node.reputation_score *= 0.95  # Reduce reputation on errors
    
    async def train_federated_model(self, model_id: str, training_data: np.ndarray, labels: np.ndarray):
        """Train local model for federated learning"""
        try:
            # Simple federated learning simulation
            # In practice, this would use frameworks like TensorFlow Federated or PySyft
            
            # Train local model (simplified)
            model_weights = self._train_model(training_data, labels)
            
            # Create federated model
            model = FederatedModel(
                model_id=model_id,
                version=len(self.local_models.get(model_id, [])) + 1,
                weights=model_weights,
                metrics={'accuracy': 0.85, 'loss': 0.15},  # Placeholder metrics
                training_samples=len(training_data),
                node_id=self.node_id
            )
            
            # Store locally
            self.local_models[model_id] = model
            
            # Share with federation
            await self._share_model(model)
            
            logger.info(f"Trained and shared federated model: {model_id}")
            
        except Exception as e:
            logger.error(f"Error training federated model: {e}")
    
    async def aggregate_federated_models(self, model_id: str) -> Optional[FederatedModel]:
        """Aggregate federated models using federated averaging"""
        try:
            # Collect models from federation
            models = self._collect_federated_models(model_id)
            
            if not models:
                return None
            
            # Federated averaging
            total_samples = sum(model.training_samples for model in models)
            aggregated_weights = np.zeros_like(models[0].weights)
            
            for model in models:
                weight_factor = model.training_samples / total_samples
                aggregated_weights += model.weights * weight_factor
            
            # Create aggregated model
            global_model = FederatedModel(
                model_id=model_id,
                version=max(model.version for model in models) + 1,
                weights=aggregated_weights,
                metrics={'aggregated': True},
                training_samples=total_samples,
                node_id='global'
            )
            
            self.global_models[model_id] = global_model
            
            logger.info(f"Aggregated federated model {model_id} from {len(models)} nodes")
            return global_model
            
        except Exception as e:
            logger.error(f"Error aggregating federated models: {e}")
            return None
    
    def get_federation_metrics(self) -> Dict[str, Any]:
        """Get federation metrics and statistics"""
        return {
            'local_indicators': len(self.local_indicators),
            'federated_indicators': len(self.federated_indicators),
            'federation_nodes': len(self.federation_nodes),
            'active_nodes': len([n for n in self.federation_nodes.values() if n.active]),
            'sources': len(self.sources),
            'local_models': len(self.local_models),
            'global_models': len(self.global_models),
            'reputation_scores': {
                node.node_id: node.reputation_score 
                for node in self.federation_nodes.values()
            }
        }
    
    def _enrich_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        """Enrich indicator with additional context"""
        # Add reputation scoring, geolocation, etc.
        # This is a simplified version
        
        # Check against existing indicators for correlation
        similar_indicators = []
        for existing in self.local_indicators.values():
            if existing.type == indicator.type and existing.category == indicator.category:
                similar_indicators.append(existing)
        
        # Adjust confidence based on correlation
        if len(similar_indicators) > 5:
            indicator.confidence = ConfidenceLevel.HIGH
        elif len(similar_indicators) > 2:
            indicator.confidence = ConfidenceLevel.MEDIUM
        
        # Add enrichment metadata
        indicator.metadata.update({
            'enrichment_timestamp': datetime.now(timezone.utc).isoformat(),
            'similar_indicators': len(similar_indicators),
            'enrichment_node': self.node_id
        })
        
        return indicator
    
    async def _share_indicator(self, indicator: ThreatIndicator):
        """Share indicator with federation nodes"""
        for node in self.federation_nodes.values():
            if not node.active or node.trust_level.value < ConfidenceLevel.MEDIUM.value:
                continue
            
            try:
                await self._send_indicator_to_node(indicator, node)
                node.shared_indicators += 1
                
            except Exception as e:
                logger.error(f"Error sharing indicator with node {node.name}: {e}")
    
    async def _share_model(self, model: FederatedModel):
        """Share model with federation nodes"""
        # Encrypt model weights before sharing
        encrypted_model = self._encrypt_model(model)
        
        for node in self.federation_nodes.values():
            if not node.active:
                continue
            
            try:
                await self._send_model_to_node(encrypted_model, node)
                
            except Exception as e:
                logger.error(f"Error sharing model with node {node.name}: {e}")
    
    def _encrypt_model(self, model: FederatedModel) -> FederatedModel:
        """Encrypt model weights for secure transmission"""
        try:
            weights_bytes = model.weights.tobytes()
            encrypted_weights = self.cipher.encrypt(weights_bytes)
            
            encrypted_model = FederatedModel(
                model_id=model.model_id,
                version=model.version,
                weights=encrypted_weights,
                metrics=model.metrics,
                training_samples=model.training_samples,
                created_at=model.created_at,
                node_id=model.node_id,
                encrypted=True
            )
            
            return encrypted_model
            
        except Exception as e:
            logger.error(f"Error encrypting model: {e}")
            return model
    
    def _decrypt_model(self, encrypted_model: FederatedModel) -> FederatedModel:
        """Decrypt model weights"""
        try:
            if not encrypted_model.encrypted:
                return encrypted_model
            
            decrypted_bytes = self.cipher.decrypt(encrypted_model.weights)
            weights = np.frombuffer(decrypted_bytes, dtype=np.float64)
            
            decrypted_model = FederatedModel(
                model_id=encrypted_model.model_id,
                version=encrypted_model.version,
                weights=weights,
                metrics=encrypted_model.metrics,
                training_samples=encrypted_model.training_samples,
                created_at=encrypted_model.created_at,
                node_id=encrypted_model.node_id,
                encrypted=False
            )
            
            return decrypted_model
            
        except Exception as e:
            logger.error(f"Error decrypting model: {e}")
            return encrypted_model
    
    def _train_model(self, training_data: np.ndarray, _labels: np.ndarray) -> np.ndarray:
        """Train model (simplified implementation)"""
        # This is a placeholder for actual ML training
        # In practice, would use proper ML frameworks
        
        # Simple linear model weights simulation
        n_features = training_data.shape[1]
        rng = np.random.default_rng(42)  # Fixed seed for reproducibility
        weights = rng.normal(0, 0.1, n_features)
        
        return weights
    
    def _is_indicator_valid(self, indicator: ThreatIndicator) -> bool:
        """Check if indicator is still valid (not expired)"""
        expiry_time = indicator.last_seen + timedelta(seconds=indicator.ttl)
        return datetime.now(timezone.utc) < expiry_time
    
    def _validate_federated_indicator(self, indicator: ThreatIndicator, source_node: FederationNode) -> bool:
        """Validate indicator from federation node"""
        # Check trust level
        if source_node.trust_level.value < ConfidenceLevel.LOW.value:
            return False
        
        # Check reputation score
        if source_node.reputation_score < self.trust_threshold:
            return False
        
        # Check if indicator is not too old
        age_hours = (datetime.now(timezone.utc) - indicator.last_seen).total_seconds() / 3600
        if age_hours > 168:  # 1 week
            return False
        
        return True
    
    def _request_indicators_from_node(self, node: FederationNode) -> List[ThreatIndicator]:
        """Request indicators from federation node"""
        # This would implement the actual federation protocol
        # For now, return empty list
        return []
    
    async def _send_indicator_to_node(self, indicator: ThreatIndicator, node: FederationNode):
        """Send indicator to federation node"""
        # This would implement the actual federation protocol
        pass
    
    async def _send_model_to_node(self, model: FederatedModel, node: FederationNode):
        """Send model to federation node"""
        # This would implement the actual federation protocol
        pass
    
    def _collect_federated_models(self, model_id: str) -> List[FederatedModel]:
        """Collect models from federation nodes"""
        # This would implement the actual federation protocol
        # For now, return local model only
        if model_id in self.local_models:
            return [self.local_models[model_id]]
        return []
    
    def _start_background_tasks(self):
        """Start background tasks for federation"""
        self._aggregation_task = asyncio.create_task(self._aggregation_worker())
        self._cleanup_task = asyncio.create_task(self._cleanup_worker())
    
    async def _aggregation_worker(self):
        """Background worker for periodic aggregation"""
        while True:
            try:
                await asyncio.sleep(self.aggregation_interval)
                
                # Sync with sources
                await self.sync_with_sources()
                
                # Sync with federation
                await self.sync_with_federation()
                
                # Aggregate models
                for model_id in self.local_models:
                    await self.aggregate_federated_models(model_id)
                
            except Exception as e:
                logger.error(f"Error in aggregation worker: {e}")
    
    async def _cleanup_worker(self):
        """Background worker for cleanup tasks"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Clean up expired indicators
                current_time = datetime.now(timezone.utc)
                expired_local = [
                    ind_id for ind_id, indicator in self.local_indicators.items()
                    if not self._is_indicator_valid(indicator)
                ]
                expired_federated = [
                    ind_id for ind_id, indicator in self.federated_indicators.items()
                    if not self._is_indicator_valid(indicator)
                ]
                
                for ind_id in expired_local:
                    del self.local_indicators[ind_id]
                
                for ind_id in expired_federated:
                    del self.federated_indicators[ind_id]
                
                logger.info(f"Cleaned up {len(expired_local)} local and {len(expired_federated)} federated indicators")
                
                # Update node reputation scores
                for node in self.federation_nodes.values():
                    # Decay reputation over time for inactive nodes
                    hours_since_seen = (current_time - node.last_seen).total_seconds() / 3600
                    if hours_since_seen > 24:
                        node.reputation_score *= 0.99
                        if node.reputation_score < 0.1:
                            node.active = False
                
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")

# Utility functions for federation setup
def create_sample_federation() -> FederatedThreatIntelligence:
    """Create a sample federation with demo data"""
    federation = FederatedThreatIntelligence("demo-node-001")
    
    # Add sample indicators
    sample_indicators = [
        ThreatIndicator(
            id="demo-001",
            type="ip",
            value="192.168.1.100",
            category=ThreatCategory.MALWARE,
            level=ThreatLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            first_seen=datetime.now(timezone.utc) - timedelta(hours=2),
            source="demo",
            description="Known C2 server",
            tags=["c2", "malware", "botnet"]
        ),
        ThreatIndicator(
            id="demo-002",
            type="domain",
            value="evil.example.com",
            category=ThreatCategory.PHISHING,
            level=ThreatLevel.MEDIUM,
            confidence=ConfidenceLevel.MEDIUM,
            first_seen=datetime.now(timezone.utc) - timedelta(hours=6),
            source="demo",
            description="Phishing domain",
            tags=["phishing", "credential-theft"]
        )
    ]
    
    tasks = []
    for indicator in sample_indicators:
        # Store the task to prevent garbage collection
        task = asyncio.create_task(federation.add_indicator(indicator))
        tasks.append(task)
    
    return federation

def setup_misp_integration(misp_url: str, misp_key: str) -> MISPSource:
    """Setup MISP integration"""
    return MISPSource(misp_url, misp_key)

def setup_opencti_integration(opencti_url: str, opencti_token: str) -> OpenCTISource:
    """Setup OpenCTI integration"""
    return OpenCTISource(opencti_url, opencti_token)
