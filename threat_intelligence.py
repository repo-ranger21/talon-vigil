"""
Federated Threat Intelligence for TalonVigil
Aggregates threat intelligence from multiple sources and implements federated ML
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import requests
import aiohttp
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import ipaddress
import re

logger = logging.getLogger(__name__)

class ThreatIntelSource(Enum):
    """Supported threat intelligence sources"""
    MISP = "misp"
    TAXII = "taxii"
    OTX = "otx"
    VIRUSTOTAL = "virustotal"
    ABUSE_CH = "abuse_ch"
    SHODAN = "shodan"
    GREYNOISE = "greynoise"
    URLVOID = "urlvoid"
    HYBRID_ANALYSIS = "hybrid_analysis"
    INTERNAL = "internal"
    CUSTOM_FEED = "custom_feed"

class ThreatType(Enum):
    """Types of threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    APT = "apt"
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    CRYPTOMINING = "cryptomining"
    DATA_EXFILTRATION = "data_exfiltration"
    DDOS = "ddos"
    VULNERABLE_SERVICE = "vulnerable_service"
    MALICIOUS_DOMAIN = "malicious_domain"
    MALICIOUS_IP = "malicious_ip"
    MALICIOUS_URL = "malicious_url"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"

class ConfidenceLevel(Enum):
    """Confidence levels for threat intelligence"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    NETWORK_SIGNATURE = "network_signature"

@dataclass
class ThreatIndicator:
    """Individual threat indicator/IOC"""
    id: str
    ioc_type: IOCType
    value: str
    threat_types: List[ThreatType]
    confidence: ConfidenceLevel
    source: ThreatIntelSource
    first_seen: datetime
    last_seen: datetime
    ttl: Optional[datetime] = None  # Time to live
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    related_indicators: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical

@dataclass
class ThreatCampaign:
    """Threat campaign information"""
    id: str
    name: str
    description: str
    threat_actor: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    indicators: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)  # Tactics, Techniques, Procedures
    targets: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ThreatIntelFeed:
    """Threat intelligence feed configuration"""
    id: str
    source: ThreatIntelSource
    name: str
    url: str
    api_key: Optional[str] = None
    format: str = "json"  # json, xml, csv, stix
    update_frequency: int = 3600  # seconds
    enabled: bool = True
    last_update: Optional[datetime] = None
    indicators_count: int = 0
    authentication: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

class ThreatIntelConnector(ABC):
    """Abstract base class for threat intelligence connectors"""
    
    def __init__(self, feed_config: ThreatIntelFeed):
        self.config = feed_config
        
    @abstractmethod
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """Fetch threat indicators from the source"""
        pass
    
    @abstractmethod
    async def enrich_indicator(self, indicator: str, ioc_type: IOCType) -> Optional[ThreatIndicator]:
        """Enrich a single indicator with threat intelligence"""
        pass

class MISPConnector(ThreatIntelConnector):
    """MISP threat intelligence connector"""
    
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """Fetch indicators from MISP"""
        indicators = []
        
        try:
            headers = {
                "Authorization": self.config.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            # MISP API endpoint for attributes
            url = f"{self.config.url}/attributes/restSearch"
            
            # Search parameters
            search_params = {
                "returnFormat": "json",
                "type": ["ip-dst", "ip-src", "hostname", "domain", "url", "md5", "sha1", "sha256"],
                "to_ids": True,  # Only indicators marked for detection
                "published": True,
                "timestamp": (datetime.utcnow() - timedelta(days=30)).timestamp()  # Last 30 days
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=search_params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for attribute in data.get("response", {}).get("Attribute", []):
                            indicator = self._parse_misp_attribute(attribute)
                            if indicator:
                                indicators.append(indicator)
                    else:
                        logger.error(f"MISP API error: {response.status}")
            
            logger.info(f"Fetched {len(indicators)} indicators from MISP")
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching MISP indicators: {e}")
            return []
    
    async def enrich_indicator(self, indicator: str, ioc_type: IOCType) -> Optional[ThreatIndicator]:
        """Enrich indicator with MISP data"""
        try:
            headers = {
                "Authorization": self.config.api_key,
                "Accept": "application/json"
            }
            
            # Search for specific indicator
            url = f"{self.config.url}/attributes/restSearch"
            search_params = {
                "returnFormat": "json",
                "value": indicator,
                "to_ids": True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=search_params) as response:
                    if response.status == 200:
                        data = await response.json()
                        attributes = data.get("response", {}).get("Attribute", [])
                        
                        if attributes:
                            return self._parse_misp_attribute(attributes[0])
            
            return None
            
        except Exception as e:
            logger.error(f"Error enriching indicator with MISP: {e}")
            return None
    
    def _parse_misp_attribute(self, attribute: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Parse MISP attribute to ThreatIndicator"""
        try:
            ioc_type_mapping = {
                "ip-dst": IOCType.IP_ADDRESS,
                "ip-src": IOCType.IP_ADDRESS,
                "hostname": IOCType.DOMAIN,
                "domain": IOCType.DOMAIN,
                "url": IOCType.URL,
                "md5": IOCType.FILE_HASH,
                "sha1": IOCType.FILE_HASH,
                "sha256": IOCType.FILE_HASH,
                "email": IOCType.EMAIL
            }
            
            misp_type = attribute.get("type")
            ioc_type = ioc_type_mapping.get(misp_type)
            
            if not ioc_type:
                return None
            
            # Determine threat types from tags
            threat_types = []
            tags = []
            for tag in attribute.get("Tag", []):
                tag_name = tag.get("name", "").lower()
                tags.append(tag_name)
                
                if "malware" in tag_name:
                    threat_types.append(ThreatType.MALWARE)
                elif "phishing" in tag_name:
                    threat_types.append(ThreatType.PHISHING)
                elif "apt" in tag_name:
                    threat_types.append(ThreatType.APT)
                elif "botnet" in tag_name:
                    threat_types.append(ThreatType.BOTNET)
            
            if not threat_types:
                threat_types = [ThreatType.SUSPICIOUS_BEHAVIOR]
            
            return ThreatIndicator(
                id=f"misp_{attribute.get('uuid')}",
                ioc_type=ioc_type,
                value=attribute.get("value"),
                threat_types=threat_types,
                confidence=ConfidenceLevel.HIGH,  # MISP is generally high confidence
                source=ThreatIntelSource.MISP,
                first_seen=datetime.fromtimestamp(int(attribute.get("timestamp", 0))),
                last_seen=datetime.utcnow(),
                metadata={
                    "event_id": attribute.get("event_id"),
                    "category": attribute.get("category"),
                    "comment": attribute.get("comment", ""),
                    "distribution": attribute.get("distribution")
                },
                tags=tags
            )
            
        except Exception as e:
            logger.error(f"Error parsing MISP attribute: {e}")
            return None

class OTXConnector(ThreatIntelConnector):
    """AlienVault OTX connector"""
    
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """Fetch indicators from OTX"""
        indicators = []
        
        try:
            headers = {
                "X-OTX-API-KEY": self.config.api_key,
                "Accept": "application/json"
            }
            
            # Get recent pulses
            url = f"{self.config.url}/api/v1/pulses/subscribed"
            params = {
                "modified_since": (datetime.utcnow() - timedelta(days=7)).isoformat(),
                "limit": 100
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for pulse in data.get("results", []):
                            pulse_indicators = self._parse_otx_pulse(pulse)
                            indicators.extend(pulse_indicators)
                    else:
                        logger.error(f"OTX API error: {response.status}")
            
            logger.info(f"Fetched {len(indicators)} indicators from OTX")
            return indicators
            
        except Exception as e:
            logger.error(f"Error fetching OTX indicators: {e}")
            return []
    
    async def enrich_indicator(self, indicator: str, ioc_type: IOCType) -> Optional[ThreatIndicator]:
        """Enrich indicator with OTX data"""
        try:
            headers = {
                "X-OTX-API-KEY": self.config.api_key,
                "Accept": "application/json"
            }
            
            # Map IOC type to OTX endpoint
            endpoint_mapping = {
                IOCType.IP_ADDRESS: "IPv4",
                IOCType.DOMAIN: "hostname",
                IOCType.URL: "url",
                IOCType.FILE_HASH: "file"
            }
            
            endpoint = endpoint_mapping.get(ioc_type)
            if not endpoint:
                return None
            
            url = f"{self.config.url}/api/v1/indicators/{endpoint}/{indicator}/general"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_otx_indicator(data, indicator, ioc_type)
            
            return None
            
        except Exception as e:
            logger.error(f"Error enriching indicator with OTX: {e}")
            return None
    
    def _parse_otx_pulse(self, pulse: Dict[str, Any]) -> List[ThreatIndicator]:
        """Parse OTX pulse to threat indicators"""
        indicators = []
        
        try:
            pulse_tags = pulse.get("tags", [])
            
            for indicator_data in pulse.get("indicators", []):
                indicator = self._parse_otx_indicator_data(indicator_data, pulse_tags)
                if indicator:
                    indicators.append(indicator)
            
        except Exception as e:
            logger.error(f"Error parsing OTX pulse: {e}")
        
        return indicators
    
    def _parse_otx_indicator_data(self, indicator_data: Dict[str, Any], pulse_tags: List[str]) -> Optional[ThreatIndicator]:
        """Parse individual OTX indicator"""
        try:
            type_mapping = {
                "IPv4": IOCType.IP_ADDRESS,
                "IPv6": IOCType.IP_ADDRESS,
                "hostname": IOCType.DOMAIN,
                "domain": IOCType.DOMAIN,
                "URL": IOCType.URL,
                "FileHash-MD5": IOCType.FILE_HASH,
                "FileHash-SHA1": IOCType.FILE_HASH,
                "FileHash-SHA256": IOCType.FILE_HASH
            }
            
            otx_type = indicator_data.get("type")
            ioc_type = type_mapping.get(otx_type)
            
            if not ioc_type:
                return None
            
            # Determine threat types from tags
            threat_types = []
            for tag in pulse_tags:
                tag_lower = tag.lower()
                if "malware" in tag_lower:
                    threat_types.append(ThreatType.MALWARE)
                elif "phishing" in tag_lower:
                    threat_types.append(ThreatType.PHISHING)
                elif "apt" in tag_lower:
                    threat_types.append(ThreatType.APT)
            
            if not threat_types:
                threat_types = [ThreatType.SUSPICIOUS_BEHAVIOR]
            
            return ThreatIndicator(
                id=f"otx_{hashlib.md5(indicator_data.get('indicator', '').encode()).hexdigest()}",
                ioc_type=ioc_type,
                value=indicator_data.get("indicator"),
                threat_types=threat_types,
                confidence=ConfidenceLevel.MEDIUM,
                source=ThreatIntelSource.OTX,
                first_seen=datetime.fromisoformat(indicator_data.get("created", datetime.utcnow().isoformat()).replace("Z", "+00:00")),
                last_seen=datetime.utcnow(),
                metadata={
                    "description": indicator_data.get("description", ""),
                    "is_active": indicator_data.get("is_active", True)
                },
                tags=pulse_tags
            )
            
        except Exception as e:
            logger.error(f"Error parsing OTX indicator: {e}")
            return None
    
    def _parse_otx_indicator(self, data: Dict[str, Any], indicator: str, ioc_type: IOCType) -> Optional[ThreatIndicator]:
        """Parse OTX indicator enrichment response"""
        try:
            # Extract reputation and analysis info
            reputation = data.get("reputation", 0)
            
            # Determine confidence based on reputation
            if reputation == 0:
                confidence = ConfidenceLevel.LOW
            elif reputation <= 2:
                confidence = ConfidenceLevel.MEDIUM
            else:
                confidence = ConfidenceLevel.HIGH
            
            return ThreatIndicator(
                id=f"otx_{hashlib.md5(indicator.encode()).hexdigest()}",
                ioc_type=ioc_type,
                value=indicator,
                threat_types=[ThreatType.SUSPICIOUS_BEHAVIOR],
                confidence=confidence,
                source=ThreatIntelSource.OTX,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                metadata={
                    "reputation": reputation,
                    "whois": data.get("whois"),
                    "pulse_info": data.get("pulse_info", {})
                }
            )
            
        except Exception as e:
            logger.error(f"Error parsing OTX enrichment: {e}")
            return None

class VirusTotalConnector(ThreatIntelConnector):
    """VirusTotal connector"""
    
    async def enrich_indicator(self, indicator: str, ioc_type: IOCType) -> Optional[ThreatIndicator]:
        """Enrich indicator with VirusTotal data"""
        try:
            headers = {
                "x-apikey": self.config.api_key,
                "Accept": "application/json"
            }
            
            # Map IOC type to VT endpoint
            if ioc_type == IOCType.IP_ADDRESS:
                url = f"{self.config.url}/api/v3/ip_addresses/{indicator}"
            elif ioc_type == IOCType.DOMAIN:
                url = f"{self.config.url}/api/v3/domains/{indicator}"
            elif ioc_type == IOCType.URL:
                url_id = hashlib.sha256(indicator.encode()).hexdigest()
                url = f"{self.config.url}/api/v3/urls/{url_id}"
            elif ioc_type == IOCType.FILE_HASH:
                url = f"{self.config.url}/api/v3/files/{indicator}"
            else:
                return None
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_vt_response(data, indicator, ioc_type)
                    elif response.status == 404:
                        # Indicator not found in VT
                        return None
                    else:
                        logger.error(f"VirusTotal API error: {response.status}")
            
            return None
            
        except Exception as e:
            logger.error(f"Error enriching indicator with VirusTotal: {e}")
            return None
    
    async def fetch_indicators(self) -> List[ThreatIndicator]:
        """VirusTotal doesn't provide bulk indicator feeds, only enrichment"""
        return []
    
    def _parse_vt_response(self, data: Dict[str, Any], indicator: str, ioc_type: IOCType) -> Optional[ThreatIndicator]:
        """Parse VirusTotal response"""
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Get analysis stats
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            total = sum(last_analysis_stats.values())
            
            # Determine confidence and threat types
            if malicious > 0:
                confidence = ConfidenceLevel.HIGH
                threat_types = [ThreatType.MALWARE]
                severity = "high" if malicious > 5 else "medium"
            elif suspicious > 0:
                confidence = ConfidenceLevel.MEDIUM
                threat_types = [ThreatType.SUSPICIOUS_BEHAVIOR]
                severity = "medium"
            else:
                confidence = ConfidenceLevel.LOW
                threat_types = [ThreatType.SUSPICIOUS_BEHAVIOR]
                severity = "low"
            
            # Get additional metadata
            metadata = {
                "last_analysis_stats": last_analysis_stats,
                "reputation": attributes.get("reputation", 0),
                "harmless": last_analysis_stats.get("harmless", 0),
                "total_votes": {
                    "harmless": attributes.get("total_votes", {}).get("harmless", 0),
                    "malicious": attributes.get("total_votes", {}).get("malicious", 0)
                }
            }
            
            # Add type-specific metadata
            if ioc_type == IOCType.DOMAIN:
                metadata.update({
                    "categories": attributes.get("categories", {}),
                    "creation_date": attributes.get("creation_date"),
                    "whois": attributes.get("whois")
                })
            elif ioc_type == IOCType.IP_ADDRESS:
                metadata.update({
                    "country": attributes.get("country"),
                    "asn": attributes.get("asn"),
                    "as_owner": attributes.get("as_owner")
                })
            
            return ThreatIndicator(
                id=f"vt_{hashlib.md5(indicator.encode()).hexdigest()}",
                ioc_type=ioc_type,
                value=indicator,
                threat_types=threat_types,
                confidence=confidence,
                source=ThreatIntelSource.VIRUSTOTAL,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                metadata=metadata,
                severity=severity
            )
            
        except Exception as e:
            logger.error(f"Error parsing VirusTotal response: {e}")
            return None

class FederatedThreatIntelligence:
    """
    Federated threat intelligence aggregator
    Manages multiple threat intelligence sources and implements federated learning
    """
    
    def __init__(self, storage_backend: Optional[Any] = None):
        self.feeds: Dict[str, ThreatIntelFeed] = {}
        self.connectors: Dict[str, ThreatIntelConnector] = {}
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.campaigns: Dict[str, ThreatCampaign] = {}
        self.storage = storage_backend
        
        # Enrichment cache to avoid duplicate API calls
        self.enrichment_cache: Dict[str, ThreatIndicator] = {}
        self.cache_ttl = timedelta(hours=24)
        
        # Statistics
        self.stats = {
            "total_indicators": 0,
            "indicators_by_source": {},
            "indicators_by_type": {},
            "last_update": None,
            "enrichment_requests": 0,
            "cache_hits": 0
        }
    
    def register_feed(self, feed: ThreatIntelFeed):
        """Register a threat intelligence feed"""
        self.feeds[feed.id] = feed
        
        # Create appropriate connector
        if feed.source == ThreatIntelSource.MISP:
            self.connectors[feed.id] = MISPConnector(feed)
        elif feed.source == ThreatIntelSource.OTX:
            self.connectors[feed.id] = OTXConnector(feed)
        elif feed.source == ThreatIntelSource.VIRUSTOTAL:
            self.connectors[feed.id] = VirusTotalConnector(feed)
        
        logger.info(f"Registered threat intelligence feed: {feed.name}")
    
    async def update_all_feeds(self):
        """Update indicators from all enabled feeds"""
        logger.info("Starting threat intelligence feed update")
        
        update_tasks = []
        for feed_id, feed in self.feeds.items():
            if feed.enabled:
                task = asyncio.create_task(self._update_feed(feed_id))
                update_tasks.append(task)
        
        if update_tasks:
            results = await asyncio.gather(*update_tasks, return_exceptions=True)
            
            # Process results
            total_new_indicators = 0
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Feed update failed: {result}")
                else:
                    total_new_indicators += result
            
            logger.info(f"Feed update completed: {total_new_indicators} new indicators")
            self._update_statistics()
        
        return total_new_indicators
    
    async def _update_feed(self, feed_id: str) -> int:
        """Update indicators from a specific feed"""
        feed = self.feeds[feed_id]
        connector = self.connectors.get(feed_id)
        
        if not connector:
            logger.error(f"No connector for feed: {feed_id}")
            return 0
        
        try:
            logger.info(f"Updating feed: {feed.name}")
            indicators = await connector.fetch_indicators()
            
            new_indicators = 0
            for indicator in indicators:
                if self._store_indicator(indicator):
                    new_indicators += 1
            
            # Update feed metadata
            feed.last_update = datetime.utcnow()
            feed.indicators_count = len([i for i in self.indicators.values() if i.source == feed.source])
            
            logger.info(f"Feed {feed.name} updated: {new_indicators} new indicators")
            return new_indicators
            
        except Exception as e:
            logger.error(f"Error updating feed {feed.name}: {e}")
            return 0
    
    def _store_indicator(self, indicator: ThreatIndicator) -> bool:
        """Store indicator, return True if new"""
        # Check if indicator already exists
        existing_key = self._get_indicator_key(indicator.value, indicator.ioc_type)
        
        if existing_key in self.indicators:
            # Update existing indicator
            existing = self.indicators[existing_key]
            existing.last_seen = datetime.utcnow()
            
            # Merge threat types
            for threat_type in indicator.threat_types:
                if threat_type not in existing.threat_types:
                    existing.threat_types.append(threat_type)
            
            # Merge tags
            for tag in indicator.tags:
                if tag not in existing.tags:
                    existing.tags.append(tag)
            
            # Update confidence to higher value
            if indicator.confidence.value == "confirmed" or (
                indicator.confidence.value == "high" and existing.confidence.value != "confirmed"
            ):
                existing.confidence = indicator.confidence
            
            return False
        else:
            # Store new indicator
            self.indicators[existing_key] = indicator
            
            # Store in persistent storage if available
            if self.storage:
                self.storage.store_indicator(indicator)
            
            return True
    
    def _get_indicator_key(self, value: str, ioc_type: IOCType) -> str:
        """Generate unique key for indicator"""
        return f"{ioc_type.value}:{value.lower()}"
    
    async def enrich_indicator(self, indicator: str, ioc_type: IOCType, 
                              sources: List[ThreatIntelSource] = None) -> Optional[ThreatIndicator]:
        """Enrich an indicator with threat intelligence from multiple sources"""
        self.stats["enrichment_requests"] += 1
        
        # Check cache first
        cache_key = self._get_indicator_key(indicator, ioc_type)
        if cache_key in self.enrichment_cache:
            cached_indicator = self.enrichment_cache[cache_key]
            if datetime.utcnow() - cached_indicator.last_seen < self.cache_ttl:
                self.stats["cache_hits"] += 1
                return cached_indicator
        
        # Check local storage
        if cache_key in self.indicators:
            local_indicator = self.indicators[cache_key]
            if datetime.utcnow() - local_indicator.last_seen < self.cache_ttl:
                return local_indicator
        
        # Enrich from external sources
        if not sources:
            sources = [ThreatIntelSource.VIRUSTOTAL, ThreatIntelSource.OTX]
        
        enrichment_tasks = []
        for source in sources:
            # Find connector for source
            connector = None
            for feed_id, feed in self.feeds.items():
                if feed.source == source and feed.enabled:
                    connector = self.connectors.get(feed_id)
                    break
            
            if connector:
                task = asyncio.create_task(connector.enrich_indicator(indicator, ioc_type))
                enrichment_tasks.append(task)
        
        if enrichment_tasks:
            results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)
            
            # Combine results from multiple sources
            enriched_indicator = None
            for result in results:
                if isinstance(result, ThreatIndicator):
                    if enriched_indicator is None:
                        enriched_indicator = result
                    else:
                        # Merge information
                        enriched_indicator = self._merge_indicators(enriched_indicator, result)
            
            if enriched_indicator:
                # Cache the result
                self.enrichment_cache[cache_key] = enriched_indicator
                
                # Store in main indicators
                self._store_indicator(enriched_indicator)
                
                return enriched_indicator
        
        return None
    
    def _merge_indicators(self, indicator1: ThreatIndicator, indicator2: ThreatIndicator) -> ThreatIndicator:
        """Merge two indicators from different sources"""
        # Take the higher confidence
        confidence = indicator1.confidence
        if indicator2.confidence.value == "confirmed" or (
            indicator2.confidence.value == "high" and confidence.value not in ["confirmed", "high"]
        ):
            confidence = indicator2.confidence
        
        # Merge threat types
        threat_types = list(set(indicator1.threat_types + indicator2.threat_types))
        
        # Merge tags
        tags = list(set(indicator1.tags + indicator2.tags))
        
        # Combine metadata
        metadata = {**indicator1.metadata, **indicator2.metadata}
        metadata["sources"] = [indicator1.source.value, indicator2.source.value]
        
        # Use earlier first_seen date
        first_seen = min(indicator1.first_seen, indicator2.first_seen)
        
        return ThreatIndicator(
            id=f"merged_{hashlib.md5(indicator1.value.encode()).hexdigest()}",
            ioc_type=indicator1.ioc_type,
            value=indicator1.value,
            threat_types=threat_types,
            confidence=confidence,
            source=ThreatIntelSource.INTERNAL,  # Mark as merged/internal
            first_seen=first_seen,
            last_seen=datetime.utcnow(),
            metadata=metadata,
            tags=tags,
            severity=max(indicator1.severity, indicator2.severity, key=lambda x: ["low", "medium", "high", "critical"].index(x))
        )
    
    def search_indicators(self, query: str = None, ioc_type: IOCType = None, 
                         threat_types: List[ThreatType] = None,
                         confidence_min: ConfidenceLevel = None,
                         source: ThreatIntelSource = None,
                         tags: List[str] = None,
                         limit: int = 100) -> List[ThreatIndicator]:
        """Search indicators with various filters"""
        results = []
        
        for indicator in self.indicators.values():
            # Apply filters
            if query and query.lower() not in indicator.value.lower():
                continue
            
            if ioc_type and indicator.ioc_type != ioc_type:
                continue
            
            if threat_types and not any(tt in indicator.threat_types for tt in threat_types):
                continue
            
            if confidence_min:
                confidence_order = ["low", "medium", "high", "confirmed"]
                if confidence_order.index(indicator.confidence.value) < confidence_order.index(confidence_min.value):
                    continue
            
            if source and indicator.source != source:
                continue
            
            if tags and not any(tag in indicator.tags for tag in tags):
                continue
            
            results.append(indicator)
            
            if len(results) >= limit:
                break
        
        return results
    
    def get_indicator_by_value(self, value: str, ioc_type: IOCType) -> Optional[ThreatIndicator]:
        """Get specific indicator by value and type"""
        key = self._get_indicator_key(value, ioc_type)
        return self.indicators.get(key)
    
    def create_campaign(self, campaign: ThreatCampaign):
        """Create or update a threat campaign"""
        self.campaigns[campaign.id] = campaign
        logger.info(f"Created/updated threat campaign: {campaign.name}")
    
    def associate_indicator_to_campaign(self, indicator_id: str, campaign_id: str):
        """Associate an indicator with a campaign"""
        campaign = self.campaigns.get(campaign_id)
        if campaign and indicator_id not in campaign.indicators:
            campaign.indicators.append(indicator_id)
            logger.info(f"Associated indicator {indicator_id} with campaign {campaign_id}")
    
    def get_related_indicators(self, indicator_value: str, ioc_type: IOCType) -> List[ThreatIndicator]:
        """Get indicators related to the given indicator"""
        base_indicator = self.get_indicator_by_value(indicator_value, ioc_type)
        if not base_indicator:
            return []
        
        related = []
        
        # Find indicators from same campaigns
        for campaign in self.campaigns.values():
            if any(ind.value == indicator_value for ind in self.indicators.values() 
                   if ind.id in campaign.indicators):
                for indicator_id in campaign.indicators:
                    indicator = next((ind for ind in self.indicators.values() if ind.id == indicator_id), None)
                    if indicator and indicator.value != indicator_value:
                        related.append(indicator)
        
        # Find indicators with shared tags
        for indicator in self.indicators.values():
            if (indicator.value != indicator_value and 
                any(tag in base_indicator.tags for tag in indicator.tags)):
                related.append(indicator)
        
        return list(set(related))
    
    def _update_statistics(self):
        """Update internal statistics"""
        self.stats["total_indicators"] = len(self.indicators)
        self.stats["last_update"] = datetime.utcnow()
        
        # Count by source
        source_counts = {}
        type_counts = {}
        
        for indicator in self.indicators.values():
            source = indicator.source.value
            source_counts[source] = source_counts.get(source, 0) + 1
            
            ioc_type = indicator.ioc_type.value
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
        
        self.stats["indicators_by_source"] = source_counts
        self.stats["indicators_by_type"] = type_counts
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        return self.stats.copy()
    
    def cleanup_expired_indicators(self):
        """Remove expired indicators based on TTL"""
        expired_keys = []
        current_time = datetime.utcnow()
        
        for key, indicator in self.indicators.items():
            if indicator.ttl and current_time > indicator.ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.indicators[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired indicators")
        
        # Also cleanup enrichment cache
        expired_cache_keys = []
        for key, indicator in self.enrichment_cache.items():
            if current_time - indicator.last_seen > self.cache_ttl:
                expired_cache_keys.append(key)
        
        for key in expired_cache_keys:
            del self.enrichment_cache[key]


# Utility functions
def normalize_indicator(value: str, ioc_type: IOCType) -> str:
    """Normalize indicator value based on type"""
    if ioc_type == IOCType.DOMAIN:
        return value.lower().strip()
    elif ioc_type == IOCType.URL:
        return value.strip()
    elif ioc_type == IOCType.IP_ADDRESS:
        try:
            # Validate and normalize IP address
            ip = ipaddress.ip_address(value.strip())
            return str(ip)
        except ValueError:
            return value.strip()
    elif ioc_type == IOCType.FILE_HASH:
        return value.lower().strip()
    elif ioc_type == IOCType.EMAIL:
        return value.lower().strip()
    else:
        return value.strip()

def is_valid_indicator(value: str, ioc_type: IOCType) -> bool:
    """Validate indicator format"""
    try:
        if ioc_type == IOCType.IP_ADDRESS:
            ipaddress.ip_address(value)
            return True
        elif ioc_type == IOCType.DOMAIN:
            # Basic domain validation
            domain_pattern = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            )
            return bool(domain_pattern.match(value))
        elif ioc_type == IOCType.URL:
            parsed = urlparse(value)
            return bool(parsed.scheme and parsed.netloc)
        elif ioc_type == IOCType.FILE_HASH:
            # Check for MD5, SHA1, SHA256 format
            if len(value) == 32:  # MD5
                return bool(re.match(r'^[a-fA-F0-9]{32}$', value))
            elif len(value) == 40:  # SHA1
                return bool(re.match(r'^[a-fA-F0-9]{40}$', value))
            elif len(value) == 64:  # SHA256
                return bool(re.match(r'^[a-fA-F0-9]{64}$', value))
            return False
        elif ioc_type == IOCType.EMAIL:
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            return bool(email_pattern.match(value))
        else:
            return True  # For other types, assume valid
    except Exception:
        return False

async def bulk_enrich_indicators(threat_intel: FederatedThreatIntelligence,
                                 indicators: List[Dict[str, Any]],
                                 max_concurrent: int = 10) -> List[Optional[ThreatIndicator]]:
    """Bulk enrich multiple indicators with concurrency control"""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def enrich_single(indicator_data):
        async with semaphore:
            return await threat_intel.enrich_indicator(
                indicator_data["value"],
                IOCType(indicator_data["type"]),
                indicator_data.get("sources")
            )
    
    tasks = [enrich_single(ind) for ind in indicators]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Convert exceptions to None
    return [result if not isinstance(result, Exception) else None for result in results]
