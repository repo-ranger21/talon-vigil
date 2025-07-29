"""
SOAR (Security Orchestration, Automation, and Response) Integration for TalonVigil
Supports Cortex XSOAR, Splunk Phantom, and other SOAR platforms
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import requests
import aiohttp
from urllib.parse import urljoin
import hashlib
import hmac
import base64

logger = logging.getLogger(__name__)

class SOARPlatform(Enum):
    """Supported SOAR platforms"""
    CORTEX_XSOAR = "cortex_xsoar"
    SPLUNK_PHANTOM = "splunk_phantom"
    MICROSOFT_SENTINEL = "microsoft_sentinel"
    IBM_RESILIENT = "ibm_resilient"
    CUSTOM = "custom"

class IncidentSeverity(Enum):
    """Incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(Enum):
    """Incident status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"

@dataclass
class SOARIncident:
    """SOAR incident data structure"""
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.NEW
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    assigned_to: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    playbook_id: Optional[str] = None
    custom_fields: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PlaybookExecution:
    """Playbook execution tracking"""
    execution_id: str
    playbook_id: str
    incident_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    steps_completed: int = 0
    total_steps: int = 0
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

class SOARConnector(ABC):
    """Abstract base class for SOAR platform connectors"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config.get('base_url')
        self.api_key = config.get('api_key')
        self.timeout = config.get('timeout', 30)
        
    @abstractmethod
    async def create_incident(self, incident: SOARIncident) -> Dict[str, Any]:
        """Create an incident in the SOAR platform"""
        pass
    
    @abstractmethod
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing incident"""
        pass
    
    @abstractmethod
    async def get_incident(self, incident_id: str) -> Optional[SOARIncident]:
        """Retrieve incident details"""
        pass
    
    @abstractmethod
    async def execute_playbook(self, playbook_id: str, incident_id: str, 
                              parameters: Dict[str, Any] = None) -> PlaybookExecution:
        """Execute a playbook against an incident"""
        pass
    
    @abstractmethod
    async def get_playbook_status(self, execution_id: str) -> PlaybookExecution:
        """Get playbook execution status"""
        pass

class CortexXSOARConnector(SOARConnector):
    """Cortex XSOAR connector implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.server_url = config.get('server_url')
        self.api_key = config.get('api_key')
        self.api_key_id = config.get('api_key_id')
        
    async def create_incident(self, incident: SOARIncident) -> Dict[str, Any]:
        """Create incident in Cortex XSOAR"""
        try:
            headers = self._get_auth_headers()
            
            incident_data = {
                "name": incident.title,
                "details": incident.description,
                "severity": self._map_severity(incident.severity),
                "type": "TalonVigil Alert",
                "labels": [{"type": "tag", "value": tag} for tag in incident.tags],
                "customFields": incident.custom_fields
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.post(
                    f"{self.server_url}/incident",
                    headers=headers,
                    json=incident_data
                ) as response:
                    if response.status == 201:
                        result = await response.json()
                        logger.info(f"Created XSOAR incident: {result.get('id')}")
                        return result
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to create XSOAR incident: {error_text}")
                        raise Exception(f"XSOAR API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error creating XSOAR incident: {e}")
            raise
    
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update XSOAR incident"""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.post(
                    f"{self.server_url}/incident/{incident_id}",
                    headers=headers,
                    json=updates
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"Updated XSOAR incident: {incident_id}")
                        return result
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to update XSOAR incident: {error_text}")
                        raise Exception(f"XSOAR API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error updating XSOAR incident: {e}")
            raise
    
    async def get_incident(self, incident_id: str) -> Optional[SOARIncident]:
        """Get XSOAR incident details"""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.get(
                    f"{self.server_url}/incident/{incident_id}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_xsoar_incident(data)
                    elif response.status == 404:
                        return None
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to get XSOAR incident: {error_text}")
                        raise Exception(f"XSOAR API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error getting XSOAR incident: {e}")
            raise
    
    async def execute_playbook(self, playbook_id: str, incident_id: str, 
                              parameters: Dict[str, Any] = None) -> PlaybookExecution:
        """Execute XSOAR playbook"""
        try:
            headers = self._get_auth_headers()
            
            playbook_data = {
                "playbookId": playbook_id,
                "incidentId": incident_id,
                "inputs": parameters or {}
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.post(
                    f"{self.server_url}/playbook/execute",
                    headers=headers,
                    json=playbook_data
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        execution_id = result.get('executionId')
                        
                        return PlaybookExecution(
                            execution_id=execution_id,
                            playbook_id=playbook_id,
                            incident_id=incident_id,
                            status="running",
                            started_at=datetime.utcnow()
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to execute XSOAR playbook: {error_text}")
                        raise Exception(f"XSOAR API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error executing XSOAR playbook: {e}")
            raise
    
    async def get_playbook_status(self, execution_id: str) -> PlaybookExecution:
        """Get XSOAR playbook execution status"""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.get(
                    f"{self.server_url}/playbook/execution/{execution_id}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_xsoar_execution(data)
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to get XSOAR playbook status: {error_text}")
                        raise Exception(f"XSOAR API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error getting XSOAR playbook status: {e}")
            raise
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Generate XSOAR authentication headers"""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def _map_severity(self, severity: IncidentSeverity) -> int:
        """Map TalonVigil severity to XSOAR severity"""
        mapping = {
            IncidentSeverity.LOW: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.HIGH: 3,
            IncidentSeverity.CRITICAL: 4
        }
        return mapping.get(severity, 2)
    
    def _parse_xsoar_incident(self, data: Dict[str, Any]) -> SOARIncident:
        """Parse XSOAR incident data to SOARIncident"""
        return SOARIncident(
            id=str(data.get('id')),
            title=data.get('name', ''),
            description=data.get('details', ''),
            severity=self._parse_severity(data.get('severity', 2)),
            status=self._parse_status(data.get('status')),
            created_at=datetime.fromisoformat(data.get('created', '').replace('Z', '+00:00')),
            updated_at=datetime.fromisoformat(data.get('modified', '').replace('Z', '+00:00')),
            assigned_to=data.get('owner'),
            tags=[label.get('value') for label in data.get('labels', [])],
            custom_fields=data.get('customFields', {})
        )
    
    def _parse_execution(self, data: Dict[str, Any]) -> PlaybookExecution:
        """Parse XSOAR execution data"""
        return PlaybookExecution(
            execution_id=data.get('executionId'),
            playbook_id=data.get('playbookId'),
            incident_id=data.get('incidentId'),
            status=data.get('status'),
            started_at=datetime.fromisoformat(data.get('startTime', '').replace('Z', '+00:00')),
            completed_at=datetime.fromisoformat(data.get('endTime', '').replace('Z', '+00:00')) if data.get('endTime') else None,
            results=data.get('outputs', {})
        )
    
    def _parse_severity(self, severity: int) -> IncidentSeverity:
        """Parse XSOAR severity to TalonVigil severity"""
        mapping = {1: IncidentSeverity.LOW, 2: IncidentSeverity.MEDIUM, 
                  3: IncidentSeverity.HIGH, 4: IncidentSeverity.CRITICAL}
        return mapping.get(severity, IncidentSeverity.MEDIUM)
    
    def _parse_status(self, status: str) -> IncidentStatus:
        """Parse XSOAR status to TalonVigil status"""
        mapping = {
            "New": IncidentStatus.NEW,
            "Under Investigation": IncidentStatus.INVESTIGATING,
            "Closed": IncidentStatus.CLOSED
        }
        return mapping.get(status, IncidentStatus.NEW)

class SplunkPhantomConnector(SOARConnector):
    """Splunk Phantom connector implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.auth_token = config.get('auth_token')
        
    async def create_incident(self, incident: SOARIncident) -> Dict[str, Any]:
        """Create incident in Splunk Phantom"""
        try:
            headers = self._get_auth_headers()
            
            container_data = {
                "name": incident.title,
                "description": incident.description,
                "severity": incident.severity.value,
                "status": incident.status.value,
                "label": "TalonVigil",
                "tags": incident.tags,
                "custom_fields": incident.custom_fields
            }
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.post(
                    f"{self.base_url}/rest/container",
                    headers=headers,
                    json=container_data
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"Created Phantom container: {result.get('id')}")
                        return result
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to create Phantom container: {error_text}")
                        raise Exception(f"Phantom API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error creating Phantom container: {e}")
            raise
    
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update Phantom container"""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.post(
                    f"{self.base_url}/rest/container/{incident_id}",
                    headers=headers,
                    json=updates
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"Updated Phantom container: {incident_id}")
                        return result
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to update Phantom container: {error_text}")
                        raise Exception(f"Phantom API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error updating Phantom container: {e}")
            raise
    
    async def get_incident(self, incident_id: str) -> Optional[SOARIncident]:
        """Get Phantom container details"""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.get(
                    f"{self.base_url}/rest/container/{incident_id}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_phantom_container(data)
                    elif response.status == 404:
                        return None
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to get Phantom container: {error_text}")
                        raise Exception(f"Phantom API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error getting Phantom container: {e}")
            raise
    
    async def execute_playbook(self, playbook_id: str, incident_id: str, 
                              parameters: Dict[str, Any] = None) -> PlaybookExecution:
        """Execute Phantom playbook"""
        try:
            headers = self._get_auth_headers()
            
            playbook_data = {
                "playbook_id": playbook_id,
                "container_id": incident_id,
                "scope": "all",
                "run": True
            }
            
            if parameters:
                playbook_data["inputs"] = parameters
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.post(
                    f"{self.base_url}/rest/playbook_run",
                    headers=headers,
                    json=playbook_data
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        execution_id = str(result.get('playbook_run_id'))
                        
                        return PlaybookExecution(
                            execution_id=execution_id,
                            playbook_id=playbook_id,
                            incident_id=incident_id,
                            status="running",
                            started_at=datetime.utcnow()
                        )
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to execute Phantom playbook: {error_text}")
                        raise Exception(f"Phantom API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error executing Phantom playbook: {e}")
            raise
    
    async def get_playbook_status(self, execution_id: str) -> PlaybookExecution:
        """Get Phantom playbook execution status"""
        try:
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                async with session.get(
                    f"{self.base_url}/rest/playbook_run/{execution_id}",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_phantom_execution(data)
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to get Phantom playbook status: {error_text}")
                        raise Exception(f"Phantom API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error getting Phantom playbook status: {e}")
            raise
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Generate Phantom authentication headers"""
        return {
            "ph-auth-token": self.auth_token,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def _parse_phantom_container(self, data: Dict[str, Any]) -> SOARIncident:
        """Parse Phantom container data to SOARIncident"""
        return SOARIncident(
            id=str(data.get('id')),
            title=data.get('name', ''),
            description=data.get('description', ''),
            severity=IncidentSeverity(data.get('severity', 'medium')),
            status=IncidentStatus(data.get('status', 'new')),
            created_at=datetime.fromisoformat(data.get('create_time', '').replace('Z', '+00:00')),
            updated_at=datetime.fromisoformat(data.get('update_time', '').replace('Z', '+00:00')),
            tags=data.get('tags', []),
            custom_fields=data.get('custom_fields', {})
        )
    
    def _parse_phantom_execution(self, data: Dict[str, Any]) -> PlaybookExecution:
        """Parse Phantom execution data"""
        return PlaybookExecution(
            execution_id=str(data.get('id')),
            playbook_id=str(data.get('playbook')),
            incident_id=str(data.get('container')),
            status=data.get('status'),
            started_at=datetime.fromisoformat(data.get('start_time', '').replace('Z', '+00:00')),
            completed_at=datetime.fromisoformat(data.get('end_time', '').replace('Z', '+00:00')) if data.get('end_time') else None,
            results=data.get('results', {})
        )

class SOARManager:
    """
    Central SOAR management class
    Handles multiple SOAR platforms and orchestrates incident response
    """
    
    def __init__(self):
        self.connectors: Dict[SOARPlatform, SOARConnector] = {}
        self.incident_mappings: Dict[str, Dict[SOARPlatform, str]] = {}
        self.default_platform: Optional[SOARPlatform] = None
    
    def register_connector(self, platform: SOARPlatform, connector: SOARConnector, 
                          is_default: bool = False):
        """Register a SOAR platform connector"""
        self.connectors[platform] = connector
        if is_default or not self.default_platform:
            self.default_platform = platform
        logger.info(f"Registered SOAR connector for {platform.value}")
    
    async def create_incident(self, incident: SOARIncident, 
                             platforms: List[SOARPlatform] = None) -> Dict[SOARPlatform, str]:
        """
        Create incident across specified SOAR platforms
        
        Args:
            incident: Incident to create
            platforms: List of platforms to create incident on (default: all registered)
            
        Returns:
            Dictionary mapping platform to incident ID
        """
        if not platforms:
            platforms = list(self.connectors.keys())
        
        results = {}
        tasks = []
        
        for platform in platforms:
            connector = self.connectors.get(platform)
            if connector:
                task = asyncio.create_task(
                    self._create_incident_on_platform(connector, incident, platform)
                )
                tasks.append(task)
        
        # Wait for all incident creation tasks
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(completed_tasks):
            platform = platforms[i]
            if isinstance(result, Exception):
                logger.error(f"Failed to create incident on {platform.value}: {result}")
            else:
                results[platform] = result
                # Store mapping
                if incident.id not in self.incident_mappings:
                    self.incident_mappings[incident.id] = {}
                self.incident_mappings[incident.id][platform] = result
        
        return results
    
    async def update_incident(self, incident_id: str, updates: Dict[str, Any],
                             platforms: List[SOARPlatform] = None) -> Dict[SOARPlatform, bool]:
        """Update incident across SOAR platforms"""
        if not platforms:
            platforms = list(self.connectors.keys())
        
        results = {}
        tasks = []
        
        for platform in platforms:
            connector = self.connectors.get(platform)
            platform_incident_id = self._get_platform_incident_id(incident_id, platform)
            
            if connector and platform_incident_id:
                task = asyncio.create_task(
                    self._update_incident_on_platform(connector, platform_incident_id, updates, platform)
                )
                tasks.append(task)
        
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(completed_tasks):
            platform = platforms[i]
            results[platform] = not isinstance(result, Exception)
            if isinstance(result, Exception):
                logger.error(f"Failed to update incident on {platform.value}: {result}")
        
        return results
    
    async def execute_playbook(self, playbook_id: str, incident_id: str,
                              platform: SOARPlatform = None,
                              parameters: Dict[str, Any] = None) -> PlaybookExecution:
        """Execute playbook on specified platform"""
        if not platform:
            platform = self.default_platform
        
        connector = self.connectors.get(platform)
        if not connector:
            raise ValueError(f"No connector registered for platform {platform.value}")
        
        platform_incident_id = self._get_platform_incident_id(incident_id, platform)
        if not platform_incident_id:
            raise ValueError(f"No incident mapping found for {incident_id} on {platform.value}")
        
        return await connector.execute_playbook(playbook_id, platform_incident_id, parameters)
    
    async def get_incident_status(self, incident_id: str, 
                                 platform: SOARPlatform = None) -> Optional[SOARIncident]:
        """Get incident status from specified platform"""
        if not platform:
            platform = self.default_platform
        
        connector = self.connectors.get(platform)
        if not connector:
            return None
        
        platform_incident_id = self._get_platform_incident_id(incident_id, platform)
        if not platform_incident_id:
            return None
        
        return await connector.get_incident(platform_incident_id)
    
    def get_available_platforms(self) -> List[SOARPlatform]:
        """Get list of registered SOAR platforms"""
        return list(self.connectors.keys())
    
    def _get_platform_incident_id(self, incident_id: str, platform: SOARPlatform) -> Optional[str]:
        """Get platform-specific incident ID"""
        mapping = self.incident_mappings.get(incident_id, {})
        return mapping.get(platform)
    
    async def _create_incident_on_platform(self, connector: SOARConnector, 
                                          incident: SOARIncident, 
                                          platform: SOARPlatform) -> str:
        """Create incident on specific platform"""
        try:
            result = await connector.create_incident(incident)
            incident_id = str(result.get('id') or result.get('container_id'))
            logger.info(f"Created incident {incident_id} on {platform.value}")
            return incident_id
        except Exception as e:
            logger.error(f"Failed to create incident on {platform.value}: {e}")
            raise
    
    async def _update_incident_on_platform(self, connector: SOARConnector,
                                          platform_incident_id: str,
                                          updates: Dict[str, Any],
                                          platform: SOARPlatform) -> bool:
        """Update incident on specific platform"""
        try:
            await connector.update_incident(platform_incident_id, updates)
            logger.info(f"Updated incident {platform_incident_id} on {platform.value}")
            return True
        except Exception as e:
            logger.error(f"Failed to update incident on {platform.value}: {e}")
            raise


# Factory function for creating SOAR connectors
def create_soar_connector(platform: SOARPlatform, config: Dict[str, Any]) -> SOARConnector:
    """Factory function to create SOAR connector instances"""
    if platform == SOARPlatform.CORTEX_XSOAR:
        return CortexXSOARConnector(config)
    elif platform == SOARPlatform.SPLUNK_PHANTOM:
        return SplunkPhantomConnector(config)
    else:
        raise ValueError(f"Unsupported SOAR platform: {platform}")

# Utility functions for common SOAR operations
async def escalate_incident(soar_manager: SOARManager, incident_id: str, 
                           new_severity: IncidentSeverity):
    """Escalate incident severity across all platforms"""
    updates = {"severity": new_severity.value}
    return await soar_manager.update_incident(incident_id, updates)

async def assign_incident(soar_manager: SOARManager, incident_id: str, 
                         assignee: str):
    """Assign incident to analyst across all platforms"""
    updates = {"assigned_to": assignee}
    return await soar_manager.update_incident(incident_id, updates)

async def add_incident_comment(soar_manager: SOARManager, incident_id: str, 
                              comment: str, author: str):
    """Add comment to incident across all platforms"""
    updates = {
        "comments": [{
            "comment": comment,
            "author": author,
            "timestamp": datetime.utcnow().isoformat()
        }]
    }
    return await soar_manager.update_incident(incident_id, updates)
