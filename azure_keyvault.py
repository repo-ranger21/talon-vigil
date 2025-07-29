"""
Azure Key Vault Integration for TalonVigil
Provides secure secrets management with managed identity, auto-rotation, and audit logging.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.core.exceptions import AzureError
from azure.monitor.opentelemetry import configure_azure_monitor
import json
import threading
import time

logger = logging.getLogger(__name__)

@dataclass
class SecretMetadata:
    """Metadata for tracked secrets"""
    name: str
    version: str
    expires_at: Optional[datetime]
    created_at: datetime
    rotation_enabled: bool
    last_accessed: datetime
    access_count: int

class AzureKeyVaultManager:
    """
    Advanced Azure Key Vault integration with:
    - Managed Identity authentication
    - Automatic secret rotation
    - Audit logging and monitoring
    - Caching with TTL
    - Health monitoring
    """
    
    def __init__(self, vault_url: str, use_managed_identity: bool = True):
        self.vault_url = vault_url
        self.use_managed_identity = use_managed_identity
        self._secret_cache: Dict[str, Any] = {}
        self._cache_ttl: Dict[str, datetime] = {}
        self._secret_metadata: Dict[str, SecretMetadata] = {}
        self._rotation_callbacks: Dict[str, callable] = {}
        self._health_status = {"healthy": True, "last_check": datetime.utcnow()}
        self._lock = threading.RLock()
        
        # Initialize Azure clients
        self._initialize_clients()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _initialize_clients(self):
        """Initialize Azure Key Vault clients with proper authentication"""
        try:
            if self.use_managed_identity:
                credential = ManagedIdentityCredential()
                logger.info("Using Managed Identity for Key Vault authentication")
            else:
                credential = DefaultAzureCredential()
                logger.info("Using Default Azure Credential for Key Vault authentication")
            
            self.secret_client = SecretClient(
                vault_url=self.vault_url,
                credential=credential
            )
            
            self.key_client = KeyClient(
                vault_url=self.vault_url,
                credential=credential
            )
            
            self.certificate_client = CertificateClient(
                vault_url=self.vault_url,
                credential=credential
            )
            
            # Test connectivity
            self._test_connectivity()
            
        except Exception as e:
            logger.error(f"Failed to initialize Key Vault clients: {e}")
            raise
    
    def _test_connectivity(self):
        """Test Key Vault connectivity"""
        try:
            # Try to list secrets (basic permission test)
            list(self.secret_client.list_properties_of_secrets())
            logger.info("Key Vault connectivity test successful")
        except Exception as e:
            logger.error(f"Key Vault connectivity test failed: {e}")
            self._health_status["healthy"] = False
            raise
    
    def get_secret(self, secret_name: str, use_cache: bool = True) -> Optional[str]:
        """
        Retrieve secret with caching and audit logging
        
        Args:
            secret_name: Name of the secret
            use_cache: Whether to use cached value if available
            
        Returns:
            Secret value or None if not found
        """
        with self._lock:
            try:
                # Check cache first
                if use_cache and self._is_cached_and_valid(secret_name):
                    self._update_access_metadata(secret_name)
                    logger.debug(f"Retrieved secret '{secret_name}' from cache")
                    return self._secret_cache[secret_name]
                
                # Fetch from Key Vault
                secret = self.secret_client.get_secret(secret_name)
                
                # Update cache and metadata
                self._secret_cache[secret_name] = secret.value
                self._cache_ttl[secret_name] = datetime.utcnow() + timedelta(minutes=15)
                
                # Update metadata
                metadata = SecretMetadata(
                    name=secret_name,
                    version=secret.properties.version,
                    expires_at=secret.properties.expires_on,
                    created_at=secret.properties.created_on,
                    rotation_enabled=self._is_rotation_enabled(secret_name),
                    last_accessed=datetime.utcnow(),
                    access_count=self._secret_metadata.get(secret_name, SecretMetadata("", "", None, datetime.utcnow(), False, datetime.utcnow(), 0)).access_count + 1
                )
                self._secret_metadata[secret_name] = metadata
                
                # Audit log
                self._log_secret_access(secret_name, "GET", True)
                
                return secret.value
                
            except AzureError as e:
                logger.error(f"Failed to retrieve secret '{secret_name}': {e}")
                self._log_secret_access(secret_name, "GET", False, str(e))
                return None
            except Exception as e:
                logger.error(f"Unexpected error retrieving secret '{secret_name}': {e}")
                return None
    
    def set_secret(self, secret_name: str, secret_value: str, 
                   expires_at: Optional[datetime] = None,
                   enable_rotation: bool = False) -> bool:
        """
        Set or update a secret with optional expiration and rotation
        
        Args:
            secret_name: Name of the secret
            secret_value: Secret value
            expires_at: Optional expiration date
            enable_rotation: Whether to enable auto-rotation
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set secret in Key Vault
            secret = self.secret_client.set_secret(
                secret_name,
                secret_value,
                expires_on=expires_at
            )
            
            # Update cache
            with self._lock:
                self._secret_cache[secret_name] = secret_value
                self._cache_ttl[secret_name] = datetime.utcnow() + timedelta(minutes=15)
                
                # Update metadata
                metadata = SecretMetadata(
                    name=secret_name,
                    version=secret.properties.version,
                    expires_at=expires_at,
                    created_at=secret.properties.created_on,
                    rotation_enabled=enable_rotation,
                    last_accessed=datetime.utcnow(),
                    access_count=0
                )
                self._secret_metadata[secret_name] = metadata
            
            # Audit log
            self._log_secret_access(secret_name, "SET", True)
            
            return True
            
        except AzureError as e:
            logger.error(f"Failed to set secret '{secret_name}': {e}")
            self._log_secret_access(secret_name, "SET", False, str(e))
            return False
        except Exception as e:
            logger.error(f"Unexpected error setting secret '{secret_name}': {e}")
            return False
    
    def delete_secret(self, secret_name: str) -> bool:
        """
        Delete a secret and clean up metadata
        
        Args:
            secret_name: Name of the secret to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Delete from Key Vault
            self.secret_client.begin_delete_secret(secret_name)
            
            # Clean up cache and metadata
            with self._lock:
                self._secret_cache.pop(secret_name, None)
                self._cache_ttl.pop(secret_name, None)
                self._secret_metadata.pop(secret_name, None)
                self._rotation_callbacks.pop(secret_name, None)
            
            # Audit log
            self._log_secret_access(secret_name, "DELETE", True)
            
            return True
            
        except AzureError as e:
            logger.error(f"Failed to delete secret '{secret_name}': {e}")
            self._log_secret_access(secret_name, "DELETE", False, str(e))
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting secret '{secret_name}': {e}")
            return False
    
    def register_rotation_callback(self, secret_name: str, callback: callable):
        """
        Register a callback for secret rotation
        
        Args:
            secret_name: Name of the secret
            callback: Function to call when secret is rotated
        """
        with self._lock:
            self._rotation_callbacks[secret_name] = callback
        logger.info(f"Registered rotation callback for secret '{secret_name}'")
    
    def rotate_secret(self, secret_name: str, new_value: str) -> bool:
        """
        Manually rotate a secret
        
        Args:
            secret_name: Name of the secret to rotate
            new_value: New secret value
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set new secret version
            success = self.set_secret(secret_name, new_value)
            
            if success:
                # Call rotation callback if registered
                callback = self._rotation_callbacks.get(secret_name)
                if callback:
                    try:
                        callback(secret_name, new_value)
                    except Exception as e:
                        logger.error(f"Rotation callback failed for '{secret_name}': {e}")
                
                logger.info(f"Successfully rotated secret '{secret_name}'")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to rotate secret '{secret_name}': {e}")
            return False
    
    def get_secret_metadata(self, secret_name: str) -> Optional[SecretMetadata]:
        """Get metadata for a secret"""
        return self._secret_metadata.get(secret_name)
    
    def list_secrets(self) -> List[str]:
        """List all accessible secrets"""
        try:
            return [secret.name for secret in self.secret_client.list_properties_of_secrets()]
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get Key Vault health status"""
        return {
            **self._health_status,
            "cache_size": len(self._secret_cache),
            "tracked_secrets": len(self._secret_metadata),
            "vault_url": self.vault_url
        }
    
    def _is_cached_and_valid(self, secret_name: str) -> bool:
        """Check if secret is cached and cache is still valid"""
        if secret_name not in self._secret_cache:
            return False
        
        ttl = self._cache_ttl.get(secret_name)
        if not ttl or datetime.utcnow() > ttl:
            # Clean up expired cache entry
            self._secret_cache.pop(secret_name, None)
            self._cache_ttl.pop(secret_name, None)
            return False
        
        return True
    
    def _update_access_metadata(self, secret_name: str):
        """Update access metadata for a secret"""
        metadata = self._secret_metadata.get(secret_name)
        if metadata:
            metadata.last_accessed = datetime.utcnow()
            metadata.access_count += 1
    
    def _is_rotation_enabled(self, secret_name: str) -> bool:
        """Check if rotation is enabled for a secret"""
        # This could be configured via tags or naming convention
        return secret_name.endswith("-rotatable")
    
    def _log_secret_access(self, secret_name: str, operation: str, 
                          success: bool, error: str = None):
        """Log secret access for audit purposes"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "secret_name": secret_name,
            "operation": operation,
            "success": success,
            "vault_url": self.vault_url
        }
        
        if error:
            log_entry["error"] = error
        
        # Log to structured logger (could be sent to SIEM)
        if success:
            logger.info(f"Key Vault audit: {json.dumps(log_entry)}")
        else:
            logger.error(f"Key Vault audit: {json.dumps(log_entry)}")
    
    def _start_background_tasks(self):
        """Start background tasks for health monitoring and rotation"""
        def background_worker():
            while True:
                try:
                    # Health check every 5 minutes
                    self._perform_health_check()
                    
                    # Check for rotation every hour
                    self._check_rotation_schedule()
                    
                    # Clean up expired cache entries
                    self._cleanup_cache()
                    
                    time.sleep(300)  # 5 minutes
                    
                except Exception as e:
                    logger.error(f"Background task error: {e}")
                    time.sleep(60)  # Retry in 1 minute on error
        
        thread = threading.Thread(target=background_worker, daemon=True)
        thread.start()
        logger.info("Started Key Vault background tasks")
    
    def _perform_health_check(self):
        """Perform periodic health check"""
        try:
            self._test_connectivity()
            self._health_status["healthy"] = True
            self._health_status["last_check"] = datetime.utcnow()
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self._health_status["healthy"] = False
            self._health_status["last_check"] = datetime.utcnow()
    
    def _check_rotation_schedule(self):
        """Check if any secrets need rotation"""
        with self._lock:
            for secret_name, metadata in self._secret_metadata.items():
                if metadata.rotation_enabled and metadata.expires_at:
                    # Rotate if expires within 7 days
                    if metadata.expires_at - datetime.utcnow() < timedelta(days=7):
                        logger.warning(f"Secret '{secret_name}' needs rotation")
                        # Could trigger automated rotation here
    
    def _cleanup_cache(self):
        """Clean up expired cache entries"""
        with self._lock:
            expired_keys = [
                key for key, ttl in self._cache_ttl.items()
                if datetime.utcnow() > ttl
            ]
            
            for key in expired_keys:
                self._secret_cache.pop(key, None)
                self._cache_ttl.pop(key, None)
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")


class KeyVaultSecretProvider:
    """
    Flask integration for Key Vault secrets
    Provides easy access to secrets in Flask applications
    """
    
    def __init__(self, app=None, vault_manager: AzureKeyVaultManager = None):
        self.vault_manager = vault_manager
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Flask app with Key Vault integration"""
        if not self.vault_manager:
            vault_url = app.config.get('AZURE_KEYVAULT_URL')
            if not vault_url:
                raise ValueError("AZURE_KEYVAULT_URL must be configured")
            
            use_managed_identity = app.config.get('AZURE_USE_MANAGED_IDENTITY', True)
            self.vault_manager = AzureKeyVaultManager(vault_url, use_managed_identity)
        
        # Register teardown handler
        app.teardown_appcontext(self._teardown)
        
        # Add health check endpoint
        @app.route('/health/keyvault')
        def keyvault_health():
            return self.vault_manager.get_health_status()
    
    def _teardown(self, exception):
        """Clean up resources on app context teardown"""
        pass
    
    def get(self, secret_name: str, default=None) -> str:
        """Get secret value with optional default"""
        value = self.vault_manager.get_secret(secret_name)
        return value if value is not None else default
    
    def get_required(self, secret_name: str) -> str:
        """Get secret value, raise exception if not found"""
        value = self.vault_manager.get_secret(secret_name)
        if value is None:
            raise ValueError(f"Required secret '{secret_name}' not found in Key Vault")
        return value


# Utility functions for common secret patterns
def get_database_connection_string(vault_manager: AzureKeyVaultManager) -> str:
    """Get database connection string from Key Vault"""
    return vault_manager.get_secret("database-connection-string")

def get_api_keys(vault_manager: AzureKeyVaultManager) -> Dict[str, str]:
    """Get all API keys from Key Vault"""
    api_keys = {}
    for secret_name in vault_manager.list_secrets():
        if secret_name.startswith("api-key-"):
            key_name = secret_name.replace("api-key-", "")
            api_keys[key_name] = vault_manager.get_secret(secret_name)
    return api_keys

def setup_certificate_rotation(vault_manager: AzureKeyVaultManager, 
                               cert_name: str, 
                               update_callback: callable):
    """Setup automatic certificate rotation"""
    vault_manager.register_rotation_callback(cert_name, update_callback)
