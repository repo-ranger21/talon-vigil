"""
Advanced OpenTelemetry Observability for TalonVigil
Implements comprehensive telemetry, tracing, metrics, and logging
"""

import asyncio
import json
import logging
import time
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
import psutil

# OpenTelemetry imports
from opentelemetry import trace, metrics, baggage
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat
from opentelemetry.trace.status import Status, StatusCode
import structlog

logger = structlog.get_logger(__name__)

class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    GAUGE = "gauge"
    UP_DOWN_COUNTER = "up_down_counter"

class AlertLevel(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class SpanContext:
    """Span context information"""
    trace_id: str
    span_id: str
    operation_name: str
    service_name: str
    start_time: datetime
    duration_ms: Optional[float] = None
    status: Optional[str] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class MetricData:
    """Metric data structure"""
    name: str
    type: MetricType
    value: Union[int, float]
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""
    unit: str = ""

@dataclass
class AlertRule:
    """Alert rule configuration"""
    name: str
    metric_name: str
    condition: str  # e.g., "> 0.8", "< 10"
    threshold: float
    level: AlertLevel
    duration_seconds: int = 60
    labels: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True

class TelemetryConfig:
    """Telemetry configuration"""
    
    def __init__(self):
        self.service_name = os.getenv('SERVICE_NAME', 'talonvigil')
        self.service_version = os.getenv('SERVICE_VERSION', '1.0.0')
        self.environment = os.getenv('ENVIRONMENT', 'development')
        
        # Jaeger configuration
        self.jaeger_endpoint = os.getenv('JAEGER_ENDPOINT', 'http://localhost:14268/api/traces')
        self.jaeger_enabled = os.getenv('JAEGER_ENABLED', 'true').lower() == 'true'
        
        # OTLP configuration
        self.otlp_endpoint = os.getenv('OTLP_ENDPOINT', 'http://localhost:4317')
        self.otlp_enabled = os.getenv('OTLP_ENABLED', 'false').lower() == 'true'
        
        # Prometheus configuration
        self.prometheus_port = int(os.getenv('PROMETHEUS_PORT', '8000'))
        self.prometheus_enabled = os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true'
        
        # Sampling configuration
        self.trace_sample_rate = float(os.getenv('TRACE_SAMPLE_RATE', '1.0'))
        self.metric_export_interval = int(os.getenv('METRIC_EXPORT_INTERVAL', '5'))

class TelemetryInstrumentation:
    """Telemetry instrumentation manager"""
    
    def __init__(self, config: TelemetryConfig):
        self.config = config
        self.tracer_provider = None
        self.meter_provider = None
        self.tracer = None
        self.meter = None
        self.custom_metrics: Dict[str, Any] = {}
        self.alert_rules: List[AlertRule] = []
        self.metric_history: List[MetricData] = []
        self.active_spans: Dict[str, SpanContext] = {}
        
        self._setup_resource()
        self._setup_tracing()
        self._setup_metrics()
        self._setup_logging()
        self._setup_auto_instrumentation()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _setup_resource(self):
        """Setup OpenTelemetry resource"""
        self.resource = Resource.create({
            ResourceAttributes.SERVICE_NAME: self.config.service_name,
            ResourceAttributes.SERVICE_VERSION: self.config.service_version,
            ResourceAttributes.DEPLOYMENT_ENVIRONMENT: self.config.environment,
            "service.instance.id": f"{self.config.service_name}-{os.getpid()}",
        })
    
    def _setup_tracing(self):
        """Setup distributed tracing"""
        try:
            # Create tracer provider
            self.tracer_provider = TracerProvider(resource=self.resource)
            trace.set_tracer_provider(self.tracer_provider)
            
            # Setup exporters
            if self.config.jaeger_enabled:
                jaeger_exporter = JaegerExporter(
                    endpoint=self.config.jaeger_endpoint,
                )
                self.tracer_provider.add_span_processor(
                    BatchSpanProcessor(jaeger_exporter)
                )
                logger.info("Jaeger tracing enabled")
            
            if self.config.otlp_enabled:
                otlp_exporter = OTLPSpanExporter(
                    endpoint=self.config.otlp_endpoint,
                    insecure=True
                )
                self.tracer_provider.add_span_processor(
                    BatchSpanProcessor(otlp_exporter)
                )
                logger.info("OTLP tracing enabled")
            
            # Setup propagators
            set_global_textmap(B3MultiFormat())
            
            # Get tracer
            self.tracer = trace.get_tracer(__name__)
            
            logger.info("Distributed tracing setup completed")
            
        except Exception as e:
            logger.error(f"Error setting up tracing: {e}")
    
    def _setup_metrics(self):
        """Setup metrics collection"""
        try:
            readers = []
            
            # Prometheus reader
            if self.config.prometheus_enabled:
                prometheus_reader = PrometheusMetricReader(port=self.config.prometheus_port)
                readers.append(prometheus_reader)
                logger.info(f"Prometheus metrics enabled on port {self.config.prometheus_port}")
            
            # OTLP reader
            if self.config.otlp_enabled:
                otlp_reader = PeriodicExportingMetricReader(
                    OTLPMetricExporter(endpoint=self.config.otlp_endpoint, insecure=True),
                    export_interval_millis=self.config.metric_export_interval * 1000
                )
                readers.append(otlp_reader)
                logger.info("OTLP metrics enabled")
            
            # Create meter provider
            self.meter_provider = MeterProvider(
                resource=self.resource,
                metric_readers=readers
            )
            metrics.set_meter_provider(self.meter_provider)
            
            # Get meter
            self.meter = metrics.get_meter(__name__)
            
            # Create custom metrics
            self._create_custom_metrics()
            
            logger.info("Metrics collection setup completed")
            
        except Exception as e:
            logger.error(f"Error setting up metrics: {e}")
    
    def _setup_logging(self):
        """Setup structured logging with correlation"""
        try:
            # Configure structlog
            structlog.configure(
                processors=[
                    structlog.contextvars.merge_contextvars,
                    structlog.processors.add_log_level,
                    structlog.processors.TimeStamper(fmt="ISO"),
                    structlog.dev.ConsoleRenderer() if self.config.environment == 'development' 
                    else structlog.processors.JSONRenderer()
                ],
                wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
                logger_factory=structlog.stdlib.LoggerFactory(),
                cache_logger_on_first_use=True,
            )
            
            logger.info("Structured logging setup completed")
            
        except Exception as e:
            logger.error(f"Error setting up logging: {e}")
    
    def _setup_auto_instrumentation(self):
        """Setup automatic instrumentation"""
        try:
            # Flask instrumentation
            FlaskInstrumentor().instrument()
            
            # Requests instrumentation
            RequestsInstrumentor().instrument()
            
            # Database instrumentation
            Psycopg2Instrumentor().instrument()
            
            # Redis instrumentation
            RedisInstrumentor().instrument()
            
            logger.info("Auto-instrumentation setup completed")
            
        except Exception as e:
            logger.warning(f"Some auto-instrumentation may not be available: {e}")
    
    def _create_custom_metrics(self):
        """Create custom application metrics"""
        try:
            # Security metrics
            self.custom_metrics['threat_detections'] = self.meter.create_counter(
                name="threat_detections_total",
                description="Total number of threat detections",
                unit="1"
            )
            
            self.custom_metrics['threat_score_histogram'] = self.meter.create_histogram(
                name="threat_score",
                description="Distribution of threat scores",
                unit="1"
            )
            
            self.custom_metrics['api_requests'] = self.meter.create_counter(
                name="api_requests_total",
                description="Total API requests",
                unit="1"
            )
            
            self.custom_metrics['api_duration'] = self.meter.create_histogram(
                name="api_request_duration_seconds",
                description="API request duration",
                unit="s"
            )
            
            self.custom_metrics['active_sessions'] = self.meter.create_up_down_counter(
                name="active_sessions",
                description="Number of active user sessions",
                unit="1"
            )
            
            self.custom_metrics['memory_usage'] = self.meter.create_gauge(
                name="memory_usage_bytes",
                description="Memory usage in bytes",
                unit="bytes"
            )
            
            self.custom_metrics['failed_authentications'] = self.meter.create_counter(
                name="failed_authentications_total",
                description="Total failed authentication attempts",
                unit="1"
            )
            
            self.custom_metrics['chaos_experiments'] = self.meter.create_counter(
                name="chaos_experiments_total",
                description="Total chaos experiments executed",
                unit="1"
            )
            
            logger.info("Custom metrics created")
            
        except Exception as e:
            logger.error(f"Error creating custom metrics: {e}")
    
    @contextmanager
    def trace_operation(self, operation_name: str, **attributes):
        """Context manager for tracing operations"""
        with self.tracer.start_as_current_span(operation_name) as span:
            span_context = SpanContext(
                trace_id=format(span.get_span_context().trace_id, '032x'),
                span_id=format(span.get_span_context().span_id, '016x'),
                operation_name=operation_name,
                service_name=self.config.service_name,
                start_time=datetime.now(timezone.utc)
            )
            
            # Add attributes
            for key, value in attributes.items():
                span.set_attribute(key, value)
                span_context.tags[key] = value
            
            # Store active span
            self.active_spans[span_context.span_id] = span_context
            
            try:
                yield span_context
                span.set_status(Status(StatusCode.OK))
                span_context.status = "ok"
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span_context.status = "error"
                span_context.logs.append({
                    "level": "error",
                    "message": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                raise
            finally:
                span_context.duration_ms = (
                    datetime.now(timezone.utc) - span_context.start_time
                ).total_seconds() * 1000
                self.active_spans.pop(span_context.span_id, None)
    
    def record_metric(self, metric_data: MetricData):
        """Record a custom metric"""
        try:
            metric = self.custom_metrics.get(metric_data.name)
            if not metric:
                logger.warning(f"Metric {metric_data.name} not found")
                return
            
            labels = metric_data.labels
            
            if metric_data.type == MetricType.COUNTER:
                metric.add(metric_data.value, labels)
            elif metric_data.type == MetricType.HISTOGRAM:
                metric.record(metric_data.value, labels)
            elif metric_data.type == MetricType.UP_DOWN_COUNTER:
                metric.add(metric_data.value, labels)
            elif metric_data.type == MetricType.GAUGE:
                # For gauge, we need to use a callback
                pass
            
            # Store in history for alerting
            self.metric_history.append(metric_data)
            
            # Check alert rules
            self._check_alert_rules(metric_data)
            
        except Exception as e:
            logger.error(f"Error recording metric: {e}")
    
    def add_alert_rule(self, rule: AlertRule):
        """Add an alert rule"""
        self.alert_rules.append(rule)
        logger.info(f"Added alert rule: {rule.name}")
    
    def _check_alert_rules(self, metric_data: MetricData):
        """Check if metric triggers any alert rules"""
        for rule in self.alert_rules:
            if not rule.enabled or rule.metric_name != metric_data.name:
                continue
            
            try:
                # Simple condition evaluation
                if self._evaluate_condition(metric_data.value, rule.condition, rule.threshold):
                    self._trigger_alert(rule, metric_data)
                    
            except Exception as e:
                logger.error(f"Error evaluating alert rule {rule.name}: {e}")
    
    def _evaluate_condition(self, value: float, condition: str, threshold: float) -> bool:
        """Evaluate alert condition"""
        if condition.startswith('>'):
            return value > threshold
        elif condition.startswith('<'):
            return value < threshold
        elif condition.startswith('>='):
            return value >= threshold
        elif condition.startswith('<='):
            return value <= threshold
        elif condition.startswith('=='):
            return value == threshold
        elif condition.startswith('!='):
            return value != threshold
        else:
            return False
    
    def _trigger_alert(self, rule: AlertRule, metric_data: MetricData):
        """Trigger an alert"""
        alert_data = {
            "rule_name": rule.name,
            "metric_name": metric_data.name,
            "value": metric_data.value,
            "threshold": rule.threshold,
            "condition": rule.condition,
            "level": rule.level.value,
            "timestamp": metric_data.timestamp.isoformat(),
            "labels": {**metric_data.labels, **rule.labels}
        }
        
        logger.warning("Alert triggered", alert=alert_data)
        
        # Here you could integrate with alerting systems like PagerDuty, Slack, etc.
        self._send_alert_notification(alert_data)
    
    def _send_alert_notification(self, alert_data: Dict[str, Any]):
        """Send alert notification"""
        # Placeholder for alert notification integration
        # Could integrate with Slack, PagerDuty, email, etc.
        logger.info(f"Alert notification would be sent: {alert_data}")
    
    def get_system_metrics(self) -> Dict[str, float]:
        """Get current system metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            metrics = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used_bytes': memory.used,
                'memory_available_bytes': memory.available,
                'disk_percent': disk.percent,
                'disk_used_bytes': disk.used,
                'disk_free_bytes': disk.free
            }
            
            # Record system metrics
            for name, value in metrics.items():
                if name in self.custom_metrics:
                    self.record_metric(MetricData(
                        name=name,
                        type=MetricType.GAUGE,
                        value=value
                    ))
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return {}
    
    def get_telemetry_status(self) -> Dict[str, Any]:
        """Get telemetry system status"""
        return {
            'service_name': self.config.service_name,
            'service_version': self.config.service_version,
            'environment': self.config.environment,
            'tracing_enabled': self.tracer is not None,
            'metrics_enabled': self.meter is not None,
            'jaeger_enabled': self.config.jaeger_enabled,
            'otlp_enabled': self.config.otlp_enabled,
            'prometheus_enabled': self.config.prometheus_enabled,
            'active_spans': len(self.active_spans),
            'alert_rules': len(self.alert_rules),
            'metric_history_size': len(self.metric_history)
        }
    
    def _start_background_tasks(self):
        """Start background telemetry tasks"""
        self._system_metrics_task = asyncio.create_task(self._system_metrics_worker())
        self._cleanup_task = asyncio.create_task(self._cleanup_worker())
    
    async def _system_metrics_worker(self):
        """Background worker for system metrics collection"""
        while True:
            try:
                await asyncio.sleep(30)  # Collect every 30 seconds
                self.get_system_metrics()
                
            except Exception as e:
                logger.error(f"Error in system metrics worker: {e}")
    
    async def _cleanup_worker(self):
        """Background cleanup worker"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Clean up old metric history
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
                self.metric_history = [
                    m for m in self.metric_history 
                    if m.timestamp > cutoff_time
                ]
                
                logger.debug("Telemetry cleanup completed")
                
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")

class SecurityTelemetry:
    """Security-specific telemetry and monitoring"""
    
    def __init__(self, instrumentation: TelemetryInstrumentation):
        self.instrumentation = instrumentation
        self._setup_security_metrics()
        self._setup_security_alerts()
    
    def _setup_security_metrics(self):
        """Setup security-specific metrics"""
        # Add custom security metrics beyond the defaults
        pass
    
    def _setup_security_alerts(self):
        """Setup security alert rules"""
        # High threat detection rate
        self.instrumentation.add_alert_rule(AlertRule(
            name="high_threat_detection_rate",
            metric_name="threat_detections_total",
            condition="> 10",
            threshold=10.0,
            level=AlertLevel.WARNING,
            duration_seconds=300
        ))
        
        # Failed authentication spike
        self.instrumentation.add_alert_rule(AlertRule(
            name="authentication_failure_spike",
            metric_name="failed_authentications_total",
            condition="> 5",
            threshold=5.0,
            level=AlertLevel.ERROR,
            duration_seconds=60
        ))
        
        # High API error rate
        self.instrumentation.add_alert_rule(AlertRule(
            name="high_api_error_rate",
            metric_name="api_requests_total",
            condition="> 100",
            threshold=100.0,
            level=AlertLevel.WARNING,
            duration_seconds=300
        ))
    
    def record_threat_detection(self, threat_type: str, score: float, source_ip: str = ""):
        """Record a threat detection"""
        with self.instrumentation.trace_operation(
            "threat_detection",
            threat_type=threat_type,
            threat_score=score,
            source_ip=source_ip
        ):
            # Record counter metric
            self.instrumentation.record_metric(MetricData(
                name="threat_detections_total",
                type=MetricType.COUNTER,
                value=1,
                labels={"threat_type": threat_type, "source_ip": source_ip}
            ))
            
            # Record score histogram
            self.instrumentation.record_metric(MetricData(
                name="threat_score",
                type=MetricType.HISTOGRAM,
                value=score,
                labels={"threat_type": threat_type}
            ))
    
    def record_authentication_failure(self, username: str = "", source_ip: str = ""):
        """Record an authentication failure"""
        with self.instrumentation.trace_operation(
            "authentication_failure",
            username=username,
            source_ip=source_ip
        ):
            self.instrumentation.record_metric(MetricData(
                name="failed_authentications_total",
                type=MetricType.COUNTER,
                value=1,
                labels={"username": username, "source_ip": source_ip}
            ))
    
    def record_api_request(self, endpoint: str, method: str, status_code: int, duration: float):
        """Record an API request"""
        with self.instrumentation.trace_operation(
            f"{method} {endpoint}",
            http_method=method,
            http_status_code=status_code,
            http_endpoint=endpoint
        ):
            # Request counter
            self.instrumentation.record_metric(MetricData(
                name="api_requests_total",
                type=MetricType.COUNTER,
                value=1,
                labels={
                    "method": method, 
                    "endpoint": endpoint, 
                    "status_code": str(status_code)
                }
            ))
            
            # Duration histogram
            self.instrumentation.record_metric(MetricData(
                name="api_request_duration_seconds",
                type=MetricType.HISTOGRAM,
                value=duration,
                labels={"method": method, "endpoint": endpoint}
            ))
    
    def record_chaos_experiment(self, experiment_type: str, status: str):
        """Record a chaos experiment"""
        with self.instrumentation.trace_operation(
            "chaos_experiment",
            experiment_type=experiment_type,
            experiment_status=status
        ):
            self.instrumentation.record_metric(MetricData(
                name="chaos_experiments_total",
                type=MetricType.COUNTER,
                value=1,
                labels={"experiment_type": experiment_type, "status": status}
            ))

# Decorators for easy instrumentation
def trace_function(operation_name: str = None):
    """Decorator to trace function execution"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            name = operation_name or f"{func.__module__}.{func.__name__}"
            # This would need access to the global instrumentation instance
            # For now, it's a placeholder
            with trace.get_tracer(__name__).start_as_current_span(name):
                return func(*args, **kwargs)
        return wrapper
    return decorator

def record_metric_on_call(_metric_name: str, _metric_type: MetricType = MetricType.COUNTER):
    """Decorator to record metric on function call"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                # Record success metric
                # This would need access to the global instrumentation instance
                return result
            except Exception:
                # Record error metric and re-raise
                raise
        return wrapper
    return decorator

# Factory functions
def create_telemetry_instrumentation(config: Optional[TelemetryConfig] = None) -> TelemetryInstrumentation:
    """Create telemetry instrumentation instance"""
    if config is None:
        config = TelemetryConfig()
    
    return TelemetryInstrumentation(config)

def create_security_telemetry(instrumentation: TelemetryInstrumentation) -> SecurityTelemetry:
    """Create security telemetry instance"""
    return SecurityTelemetry(instrumentation)

# Global instances (to be initialized by the application)
_global_instrumentation: Optional[TelemetryInstrumentation] = None
_global_security_telemetry: Optional[SecurityTelemetry] = None

def initialize_telemetry(config: Optional[TelemetryConfig] = None):
    """Initialize global telemetry instances"""
    global _global_instrumentation, _global_security_telemetry
    
    _global_instrumentation = create_telemetry_instrumentation(config)
    _global_security_telemetry = create_security_telemetry(_global_instrumentation)
    
    logger.info("Global telemetry initialized")

def get_instrumentation() -> Optional[TelemetryInstrumentation]:
    """Get global instrumentation instance"""
    return _global_instrumentation

def get_security_telemetry() -> Optional[SecurityTelemetry]:
    """Get global security telemetry instance"""
    return _global_security_telemetry

# Example usage and integration
async def demo_telemetry():
    """Demonstration of telemetry usage"""
    # Initialize telemetry
    config = TelemetryConfig()
    instrumentation = create_telemetry_instrumentation(config)
    security_telemetry = create_security_telemetry(instrumentation)
    
    # Trace an operation
    with instrumentation.trace_operation("demo_operation", user_id="123"):
        # Simulate some work
        await asyncio.sleep(0.1)
        
        # Record threat detection
        security_telemetry.record_threat_detection("malware", 0.8, "192.168.1.100")
        
        # Record API request
        security_telemetry.record_api_request("/api/threats", "GET", 200, 0.05)
        
        # Record system metrics
        system_metrics = instrumentation.get_system_metrics()
        print(f"System metrics: {system_metrics}")
    
    # Get telemetry status
    status = instrumentation.get_telemetry_status()
    print(f"Telemetry status: {status}")

if __name__ == "__main__":
    asyncio.run(demo_telemetry())
