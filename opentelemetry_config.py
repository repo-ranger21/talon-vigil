"""
OpenTelemetry Configuration for TalonVigil
Comprehensive observability with tracing, metrics, and logging
"""

import os
import logging
from typing import Dict, List, Optional, Any
from contextlib import contextmanager
import time
import functools

# OpenTelemetry imports
from opentelemetry import trace, metrics, baggage
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.celery import CeleryInstrumentor
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat
from opentelemetry.propagators.jaeger import JaegerPropagator
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.semconv.trace import SpanAttributes
from opentelemetry.trace.status import Status, StatusCode

# Structured logging
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, ConsoleLogRecordExporter
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

logger = logging.getLogger(__name__)

class TalonVigilObservability:
    """
    Comprehensive observability setup for TalonVigil
    Configures tracing, metrics, and logging with security context
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.service_name = config.get('service_name', 'talon-vigil')
        self.service_version = config.get('service_version', '1.0.0')
        self.environment = config.get('environment', 'development')
        self.namespace = config.get('namespace', 'security')
        
        # Observability components
        self.tracer_provider = None
        self.meter_provider = None
        self.logger_provider = None
        self.tracer = None
        self.meter = None
        
        # Custom metrics
        self.security_metrics = {}
        self.performance_metrics = {}
        
        # Initialize observability
        self._setup_resource()
        self._setup_tracing()
        self._setup_metrics()
        self._setup_logging()
        self._setup_instrumentation()
        self._setup_security_metrics()
    
    def _setup_resource(self):
        """Setup OpenTelemetry resource with service metadata"""
        self.resource = Resource.create({
            ResourceAttributes.SERVICE_NAME: self.service_name,
            ResourceAttributes.SERVICE_VERSION: self.service_version,
            ResourceAttributes.SERVICE_NAMESPACE: self.namespace,
            ResourceAttributes.DEPLOYMENT_ENVIRONMENT: self.environment,
            ResourceAttributes.SERVICE_INSTANCE_ID: os.getenv('HOSTNAME', 'unknown'),
            "security.platform": "talon-vigil",
            "security.component": "cybersecurity-platform"
        })
    
    def _setup_tracing(self):
        """Setup distributed tracing"""
        # Create tracer provider
        self.tracer_provider = TracerProvider(resource=self.resource)
        trace.set_tracer_provider(self.tracer_provider)
        
        # Setup exporters
        exporters = []
        
        # Console exporter for development
        if self.environment == 'development':
            console_exporter = ConsoleSpanExporter()
            exporters.append(console_exporter)
        
        # Jaeger exporter
        jaeger_endpoint = self.config.get('jaeger_endpoint')
        if jaeger_endpoint:
            jaeger_exporter = JaegerExporter(
                agent_host_name=jaeger_endpoint.split(':')[0],
                agent_port=int(jaeger_endpoint.split(':')[1]) if ':' in jaeger_endpoint else 14268,
                collector_endpoint=f"http://{jaeger_endpoint}/api/traces"
            )
            exporters.append(jaeger_exporter)
        
        # OTLP exporter
        otlp_endpoint = self.config.get('otlp_trace_endpoint')
        if otlp_endpoint:
            otlp_exporter = OTLPSpanExporter(
                endpoint=otlp_endpoint,
                headers=self.config.get('otlp_headers', {})
            )
            exporters.append(otlp_exporter)
        
        # Add span processors
        for exporter in exporters:
            span_processor = BatchSpanProcessor(exporter)
            self.tracer_provider.add_span_processor(span_processor)
        
        # Setup propagators
        propagators = [
            B3MultiFormat(),
            JaegerPropagator(),
        ]
        set_global_textmap(CompositePropagator(propagators))
        
        # Get tracer
        self.tracer = trace.get_tracer(self.service_name, self.service_version)
        
        logger.info("Distributed tracing configured")
    
    def _setup_metrics(self):
        """Setup metrics collection and export"""
        # Setup metric readers
        readers = []
        
        # Prometheus reader
        prometheus_port = self.config.get('prometheus_port', 8000)
        if prometheus_port:
            prometheus_reader = PrometheusMetricReader(port=prometheus_port)
            readers.append(prometheus_reader)
        
        # OTLP metric reader
        otlp_metrics_endpoint = self.config.get('otlp_metrics_endpoint')
        if otlp_metrics_endpoint:
            otlp_metric_exporter = OTLPMetricExporter(
                endpoint=otlp_metrics_endpoint,
                headers=self.config.get('otlp_headers', {})
            )
            otlp_reader = PeriodicExportingMetricReader(
                exporter=otlp_metric_exporter,
                export_interval_millis=10000  # 10 seconds
            )
            readers.append(otlp_reader)
        
        # Create meter provider
        self.meter_provider = MeterProvider(
            resource=self.resource,
            metric_readers=readers
        )
        metrics.set_meter_provider(self.meter_provider)
        
        # Get meter
        self.meter = metrics.get_meter(self.service_name, self.service_version)
        
        logger.info("Metrics collection configured")
    
    def _setup_logging(self):
        """Setup structured logging with OpenTelemetry"""
        # Create logger provider
        self.logger_provider = LoggerProvider(resource=self.resource)
        set_logger_provider(self.logger_provider)
        
        # Setup exporters
        exporters = []
        
        # Console exporter for development
        if self.environment == 'development':
            console_log_exporter = ConsoleLogRecordExporter()
            exporters.append(console_log_exporter)
        
        # OTLP log exporter
        otlp_logs_endpoint = self.config.get('otlp_logs_endpoint')
        if otlp_logs_endpoint:
            otlp_log_exporter = OTLPLogExporter(
                endpoint=otlp_logs_endpoint,
                headers=self.config.get('otlp_headers', {})
            )
            exporters.append(otlp_log_exporter)
        
        # Add log record processors
        for exporter in exporters:
            log_processor = BatchLogRecordProcessor(exporter)
            self.logger_provider.add_log_record_processor(log_processor)
        
        # Setup logging instrumentation
        LoggingInstrumentor().instrument(set_logging_format=True)
        
        # Configure handler for root logger
        handler = LoggingHandler(logger_provider=self.logger_provider)
        logging.getLogger().addHandler(handler)
        
        logger.info("Structured logging configured")
    
    def _setup_instrumentation(self):
        """Setup automatic instrumentation for common libraries"""
        # Flask instrumentation
        FlaskInstrumentor().instrument()
        
        # HTTP requests instrumentation
        RequestsInstrumentor().instrument()
        
        # Database instrumentation
        SQLAlchemyInstrumentor().instrument()
        
        # Redis instrumentation
        RedisInstrumentor().instrument()
        
        # Celery instrumentation
        CeleryInstrumentor().instrument()
        
        logger.info("Automatic instrumentation configured")
    
    def _setup_security_metrics(self):
        """Setup security-specific metrics"""
        # Authentication metrics
        self.security_metrics['auth_attempts'] = self.meter.create_counter(
            name="security_auth_attempts_total",
            description="Total authentication attempts",
            unit="1"
        )
        
        self.security_metrics['auth_failures'] = self.meter.create_counter(
            name="security_auth_failures_total",
            description="Failed authentication attempts",
            unit="1"
        )
        
        self.security_metrics['auth_successes'] = self.meter.create_counter(
            name="security_auth_successes_total",
            description="Successful authentication attempts",
            unit="1"
        )
        
        # Authorization metrics
        self.security_metrics['authz_denials'] = self.meter.create_counter(
            name="security_authz_denials_total",
            description="Authorization denials",
            unit="1"
        )
        
        # Threat detection metrics
        self.security_metrics['threats_detected'] = self.meter.create_counter(
            name="security_threats_detected_total",
            description="Security threats detected",
            unit="1"
        )
        
        self.security_metrics['threats_blocked'] = self.meter.create_counter(
            name="security_threats_blocked_total",
            description="Security threats blocked",
            unit="1"
        )
        
        self.security_metrics['threat_score'] = self.meter.create_histogram(
            name="security_threat_score",
            description="Threat score distribution",
            unit="1"
        )
        
        # Rate limiting metrics
        self.security_metrics['rate_limit_hits'] = self.meter.create_counter(
            name="security_rate_limit_hits_total",
            description="Rate limit hits",
            unit="1"
        )
        
        # Input validation metrics
        self.security_metrics['validation_failures'] = self.meter.create_counter(
            name="security_validation_failures_total",
            description="Input validation failures",
            unit="1"
        )
        
        # WAF metrics
        self.security_metrics['waf_blocks'] = self.meter.create_counter(
            name="security_waf_blocks_total",
            description="WAF blocks",
            unit="1"
        )
        
        # Performance metrics
        self.performance_metrics['request_duration'] = self.meter.create_histogram(
            name="http_request_duration_seconds",
            description="HTTP request duration",
            unit="s"
        )
        
        self.performance_metrics['request_size'] = self.meter.create_histogram(
            name="http_request_size_bytes",
            description="HTTP request size",
            unit="By"
        )
        
        self.performance_metrics['response_size'] = self.meter.create_histogram(
            name="http_response_size_bytes",
            description="HTTP response size",
            unit="By"
        )
        
        logger.info("Security metrics configured")
    
    @contextmanager
    def trace_security_operation(self, operation_name: str, attributes: Dict[str, Any] = None):
        """Context manager for tracing security operations"""
        with self.tracer.start_as_current_span(
            f"security.{operation_name}",
            attributes=attributes or {}
        ) as span:
            span.set_attribute("security.operation", operation_name)
            span.set_attribute("service.name", self.service_name)
            
            try:
                yield span
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                raise
    
    def record_auth_attempt(self, user_id: str, method: str, success: bool, 
                           ip_address: str = None, user_agent: str = None):
        """Record authentication attempt"""
        attributes = {
            "auth.method": method,
            "auth.user_id": user_id,
            "auth.success": success
        }
        
        if ip_address:
            attributes["client.ip"] = ip_address
        if user_agent:
            attributes["client.user_agent"] = user_agent
        
        # Record metrics
        self.security_metrics['auth_attempts'].add(1, attributes)
        
        if success:
            self.security_metrics['auth_successes'].add(1, attributes)
        else:
            self.security_metrics['auth_failures'].add(1, attributes)
        
        # Create span
        with self.trace_security_operation("authentication", attributes) as span:
            span.set_attribute("auth.result", "success" if success else "failure")
    
    def record_authorization_denial(self, user_id: str, resource: str, action: str, 
                                   reason: str = None):
        """Record authorization denial"""
        attributes = {
            "authz.user_id": user_id,
            "authz.resource": resource,
            "authz.action": action
        }
        
        if reason:
            attributes["authz.denial_reason"] = reason
        
        self.security_metrics['authz_denials'].add(1, attributes)
        
        with self.trace_security_operation("authorization_denial", attributes) as span:
            span.set_attribute("authz.denied", True)
    
    def record_threat_detection(self, threat_type: str, threat_score: float, 
                               source_ip: str = None, blocked: bool = False,
                               details: Dict[str, Any] = None):
        """Record threat detection"""
        attributes = {
            "threat.type": threat_type,
            "threat.blocked": blocked
        }
        
        if source_ip:
            attributes["threat.source_ip"] = source_ip
        
        # Record metrics
        self.security_metrics['threats_detected'].add(1, attributes)
        self.security_metrics['threat_score'].record(threat_score, attributes)
        
        if blocked:
            self.security_metrics['threats_blocked'].add(1, attributes)
        
        # Create detailed span
        with self.trace_security_operation("threat_detection", attributes) as span:
            span.set_attribute("threat.score", threat_score)
            if details:
                for key, value in details.items():
                    span.set_attribute(f"threat.{key}", str(value))
    
    def record_rate_limit_hit(self, client_id: str, endpoint: str, limit_type: str):
        """Record rate limit hit"""
        attributes = {
            "rate_limit.client_id": client_id,
            "rate_limit.endpoint": endpoint,
            "rate_limit.type": limit_type
        }
        
        self.security_metrics['rate_limit_hits'].add(1, attributes)
        
        with self.trace_security_operation("rate_limit_hit", attributes):
            pass
    
    def record_validation_failure(self, field: str, value_type: str, reason: str,
                                 endpoint: str = None):
        """Record input validation failure"""
        attributes = {
            "validation.field": field,
            "validation.value_type": value_type,
            "validation.reason": reason
        }
        
        if endpoint:
            attributes["validation.endpoint"] = endpoint
        
        self.security_metrics['validation_failures'].add(1, attributes)
        
        with self.trace_security_operation("validation_failure", attributes):
            pass
    
    def record_waf_block(self, rule_id: str, attack_type: str, source_ip: str,
                        payload: str = None):
        """Record WAF block"""
        attributes = {
            "waf.rule_id": rule_id,
            "waf.attack_type": attack_type,
            "waf.source_ip": source_ip
        }
        
        self.security_metrics['waf_blocks'].add(1, attributes)
        
        with self.trace_security_operation("waf_block", attributes) as span:
            if payload:
                span.set_attribute("waf.payload", payload[:500])  # Truncate for safety
    
    def record_http_request(self, method: str, endpoint: str, status_code: int,
                           duration: float, request_size: int = 0, 
                           response_size: int = 0):
        """Record HTTP request metrics"""
        attributes = {
            "http.method": method,
            "http.endpoint": endpoint,
            "http.status_code": status_code
        }
        
        self.performance_metrics['request_duration'].record(duration, attributes)
        
        if request_size > 0:
            self.performance_metrics['request_size'].record(request_size, attributes)
        
        if response_size > 0:
            self.performance_metrics['response_size'].record(response_size, attributes)
    
    def get_current_span(self):
        """Get current active span"""
        return trace.get_current_span()
    
    def add_span_attribute(self, key: str, value: Any):
        """Add attribute to current span"""
        span = self.get_current_span()
        if span:
            span.set_attribute(key, value)
    
    def add_span_event(self, name: str, attributes: Dict[str, Any] = None):
        """Add event to current span"""
        span = self.get_current_span()
        if span:
            span.add_event(name, attributes or {})


# Decorators for automatic tracing
def trace_security_function(operation_name: str = None):
    """Decorator to trace security functions"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            op_name = operation_name or func.__name__
            
            # Get observability instance from Flask app if available
            observability = getattr(wrapper, '_observability', None)
            if not observability:
                # Fallback to basic tracing
                tracer = trace.get_tracer(__name__)
                with tracer.start_as_current_span(f"security.{op_name}"):
                    return func(*args, **kwargs)
            
            with observability.trace_security_operation(op_name) as span:
                # Add function metadata
                span.set_attribute("code.function", func.__name__)
                span.set_attribute("code.namespace", func.__module__)
                
                return func(*args, **kwargs)
        
        return wrapper
    return decorator

def trace_api_endpoint(endpoint_name: str = None):
    """Decorator to trace API endpoints with security context"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            endpoint = endpoint_name or func.__name__
            
            # Get Flask request context if available
            try:
                from flask import request, g
                method = request.method
                client_ip = request.remote_addr
                user_agent = request.headers.get('User-Agent', '')
                user_id = getattr(g, 'user_id', 'anonymous')
            except:
                method = 'UNKNOWN'
                client_ip = None
                user_agent = None
                user_id = 'unknown'
            
            tracer = trace.get_tracer(__name__)
            with tracer.start_as_current_span(f"api.{endpoint}") as span:
                # Add request attributes
                span.set_attribute("http.method", method)
                span.set_attribute("http.endpoint", endpoint)
                span.set_attribute("user.id", user_id)
                
                if client_ip:
                    span.set_attribute("client.ip", client_ip)
                if user_agent:
                    span.set_attribute("client.user_agent", user_agent)
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Record success
                    duration = time.time() - start_time
                    span.set_attribute("http.status_code", 200)
                    span.set_attribute("http.duration_ms", duration * 1000)
                    
                    return result
                    
                except Exception as e:
                    # Record error
                    duration = time.time() - start_time
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    span.set_attribute("http.status_code", 500)
                    span.set_attribute("http.duration_ms", duration * 1000)
                    raise
        
        return wrapper
    return decorator

# Flask integration
class FlaskObservabilityExtension:
    """Flask extension for TalonVigil observability"""
    
    def __init__(self, app=None):
        self.observability = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Flask app with observability"""
        # Get observability config
        observability_config = {
            'service_name': app.config.get('SERVICE_NAME', 'talon-vigil'),
            'service_version': app.config.get('SERVICE_VERSION', '1.0.0'),
            'environment': app.config.get('ENVIRONMENT', 'development'),
            'namespace': app.config.get('SERVICE_NAMESPACE', 'security'),
            'jaeger_endpoint': app.config.get('JAEGER_ENDPOINT'),
            'otlp_trace_endpoint': app.config.get('OTLP_TRACE_ENDPOINT'),
            'otlp_metrics_endpoint': app.config.get('OTLP_METRICS_ENDPOINT'),
            'otlp_logs_endpoint': app.config.get('OTLP_LOGS_ENDPOINT'),
            'otlp_headers': app.config.get('OTLP_HEADERS', {}),
            'prometheus_port': app.config.get('PROMETHEUS_PORT', 8000)
        }
        
        # Initialize observability
        self.observability = TalonVigilObservability(observability_config)
        
        # Store in app context
        app.extensions['observability'] = self.observability
        
        # Setup request hooks
        self._setup_request_hooks(app)
        
        logger.info("Flask observability extension initialized")
    
    def _setup_request_hooks(self, app):
        """Setup Flask request hooks for automatic observability"""
        
        @app.before_request
        def before_request():
            from flask import g, request
            g.request_start_time = time.time()
            
            # Add baggage for security context
            if hasattr(g, 'user_id'):
                baggage.set_baggage("user.id", g.user_id)
            
            baggage.set_baggage("request.id", request.headers.get('X-Request-ID', 'unknown'))
        
        @app.after_request
        def after_request(response):
            from flask import g, request
            
            # Record request metrics
            if hasattr(g, 'request_start_time'):
                duration = time.time() - g.request_start_time
                
                self.observability.record_http_request(
                    method=request.method,
                    endpoint=request.endpoint or request.path,
                    status_code=response.status_code,
                    duration=duration,
                    request_size=request.content_length or 0,
                    response_size=response.content_length or 0
                )
            
            return response


# Utility functions
def get_observability_from_app(app=None):
    """Get observability instance from Flask app"""
    if app:
        return app.extensions.get('observability')
    
    # Try to get from current app context
    try:
        from flask import current_app
        return current_app.extensions.get('observability')
    except:
        return None

def configure_observability(config: Dict[str, Any]) -> TalonVigilObservability:
    """Configure and return observability instance"""
    return TalonVigilObservability(config)

def shutdown_observability():
    """Shutdown observability components gracefully"""
    # This would be called during application shutdown
    # to ensure all telemetry is flushed
    logger.info("Shutting down observability components")
    
    # Force flush any pending data
    try:
        tracer_provider = trace.get_tracer_provider()
        if hasattr(tracer_provider, 'force_flush'):
            tracer_provider.force_flush()
    except:
        pass
    
    try:
        meter_provider = metrics.get_meter_provider()
        if hasattr(meter_provider, 'force_flush'):
            meter_provider.force_flush()
    except:
        pass
