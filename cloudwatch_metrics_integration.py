# cloudwatch_metrics.py - CloudWatch Metrics and APM Integration

import boto3
import time
import threading
from datetime import datetime
from functools import wraps
from flask import Flask, request, g, current_app
from celery.signals import task_prerun, task_postrun, task_failure
import logging

class CloudWatchMetrics:
    """CloudWatch metrics client for ThreatCompass."""
    
    def __init__(self, namespace="ThreatCompass", region="us-east-1"):
        self.namespace = namespace
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.logger = logging.getLogger(__name__)
        
        # Batch metrics for efficiency
        self.metric_buffer = []
        self.buffer_lock = threading.Lock()
        self.max_buffer_size = 20
    
    def put_metric(self, metric_name, value, unit='Count', dimensions=None, timestamp=None):
        """Put a single metric to CloudWatch."""
        try:
            metric_data = {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Timestamp': timestamp or datetime.utcnow()
            }
            
            if dimensions:
                metric_data['Dimensions'] = [
                    {'Name': k, 'Value': str(v)} for k, v in dimensions.items()
                ]
            
            # Add to buffer for batch sending
            with self.buffer_lock:
                self.metric_buffer.append(metric_data)
                
                # Send batch if buffer is full
                if len(self.metric_buffer) >= self.max_buffer_size:
                    self._send_batch()
                    
        except Exception as e:
            self.logger.error(f"Failed to queue metric {metric_name}: {e}")
    
    def _send_batch(self):
        """Send batched metrics to CloudWatch."""
        if not self.metric_buffer:
            return
            
        try:
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace,
                MetricData=self.metric_buffer
            )
            self.logger.debug(f"Sent {len(self.metric_buffer)} metrics to CloudWatch")
            self.metric_buffer.clear()
            
        except Exception as e:
            self.logger.error(f"Failed to send metrics batch: {e}")
            # Keep metrics in buffer for retry
    
    def flush(self):
        """Flush remaining metrics in buffer."""
        with self.buffer_lock:
            if self.metric_buffer:
                self._send_batch()
    
    # Convenience methods for common metrics
    def record_request_duration(self, duration_ms, endpoint=None, method=None, status_code=None):
        """Record HTTP request duration."""
        dimensions = {'Service': 'FlaskApp'}
        if endpoint:
            dimensions['Endpoint'] = endpoint
        if method:
            dimensions['Method'] = method
        if status_code:
            dimensions['StatusCode'] = str(status_code)
            
        self.put_metric('RequestDuration', duration_ms, 'Milliseconds', dimensions)
    
    def record_error(self, error_type, component=None):
        """Record application errors."""
        dimensions = {'ErrorType': error_type}
        if component:
            dimensions['Component'] = component
            
        self.put_metric('Errors', 1, 'Count', dimensions)
    
    def record_business_metric(self, metric_name, value=1, unit='Count', tenant_id=None, user_id=None):
        """Record business/application-specific metrics."""
        dimensions = {'Service': 'ThreatCompass'}
        if tenant_id:
            dimensions['TenantId'] = str(tenant_id)
        if user_id:
            dimensions['UserId'] = str(user_id)
            
        self.put_metric(metric_name, value, unit, dimensions)
    
    def record_celery_task_metric(self, task_name, duration_ms=None, success=True):
        """Record Celery task metrics."""
        dimensions = {
            'TaskName': task_name,
            'Status': 'Success' if success else 'Failure'
        }
        
        # Record task count
        self.put_metric('CeleryTaskCount', 1, 'Count', dimensions)
        
        # Record task duration if provided
        if duration_ms is not None:
            self.put_metric('CeleryTaskDuration', duration_ms, 'Milliseconds', dimensions)


# Global metrics instance
metrics = CloudWatchMetrics()


def setup_flask_metrics_middleware(app: Flask):
    """Set up Flask middleware for automatic metrics collection."""
    
    @app.before_request
    def before_request_metrics():
        g.request_start_time = time.time()
    
    @app.after_request
    def after_request_metrics(response):
        if hasattr(g, 'request_start_time'):
            duration_ms = (time.time() - g.request_start_time) * 1000
            
            # Record request metrics
            metrics.record_request_duration(
                duration_ms=duration_ms,
                endpoint=request.endpoint,
                method=request.method,
                status_code=response.status_code
            )
            
            # Record error metrics for 4xx and 5xx responses
            if response.status_code >= 400:
                error_type = 'ClientError' if response.status_code < 500 else 'ServerError'
                metrics.record_error(error_type, 'FlaskApp')
        
        return response
    
    @app.teardown_appcontext
    def flush_metrics(error):
        """Flush metrics buffer on app context teardown."""
        metrics.flush()


def setup_celery_metrics(celery_app):
    """Set up Celery metrics collection."""
    
    # Task start times storage
    task_start_times = {}
    
    @task_prerun.connect
    def task_prerun_metrics(sender=None, task_id=None, task=None, **kwargs):
        """Record task start time."""
        task_start_times[task_id] = time.time()
    
    @task_postrun.connect
    def task_postrun_metrics(sender=None, task_id=None, task=None, retval=None, state=None, **kwargs):
        """Record task completion metrics."""
        if task_id in task_start_times:
            duration_ms = (time.time() - task_start_times[task_id]) * 1000
            del task_start_times[task_id]
            
            success = state == 'SUCCESS'
            metrics.record_celery_task_metric(
                task_name=task.name,
                duration_ms=duration_ms,
                success=success
            )
    
    @task_failure.connect
    def task_failure_metrics(sender=None, task_id=None, exception=None, traceback=None, einfo=None, **kwargs):
        """Record task failure metrics."""
        if task_id in task_start_times:
            duration_ms = (time.time() - task_start_times[task_id]) * 1000
            del task_start_times[task_id]
            
            metrics.record_celery_task_metric(
                task_name=sender.name,
                duration_ms=duration_ms,
                success=False
            )
            
            # Record specific error type
            error_type = type(exception).__name__ if exception else 'UnknownError'
            metrics.record_error(error_type, 'CeleryWorker')


# Decorators for measuring specific operations
def measure_time(metric_name, component=None):
    """Decorator to measure function execution time."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                error_type = type(e).__name__
                metrics.record_error(error_type, component or func.__module__)
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                
                dimensions = {'Component': component or func.__module__}
                if hasattr(g, 'tenant_id'):
                    dimensions['TenantId'] = str(g.tenant_id)
                
                metrics.put_metric(
                    metric_name,
                    duration_ms,
                    'Milliseconds',
                    dimensions
                )
        
        return wrapper
    return decorator


def count_calls(metric_name, component=None):
    """Decorator to count function calls."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            dimensions = {'Component': component or func.__module__}
            if hasattr(g, 'tenant_id'):
                dimensions['TenantId'] = str(g.tenant_id)
            
            metrics.put_metric(metric_name, 1, 'Count', dimensions)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


# ThreatCompass-specific metrics functions
class ThreatCompassMetrics:
    """ThreatCompass business metrics."""
    
    @staticmethod
    def record_ioc_processed(ioc_type, source, tenant_id=None, success=True):
        """Record IOC processing metrics."""
        dimensions = {
            'IOCType': ioc_type,
            'Source': source,
            'Status': 'Success' if success else 'Failure'
        }
        if tenant_id:
            dimensions['TenantId'] = str(tenant_id)
        
        metrics.put_metric('IOCsProcessed', 1, 'Count', dimensions)
    
    @staticmethod
    def record_playbook_generated(tenant_id=None, playbook_type=None, step_count=None):
        """Record playbook generation metrics."""
        dimensions = {'Component': 'PlaybookEngine'}
        if tenant_id:
            dimensions['TenantId'] = str(tenant_id)
        if playbook_type:
            dimensions['PlaybookType'] = playbook_type
        
        metrics.put_metric('PlaybooksGenerated', 1, 'Count', dimensions)
        
        if step_count:
            metrics.put_metric('PlaybookStepCount', step_count, 'Count', dimensions)
    
    @staticmethod
    def record_enrichment_success(enrichment_source, tenant_id=None):
        """Record successful IOC enrichment."""
        dimensions = {
            'EnrichmentSource': enrichment_source,
            'Status': 'Success'
        }
        if tenant_id:
            dimensions['TenantId'] = str(tenant_id)
        
        metrics.put_metric('EnrichmentAttempts', 1, 'Count', dimensions)
    
    @staticmethod
    def record_enrichment_failure(enrichment_source, error_type, tenant_id=None):
        """Record failed IOC enrichment."""
        dimensions = {
            'EnrichmentSource': enrichment_source,
            'Status': 'Failure',
            'ErrorType': error_type
        }
        if tenant_id:
            dimensions['TenantId'] = str(tenant_id)
        
        metrics.put_metric('EnrichmentAttempts', 1, 'Count', dimensions)
    
    @staticmethod
    def record_automation_execution(tool_type, action_type, tenant_id=None, success=True):
        """Record automated remediation execution."""
        dimensions = {
            'ToolType': tool_type,
            'ActionType': action_type,
            'Status': 'Success' if success else 'Failure'
        }
        if tenant_id:
            dimensions['TenantId'] = str(tenant_id)
        
        metrics.put_metric('AutomationExecutions', 1, 'Count', dimensions)
    
    @staticmethod
    def record_user_activity(activity_type, tenant_id=None, user_id=None):
        """Record user activity metrics."""
        dimensions = {'ActivityType': activity_type}
        if tenant_id:
            dimensions['TenantId'] = str(tenant_id)
        if user_id:
            dimensions['UserId'] = str(user_id)
        
        metrics.put_metric('UserActivity', 1, 'Count', dimensions)


# Example usage in application code
"""
# In your IOC processing code:
from cloudwatch_metrics import ThreatCompassMetrics, measure_time

@measure_time('IOCProcessingTime', 'IOCProcessor')
def process_ioc(ioc_data):
    try:
        # Process IOC logic here
        ioc = create_ioc(ioc_data)
        
        # Record business metric
        ThreatCompassMetrics.record_ioc_processed(
            ioc_type=ioc.type,
            source=ioc.source,
            tenant_id=ioc.tenant_id,
            success=True
        )
        
        return ioc
        
    except Exception as e:
        ThreatCompassMetrics.record_ioc_processed(
            ioc_type=ioc_data.get('type', 'unknown'),
            source=ioc_data.get('source', 'unknown'),
            tenant_id=ioc_data.get('tenant_id'),
            success=False
        )
        raise

# In your enrichment tasks:
def enrich_ioc_with_virustotal(ioc_id):
    try:
        # Enrichment logic here
        result = call_virustotal_api(ioc)
        
        ThreatCompassMetrics.record_enrichment_success(
            enrichment_source='VirusTotal',
            tenant_id=ioc.tenant_id
        )
        
        return result
        
    except Exception as e:
        ThreatCompassMetrics.record_enrichment_failure(
            enrichment_source='VirusTotal',
            error_type=type(e).__name__,
            tenant_id=ioc.tenant_id
        )
        raise
"""


# OpenTelemetry Integration (Optional but Recommended)
def setup_opentelemetry(app: Flask):
    """
    Optional: Set up OpenTelemetry for advanced tracing.
    Uncomment and configure if you want to use OpenTelemetry with AWS X-Ray.
    """
    
    # Uncomment to enable OpenTelemetry
    """
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    
    # Set up tracer provider
    trace.set_tracer_provider(TracerProvider())
    tracer = trace.get_tracer(__name__)
    
    # Configure OTLP exporter (for AWS X-Ray or other compatible backends)
    otlp_exporter = OTLPSpanExporter(
        endpoint="http://localhost:4317",  # Configure for your OTLP collector
        insecure=True
    )
    
    span_processor = BatchSpanProcessor(otlp_exporter)
    trace.get_tracer_provider().add_span_processor(span_processor)
    
    # Instrument Flask app
    FlaskInstrumentor().instrument_app(app)
    RequestsInstrumentor().instrument()
    SQLAlchemyInstrumentor().instrument(engine=app.extensions['sqlalchemy'].db.engine)
    """
    
    pass