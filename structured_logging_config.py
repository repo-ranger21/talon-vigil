# logging_config.py - Structured Logging with Correlation IDs for ThreatCompass

import logging
import json
import uuid
import time
from datetime import datetime
from flask import Flask, request, g
from functools import wraps
import threading

class CorrelationIdFilter(logging.Filter):
    """Add correlation ID to all log records."""
    
    def filter(self, record):
        # Get correlation ID from thread-local storage or Flask g
        correlation_id = getattr(g, 'correlation_id', None) or getattr(threading.current_thread(), 'correlation_id', None)
        record.correlation_id = correlation_id or 'no-correlation-id'
        
        # Add request context if available
        if hasattr(g, 'current_user_id'):
            record.user_id = g.current_user_id
        if hasattr(g, 'tenant_id'):
            record.tenant_id = g.tenant_id
            
        return True


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record):
        # Create base log entry
        log_entry = {
            'timestamp': datetime.utcfromtimestamp(record.created).isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'correlation_id': getattr(record, 'correlation_id', 'no-correlation-id'),
            'service': 'threatcompass',
            'environment': getattr(record, 'environment', 'production')
        }
        
        # Add optional fields if present
        optional_fields = ['user_id', 'tenant_id', 'module', 'function', 'line', 'duration']
        for field in optional_fields:
            if hasattr(record, field):
                log_entry[field] = getattr(record, field)
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
        
        # Add request context if available
        if hasattr(record, 'request_method'):
            log_entry['request'] = {
                'method': record.request_method,
                'path': record.request_path,
                'remote_addr': record.request_remote_addr,
                'user_agent': getattr(record, 'request_user_agent', None)
            }
        
        # Add custom fields from extra parameter
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        return json.dumps(log_entry)


def setup_logging(app: Flask):
    """Configure structured logging for the Flask application."""
    
    # Remove default handlers
    app.logger.handlers.clear()
    
    # Create console handler with JSON formatting
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(JSONFormatter())
    console_handler.addFilter(CorrelationIdFilter())
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        handlers=[console_handler],
        format='%(message)s'
    )
    
    # Set specific logger levels
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    
    # Configure application logger
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(console_handler)
    
    return app.logger


def setup_correlation_id_middleware(app: Flask):
    """Set up correlation ID middleware for Flask."""
    
    @app.before_request
    def before_request():
        # Generate or extract correlation ID
        correlation_id = request.headers.get('X-Correlation-ID')
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        
        # Store in Flask g context
        g.correlation_id = correlation_id
        g.request_start_time = time.time()
        
        # Store user context if authenticated
        from flask_login import current_user
        if hasattr(current_user, 'id') and current_user.is_authenticated:
            g.current_user_id = current_user.id
            g.tenant_id = getattr(current_user, 'tenant_id', None)
        
        # Log request start
        app.logger.info(
            "Request started",
            extra={
                'extra_fields': {
                    'request_method': request.method,
                    'request_path': request.path,
                    'request_remote_addr': request.remote_addr,
                    'request_user_agent': request.headers.get('User-Agent', '')[:200]
                }
            }
        )
    
    @app.after_request
    def after_request(response):
        # Calculate request duration
        duration = time.time() - g.get('request_start_time', time.time())
        
        # Log request completion
        app.logger.info(
            "Request completed",
            extra={
                'extra_fields': {
                    'request_method': request.method,
                    'request_path': request.path,
                    'response_status': response.status_code,
                    'duration': round(duration * 1000, 2),  # milliseconds
                    'content_length': response.content_length
                }
            }
        )
        
        # Add correlation ID to response headers
        response.headers['X-Correlation-ID'] = g.get('correlation_id', 'unknown')
        
        return response
    
    return app


# Decorator for adding correlation context to functions
def with_correlation_context(correlation_id=None, user_id=None, tenant_id=None):
    """Decorator to add correlation context to any function."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Set thread-local correlation context
            thread = threading.current_thread()
            thread.correlation_id = correlation_id or getattr(g, 'correlation_id', str(uuid.uuid4()))
            
            if user_id:
                thread.user_id = user_id
            if tenant_id:
                thread.tenant_id = tenant_id
            
            try:
                return func(*args, **kwargs)
            finally:
                # Clean up thread-local data
                for attr in ['correlation_id', 'user_id', 'tenant_id']:
                    if hasattr(thread, attr):
                        delattr(thread, attr)
        
        return wrapper
    return decorator


# Enhanced logger class for application use
class ThreatCompassLogger:
    """Enhanced logger with correlation ID and structured logging support."""
    
    def __init__(self, name):
        self.logger = logging.getLogger(name)
    
    def _log(self, level, message, **kwargs):
        """Internal logging method with enhanced context."""
        extra_fields = kwargs.pop('extra', {})
        
        # Add timing information if provided
        if 'duration' in kwargs:
            extra_fields['duration'] = kwargs.pop('duration')
        
        # Add any other custom fields
        extra_fields.update(kwargs)
        
        self.logger.log(
            level, 
            message, 
            extra={'extra_fields': extra_fields} if extra_fields else None
        )
    
    def info(self, message, **kwargs):
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message, **kwargs):
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message, **kwargs):
        self._log(logging.ERROR, message, **kwargs)
    
    def debug(self, message, **kwargs):
        self._log(logging.DEBUG, message, **kwargs)
    
    def critical(self, message, **kwargs):
        self._log(logging.CRITICAL, message, **kwargs)


# Celery logging configuration
def setup_celery_logging():
    """Configure structured logging for Celery workers."""
    
    # Configure Celery logger
    celery_logger = logging.getLogger('celery')
    celery_logger.handlers.clear()
    
    # Create handler with JSON formatting
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    handler.addFilter(CorrelationIdFilter())
    
    celery_logger.addHandler(handler)
    celery_logger.setLevel(logging.INFO)
    
    return celery_logger


# Celery signal handlers for correlation ID propagation
def setup_celery_correlation_signals(celery_app):
    """Set up Celery signals to propagate correlation IDs."""
    
    from celery.signals import before_task_publish, task_prerun, task_postrun
    
    @before_task_publish.connect
    def before_task_publish_handler(sender=None, headers=None, **kwargs):
        """Add correlation ID to task headers before publishing."""
        correlation_id = getattr(g, 'correlation_id', None) or getattr(threading.current_thread(), 'correlation_id', None)
        if correlation_id and headers:
            headers['correlation_id'] = correlation_id
            headers['user_id'] = getattr(g, 'current_user_id', None)
            headers['tenant_id'] = getattr(g, 'tenant_id', None)
    
    @task_prerun.connect
    def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
        """Set up correlation context before task execution."""
        # Get correlation ID from task headers
        correlation_id = task.request.get('correlation_id')
        user_id = task.request.get('user_id')
        tenant_id = task.request.get('tenant_id')
        
        # Set thread-local context
        thread = threading.current_thread()
        thread.correlation_id = correlation_id or str(uuid.uuid4())
        if user_id:
            thread.user_id = user_id
        if tenant_id:
            thread.tenant_id = tenant_id
        
        # Log task start
        logger = ThreatCompassLogger('celery.task')
        logger.info(
            f"Task started: {task.name}",
            task_id=task_id,
            task_name=task.name,
            task_args=str(args)[:200] if args else None,
            task_kwargs=str(kwargs)[:200] if kwargs else None
        )
    
    @task_postrun.connect
    def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, state=None, **kwds):
        """Clean up and log after task execution."""
        logger = ThreatCompassLogger('celery.task')
        logger.info(
            f"Task completed: {task.name}",
            task_id=task_id,
            task_name=task.name,
            task_state=state,
            task_result=str(retval)[:200] if retval else None
        )
        
        # Clean up thread-local context
        thread = threading.current_thread()
        for attr in ['correlation_id', 'user_id', 'tenant_id']:
            if hasattr(thread, attr):
                delattr(thread, attr)


# Usage examples and helper functions
def log_performance_metric(operation_name, duration, success=True, **metadata):
    """Log performance metrics in a structured way."""
    logger = ThreatCompassLogger('performance')
    
    logger.info(
        f"Performance metric: {operation_name}",
        operation=operation_name,
        duration=duration,
        success=success,
        **metadata
    )


def log_business_event(event_name, **event_data):
    """Log business events for analytics."""
    logger = ThreatCompassLogger('business_events')
    
    logger.info(
        f"Business event: {event_name}",
        event_type=event_name,
        **event_data
    )


def log_security_event(event_type, severity, **event_data):
    """Log security-related events."""
    logger = ThreatCompassLogger('security')
    
    log_level = logging.WARNING if severity in ['medium', 'high'] else logging.INFO
    
    logger._log(
        log_level,
        f"Security event: {event_type}",
        event_type=event_type,
        severity=severity,
        **event_data
    )


# Example usage in Flask routes
"""
# In your Flask routes:
from logging_config import ThreatCompassLogger, log_performance_metric, log_business_event

logger = ThreatCompassLogger(__name__)

@app.route('/api/v1/iocs', methods=['POST'])
@login_required
def create_ioc():
    start_time = time.time()
    
    try:
        # Your IOC creation logic here
        ioc = create_ioc_logic()
        
        # Log business event
        log_business_event(
            'ioc_created',
            ioc_type=ioc.type,
            ioc_source=ioc.source,
            user_id=current_user.id,
            tenant_id=current_user.tenant_id
        )
        
        # Log performance metric
        duration = time.time() - start_time
        log_performance_metric(
            'ioc_creation',
            duration=duration * 1000,  # milliseconds
            success=True,
            ioc_type=ioc.type
        )
        
        logger.info(
            "IOC created successfully",
            ioc_id=ioc.id,
            ioc_type=ioc.type,
            duration=duration * 1000
        )
        
        return jsonify({"status": "success", "id": ioc.id})
        
    except Exception as e:
        duration = time.time() - start_time
        log_performance_metric(
            'ioc_creation',
            duration=duration * 1000,
            success=False,
            error_type=type(e).__name__
        )
        
        logger.error(
            "IOC creation failed",
            error_message=str(e),
            error_type=type(e).__name__,
            duration=duration * 1000
        )
        
        raise
"""