# sentry_integration.py - Sentry Error Tracking Integration for ThreatCompass

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.boto3sqs import Boto3SqsIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
import logging
from flask import Flask, g, request
from flask_login import current_user
import os


def setup_sentry(app: Flask):
    """Configure Sentry error tracking for ThreatCompass."""
    
    sentry_dsn = app.config.get('SENTRY_DSN') or os.environ.get('SENTRY_DSN')
    environment = app.config.get('ENVIRONMENT', 'production')
    release = app.config.get('APP_VERSION') or os.environ.get('GIT_SHA', 'unknown')
    
    if not sentry_dsn:
        app.logger.warning("Sentry DSN not configured. Error tracking disabled.")
        return
    
    # Configure logging integration
    sentry_logging = LoggingIntegration(
        level=logging.INFO,        # Capture info and above as breadcrumbs
        event_level=logging.ERROR  # Send errors and above as events
    )
    
    # Initialize Sentry
    sentry_sdk.init(
        dsn=sentry_dsn,
        environment=environment,
        release=release,
        
        # Integrations
        integrations=[
            FlaskIntegration(
                transaction_style='endpoint'
            ),
            SqlalchemyIntegration(),
            CeleryIntegration(),
            RedisIntegration(),
            Boto3SqsIntegration(),
            sentry_logging,
        ],
        
        # Performance monitoring
        traces_sample_rate=0.1,  # Capture 10% of transactions for performance monitoring
        
        # Error sampling
        sample_rate=1.0,  # Capture 100% of errors
        
        # Additional configuration
        attach_stacktrace=True,
        send_default_pii=False,  # Don't send PII for privacy
        
        # Custom configuration
        before_send=before_send_filter,
        before_send_transaction=before_send_transaction_filter,
    )
    
    # Set up Flask hooks for additional context
    setup_flask_sentry_context(app)
    
    app.logger.info(f"Sentry initialized for environment: {environment}, release: {release}")


def before_send_filter(event, hint):
    """Filter and enhance events before sending to Sentry."""
    
    # Don't send certain types of errors to reduce noise
    if 'exc_info' in hint:
        exc_type, exc_value, tb = hint['exc_info']
        
        # Filter out common non-critical errors
        if exc_type.__name__ in [
            'ConnectionError',
            'Timeout',
            'BrokenPipeError',
            'ConnectionResetError'
        ]:
            # Only send if it's happening frequently
            if not should_send_connection_error():
                return None
    
    # Enhance event with additional context
    if event.get('request'):
        # Add custom headers for correlation
        if hasattr(g, 'correlation_id'):
            event.setdefault('tags', {})['correlation_id'] = g.correlation_id
        
        # Add tenant context
        if hasattr(g, 'tenant_id'):
            event.setdefault('tags', {})['tenant_id'] = str(g.tenant_id)
    
    # Add application-specific context
    event.setdefault('extra', {}).update({
        'app_component': 'threatcompass',
        'deployment_region': os.environ.get('AWS_REGION', 'unknown')
    })
    
    return event


def before_send_transaction_filter(event, hint):
    """Filter performance transactions before sending to Sentry."""
    
    # Don't track health check requests
    if event.get('transaction', '').endswith('/health'):
        return None
    
    # Don't track static file requests
    if '/static/' in event.get('transaction', ''):
        return None
    
    return event


def should_send_connection_error():
    """Determine if connection errors should be sent to Sentry."""
    # Implement rate limiting logic here
    # For example, only send 1 out of every 10 connection errors
    import random
    return random.random() < 0.1


def setup_flask_sentry_context(app: Flask):
    """Set up Flask request hooks to add context to Sentry."""
    
    @app.before_request
    def set_sentry_context():
        """Add request context to Sentry scope."""
        with sentry_sdk.configure_scope() as scope:
            # Add correlation ID
            if hasattr(g, 'correlation_id'):
                scope.set_tag('correlation_id', g.correlation_id)
            
            # Add user context
            if current_user.is_authenticated:
                scope.set_user({
                    'id': str(current_user.id),
                    'username': current_user.username,
                    'email': current_user.email,
                    'tenant_id': str(getattr(current_user, 'tenant_id', 'unknown'))
                })
                scope.set_tag('tenant_id', str(current_user.tenant_id))
            
            # Add request context
            scope.set_context('request', {
                'method': request.method,
                'url': request.url,
                'endpoint': request.endpoint,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', '')[:200]
            })
    
    @app.after_request
    def clear_sentry_context(response):
        """Clean up Sentry context after request."""
        with sentry_sdk.configure_scope() as scope:
            # Add response context
            scope.set_context('response', {
                'status_code': response.status_code,
                'content_length': response.content_length
            })
        
        return response


def setup_celery_sentry_context(celery_app):
    """Set up Celery task hooks to add context to Sentry."""
    
    from celery.signals import before_task_publish, task_prerun, task_postrun, task_failure
    
    @task_prerun.connect
    def celery_task_prerun(sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
        """Add task context to Sentry before task execution."""
        with sentry_sdk.configure_scope() as scope:
            scope.set_tag('celery_task', task.name)
            scope.set_tag('task_id', task_id)
            
            # Add correlation context from task headers
            correlation_id = task.request.get('correlation_id')
            if correlation_id:
                scope.set_tag('correlation_id', correlation_id)
            
            user_id = task.request.get('user_id')
            if user_id:
                scope.set_tag('user_id', str(user_id))
            
            tenant_id = task.request.get('tenant_id')
            if tenant_id:
                scope.set_tag('tenant_id', str(tenant_id))
            
            scope.set_context('celery_task', {
                'name': task.name,
                'id': task_id,
                'args': str(args)[:200] if args else None,
                'kwargs': str(kwargs)[:200] if kwargs else None,
                'retries': task.request.retries,
                'eta': task.request.eta
            })
    
    @task_failure.connect
    def celery_task_failure(sender=None, task_id=None, exception=None, traceback=None, einfo=None, **kwds):
        """Capture task failures in Sentry."""
        with sentry_sdk.configure_scope() as scope:
            scope.set_tag('celery_task_failed', sender.name)
            scope.set_context('task_failure', {
                'task_name': sender.name,
                'task_id': task_id,
                'exception_type': type(exception).__name__ if exception else 'Unknown',
                'retries': sender.request.retries if hasattr(sender, 'request') else 0
            })
        
        # Capture the exception
        sentry_sdk.capture_exception(exception)


class SentryThreatCompassLogger:
    """Enhanced logger that integrates with Sentry for structured error reporting."""
    
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        self.name = name
    
    def capture_business_error(self, error_type, message, **context):
        """Capture business logic errors with additional context."""
        with sentry_sdk.configure_scope() as scope:
            scope.set_tag('error_category', 'business_logic')
            scope.set_tag('business_error_type', error_type)
            scope.set_context('business_context', context)
        
        # Log the error
        self.logger.error(f"Business Error - {error_type}: {message}", extra=context)
        
        # Capture in Sentry
        sentry_sdk.capture_message(
            f"Business Error: {message}",
            level='error',
            extras=context
        )
    
    def capture_security_incident(self, incident_type, severity, message, **context):
        """Capture security-related incidents."""
        with sentry_sdk.configure_scope() as scope:
            scope.set_tag('error_category', 'security')
            scope.set_tag('security_incident_type', incident_type)
            scope.set_tag('severity', severity)
            scope.set_context('security_context', context)
        
        log_level = 'critical' if severity == 'high' else 'error'
        self.logger.log(
            getattr(logging, log_level.upper()),
            f"Security Incident - {incident_type}: {message}",
            extra=context
        )
        
        sentry_sdk.capture_message(
            f"Security Incident: {message}",
            level=log_level,
            extras=context
        )
    
    def capture_performance_issue(self, operation, duration_ms, threshold_ms, **context):
        """Capture performance issues."""
        if duration_ms <= threshold_ms:
            return
        
        with sentry_sdk.configure_scope() as scope:
            scope.set_tag('error_category', 'performance')
            scope.set_tag('slow_operation', operation)
            scope.set_context('performance_context', {
                'operation': operation,
                'duration_ms': duration_ms,
                'threshold_ms':