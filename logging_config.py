"""Logging configuration for TalonVigil application."""

import os
import logging
from logging.config import dictConfig
from pathlib import Path

def setup_logging():
    """Initialize logging configuration"""
    # Create logs directory in project root
    logs_dir = Path(__file__).parent / 'logs'
    logs_dir.mkdir(exist_ok=True)

    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            },
        },
        'handlers': {
            'celery': {
                'level': 'INFO',
                'class': 'logging.FileHandler',
                'filename': str(logs_dir / 'celery.log'),
                'formatter': 'standard',
            },
            'flask': {
                'level': 'INFO',
                'class': 'logging.FileHandler',
                'filename': str(logs_dir / 'flask.log'),
                'formatter': 'standard',
            }
        },
        'loggers': {
            'celery': {
                'handlers': ['celery'],
                'level': 'INFO',
                'propagate': True
            },
            'flask': {
                'handlers': ['flask'],
                'level': 'INFO',
                'propagate': True
            }
        }
    }

    # Apply configuration
    dictConfig(config)
    
    # Create a test log entry to verify logging is working
    logger = logging.getLogger('celery')
    logger.info('Logging system initialized')

if __name__ == '__main__':
    setup_logging()
