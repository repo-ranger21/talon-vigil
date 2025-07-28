from celery import Celery
from flask import Flask

def make_celery(app: Flask) -> Celery:
    """
    Creates and configures a Celery instance that is integrated
    with the Flask application context.
    """
    celery = Celery(
        app.import_name,
        broker='redis://localhost:6379/0',
        backend='redis://localhost:6379/0'
    )

    # Load the rest of the config from celeryconfig.py
    celery.config_from_object('celeryconfig')

    class ContextTask(celery.Task):
        abstract = True
        
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery