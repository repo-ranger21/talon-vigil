#!/bin/bash

# Function to cleanup background processes on exit
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$REDIS_PID" ]; then
        kill $REDIS_PID 2>/dev/null
    fi
    if [ ! -z "$CELERY_PID" ]; then
        kill $CELERY_PID 2>/dev/null
    fi
    if [ ! -z "$CELERY_BEAT_PID" ]; then
        kill $CELERY_BEAT_PID 2>/dev/null
    fi
    exit
}

# Set up cleanup on script exit
trap cleanup EXIT INT TERM

# Check if Redis is running
redis-cli ping > /dev/null 2>&1
REDIS_RUNNING=$?

if [ $REDIS_RUNNING -ne 0 ]; then
    echo "Starting Redis server..."
    redis-server --daemonize yes
    sleep 2
    
    # Check if Redis started successfully
    redis-cli ping > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Failed to start Redis server. Please check if Redis is installed correctly."
        exit 1
    fi
fi

# Ensure virtual environment is active if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Start Celery worker with automatic reload and logging
echo "Starting Celery worker..."
celery -A app.celery worker \
    -l INFO \
    --pool=solo \
    --logfile="$PWD/logs/celery.log" \
    --pidfile="$PWD/logs/celery.pid" &
CELERY_PID=$!

# Wait for Celery worker to initialize
sleep 2

# Check if Celery worker started successfully
if ! ps -p $CELERY_PID > /dev/null; then
    echo "Failed to start Celery worker. Please check your Celery configuration."
    exit 1
fi

echo "Celery worker is running with PID: $CELERY_PID"

# Start Celery Beat scheduler with logging
echo "Starting Celery Beat scheduler..."
celery -A app.celery beat \
    -l INFO \
    --scheduler redbeat.RedBeatScheduler \
    --logfile="$PWD/logs/celerybeat.log" \
    --pidfile="$PWD/logs/celerybeat.pid" &
CELERY_BEAT_PID=$!

# Wait for Celery Beat to initialize
sleep 2

# Check if Celery Beat started successfully
if ! ps -p $CELERY_BEAT_PID > /dev/null; then
    echo "Failed to start Celery Beat. Please check your Celery configuration."
    kill $CELERY_PID  # Clean up worker since beat failed
    exit 1
fi

echo "Celery Beat is running with PID: $CELERY_BEAT_PID"

# Start Flask development server
echo "Starting Flask development server..."
FLASK_ENV=development FLASK_DEBUG=1 flask run
