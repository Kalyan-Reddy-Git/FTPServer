"""
gunicorn.conf.py
Production Gunicorn configuration for Render deployment.
Course: Computer Networks and Ethical Hacking
"""

import os

# Render injects the PORT environment variable dynamically (e.g. 10000)
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"

# Worker processes
workers = int(os.environ.get("WEB_CONCURRENCY", 2))

# Allow sufficient time for file uploads and downloads
timeout = 120
keepalive = 5

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
