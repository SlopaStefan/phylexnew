# Gunicorn configuration for Azure App Service
# This file is used when deploying to Azure

import multiprocessing
import os

# Server socket
bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
backlog = 2048

# Worker processes
workers = 1
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging
accesslog = '-'  # stdout
errorlog = '-'   # stderr
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'phylex'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (Azure handles this)
forwarded_allow_ips = '*'
proxy_allow_ips = '*'
def on_starting(server):
    import logging
    # Force the Azure SDK and underlying connection libraries to only report critical errors
    logging.getLogger('azure').setLevel(logging.WARNING)
    logging.getLogger('azure.monitor').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
