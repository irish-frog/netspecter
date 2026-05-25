import json
import os
from pathlib import Path


CONFIG_PATH = Path(os.environ.get("NETSPECTER_CONFIG_ROOT", "/etc/netspecter")) / "config.json"

host = "0.0.0.0"
port = 5050
try:
    app_settings = json.loads(CONFIG_PATH.read_text())
    host = str(app_settings.get("web_host", host) or host)
    port = int(app_settings.get("web_port", port) or port)
except Exception:
    pass

bind = f"{host}:{port}"
workers = 2
preload_app = True
accesslog = "-"
errorlog = "-"
capture_output = True
timeout = 30
graceful_timeout = 30
