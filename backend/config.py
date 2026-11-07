import os

# Keep this service on localhost during development.
HOST = "127.0.0.1"
PORT = int(os.getenv("PORT", "5000"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "change-this-admin-token")
MODEL_PATH = os.getenv("MODEL_PATH", "traffic_model.joblib")

WINDOW_SECONDS = 10
ALERT_COOLDOWN_SECONDS = 20
DDOS_CONFIDENCE_THRESHOLD = 0.85
AUTO_BLOCK_SECONDS = 300
PER_IP_RATE = 15          # requests per second, token-bucket refill
PER_IP_BURST = 30
MAX_BODY_SAMPLE_BYTES = 2048
