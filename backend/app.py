import os
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

import joblib
import pandas as pd
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_socketio import SocketIO

from config import (
    HOST, PORT, ADMIN_TOKEN, MODEL_PATH, WINDOW_SECONDS,
    ALERT_COOLDOWN_SECONDS, DDOS_CONFIDENCE_THRESHOLD,
    AUTO_BLOCK_SECONDS, PER_IP_RATE, PER_IP_BURST
)

app = Flask(__name__)

CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:5173",
            "http://127.0.0.1:5173"
        ]
    }
})

socketio = SocketIO(
    app,
    cors_allowed_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    async_mode="threading"
)

FEATURES = [
    "requests_per_sec", "unique_ips", "avg_inter_request_ms",
    "bytes_per_sec", "error_rate"
]

model = None
if os.path.exists(MODEL_PATH):
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]

lock = threading.RLock()
events = deque(maxlen=5000)
ip_hits = defaultdict(deque)
blocked_ips = {}       # ip -> expiry epoch
rate_buckets = {}      # ip -> (tokens, last_update)
alerts = deque(maxlen=100)
last_alert_time = {}
latest_snapshot = {
    "timestamp": None, "requests_per_sec": 0, "unique_ips": 0,
    "avg_inter_request_ms": 0, "bytes_per_sec": 0, "error_rate": 0,
    "classification": "Waiting for traffic", "confidence": 0,
    "total_requests": 0
}

def client_ip():
    # Do not trust X-Forwarded-For unless this app is behind a trusted proxy
    # configured to overwrite that header.
    return request.remote_addr or "unknown"

def is_blocked(ip):
    now = time.time()
    expiry = blocked_ips.get(ip)
    if expiry is None:
        return False
    if expiry <= now:
        blocked_ips.pop(ip, None)
        return False
    return True

def consume_token(ip):
    now = time.time()
    tokens, updated = rate_buckets.get(ip, (float(PER_IP_BURST), now))
    tokens = min(float(PER_IP_BURST), tokens + (now - updated) * PER_IP_RATE)
    if tokens < 1:
        rate_buckets[ip] = (tokens, now)
        return False
    rate_buckets[ip] = (tokens - 1, now)
    return True

def emit_alert(kind, message, severity="warning", ip=None):
    now = time.time()
    key = f"{kind}:{ip or 'global'}"
    if now - last_alert_time.get(key, 0) < ALERT_COOLDOWN_SECONDS:
        return
    last_alert_time[key] = now
    alert = {
        "id": f"{int(now * 1000)}-{len(alerts)}",
        "time": datetime.now(timezone.utc).isoformat(),
        "type": kind, "message": message, "severity": severity, "ip": ip
    }
    alerts.appendleft(alert)
    socketio.emit("alert", alert)

@app.before_request
def security_gate():
    ip = client_ip()
    g.client_ip = ip
    # Keep management endpoints usable even if a test client IP is blocked.
    if request.path.startswith("/api/admin") or request.path in ("/health", "/"):
        return None
    with lock:
        if is_blocked(ip):
            emit_alert("blocked_request", "Request rejected from blocked source", "high", ip)
            return jsonify({"error": "Temporarily blocked by traffic protection"}), 403
        if not consume_token(ip):
            emit_alert("rate_limit", "Per-IP request rate limit exceeded", "warning", ip)
            return jsonify({"error": "Rate limit exceeded"}), 429

@app.after_request
def observe_request(response):
    if request.path.startswith("/api/") or request.path in ("/health", "/"):
        return response
    ip = getattr(g, "client_ip", "unknown")
    now = time.time()
    size = request.content_length or 0
    with lock:
        events.append({
            "t": now, "ip": ip, "bytes": int(size),
            "error": 1 if response.status_code >= 400 else 0
        })
        ip_hits[ip].append(now)
        cutoff = now - 60
        while ip_hits[ip] and ip_hits[ip][0] < cutoff:
            ip_hits[ip].popleft()
    return response

def classify_window(rows, now):
    if not rows:
        return None
    duration = max(1.0, min(WINDOW_SECONDS, now - rows[0]["t"]))
    count = len(rows)
    unique_ips = len({r["ip"] for r in rows})
    intervals = []
    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r["ip"]].append(r["t"])
    for times in by_ip.values():
        times.sort()
        intervals.extend([(times[i] - times[i-1]) * 1000
                          for i in range(1, len(times))])
    avg_interval = sum(intervals) / len(intervals) if intervals else 1000.0
    bps = sum(r["bytes"] for r in rows) / duration
    error_rate = sum(r["error"] for r in rows) / count
    rps = count / duration
    features = {
        "requests_per_sec": rps,
        "unique_ips": unique_ips,
        "avg_inter_request_ms": avg_interval,
        "bytes_per_sec": bps,
        "error_rate": error_rate
    }

    classification = "Normal"
    confidence = 0.0
    if model is not None:
        frame = pd.DataFrame([[features[k] for k in FEATURES]], columns=FEATURES)
        probs = model.predict_proba(frame)[0]
        classes = list(model.classes_)
        best_idx = int(probs.argmax())
        model_label = str(classes[best_idx])
        confidence = float(probs[best_idx])
        classification = "DDoS" if model_label.lower() in ("ddos", "attack") else "Normal"
    else:
        # Explicit fallback only: this is a heuristic, not ML.
        classification = "DDoS" if rps > 100 and unique_ips < max(2, count * 0.1) else "Normal"

    # CIC-DDoS2019 does not contain a dedicated Flash Crowd label.
    # Treat high legitimate-looking diversity as a review/rate-limit signal.
    if classification == "Normal" and rps >= 20 and unique_ips >= max(5, count * 0.35):
        classification = "Flash Crowd"

    return {
        **features, "classification": classification,
        "confidence": round(confidence, 4),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_requests": count
    }

def monitor_loop():
    global latest_snapshot
    while True:
        now = time.time()
        with lock:
            cutoff = now - WINDOW_SECONDS
            while events and events[0]["t"] < cutoff:
                events.popleft()
            rows = list(events)
            snapshot = classify_window(rows, now)
            if snapshot:
                latest_snapshot = snapshot
                socketio.emit("traffic", snapshot)
                if snapshot["classification"] == "DDoS":
                    emit_alert("ddos_detected",
                               f"Possible DDoS traffic: {snapshot['requests_per_sec']:.1f} req/s",
                               "high")
                    # Only temporarily block a source that is individually noisy.
                    if model is not None and snapshot["confidence"] >= DDOS_CONFIDENCE_THRESHOLD:
                        for ip, hits in list(ip_hits.items()):
                            while hits and hits[0] < now - 10:
                                hits.popleft()
                            if len(hits) >= 30 and ip not in ("127.0.0.1", "::1", "unknown"):
                                blocked_ips[ip] = now + AUTO_BLOCK_SECONDS
                                emit_alert("temporary_ip_block",
                                           f"High-rate source temporarily blocked for {AUTO_BLOCK_SECONDS}s",
                                           "high", ip)
                elif snapshot["classification"] == "Flash Crowd":
                    emit_alert("flash_crowd",
                               "Traffic surge with broad source diversity; gentle per-IP limiting remains active",
                               "warning")
        socketio.sleep(1)

@app.get("/")
def home():
    return jsonify({"service": "Automated Traffic Attack Detection", "status": "running"})

@app.get("/health")
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None})

@app.get("/api/traffic/current")
def current_traffic():
    return jsonify(latest_snapshot)

@app.get("/api/traffic/history")
def traffic_history():
    # The UI keeps its own rolling chart from Socket.IO updates.
    return jsonify({"current": latest_snapshot})

@app.get("/api/alerts")
def get_alerts():
    return jsonify(list(alerts))

def require_admin():
    supplied = request.headers.get("X-Admin-Token", "")
    return bool(ADMIN_TOKEN) and supplied == ADMIN_TOKEN

@app.post("/api/admin/block")
def admin_block():
    if not require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()
    seconds = int(data.get("seconds", AUTO_BLOCK_SECONDS))
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "A valid IP address is required"}), 400
    if ip in ("127.0.0.1", "::1"):
        return jsonify({"error": "Refusing to block localhost"}), 400
    seconds = max(10, min(seconds, 3600))
    with lock:
        blocked_ips[ip] = time.time() + seconds
    emit_alert("admin_ip_block", f"Administrator blocked {ip} for {seconds}s", "high", ip)
    return jsonify({"status": "blocked", "ip": ip, "seconds": seconds})

@app.post("/api/admin/unblock")
def admin_unblock():
    if not require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()
    with lock:
        existed = blocked_ips.pop(ip, None) is not None
    return jsonify({"status": "unblocked" if existed else "not_found", "ip": ip})

@app.get("/test")
def test_traffic():
    return jsonify({
        "status": "success",
        "message": "Test traffic received"
    }), 200
    if not require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    now = time.time()
    with lock:
        active = [{"ip": ip, "expires_in": max(0, int(exp-now))}
                  for ip, exp in blocked_ips.items() if exp > now]
    return jsonify(active)

if __name__ == "__main__":
    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()
    print(f"Admin token configured: {'yes' if ADMIN_TOKEN else 'NO'}")
    socketio.run(app, host=HOST, port=PORT, debug=False, allow_unsafe_werkzeug=True)
