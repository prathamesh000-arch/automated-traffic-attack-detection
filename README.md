# TrafficGuard — Automated DDoS & Flash Crowd Detection

Full-stack academic prototype:
- Flask + Flask-SocketIO backend
- React/Vite admin dashboard
- Rolling real-time HTTP request monitoring
- CIC-DDoS2019 CSV preparation pipeline
- Random Forest model training
- Socket.IO live charts and alerts
- Token-protected temporary IP block/unblock
- Per-IP token-bucket rate limiting

## Important dataset limitation

The official CIC-DDoS2019 benchmark contains benign and multiple DDoS traffic types, but it is a flow-level network dataset, not a live HTTP request log. It does **not** provide a dedicated, trustworthy Flash Crowd label. This project maps its flow windows into Normal vs DDoS for model training. Flash Crowd is currently a separate high-diversity traffic heuristic. To claim ML-based three-class detection, collect or obtain a separately labelled Flash Crowd dataset and train on all three classes.

Official dataset: https://www.unb.ca/cic/datasets/ddos-2019.html
Dataset paper: Sharafaldin et al., “Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy,” IEEE ICCST, 2019, DOI: 10.1109/CCST.2019.8888419.

## 1. Backend setup (Windows PowerShell)

```powershell
cd backend
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:ADMIN_TOKEN="make-a-long-random-secret"
```

## 2. Prepare the real dataset

Download CIC-DDoS2019 CSV files from the official CIC page and extract them, for example to `backend/data/CICDDoS2019/`.

```powershell
python prepare_cicddos.py --input .\data\CICDDoS2019 --output traffic_windows.csv
```

The converter expects CICFlowMeter columns including `Timestamp`, `Source IP`, `Flow Bytes/s`, and `Label`. It aggregates 10-second windows. Some official mirrors/files may not contain benign flows. The script will stop if it cannot find both Normal/Benign and DDoS windows; add a suitable benign capture rather than relabelling attack data as benign.

## 3. Train model

```powershell
python train_model.py --data traffic_windows.csv --output traffic_model.joblib
```

For research-quality evaluation, split by capture/day or source environment, not just random rows. Report precision, recall, F1-score, confusion matrix, false-positive rate and latency. Avoid claiming real deployment accuracy from one random split.

## 4. Run backend

Keep the model file in the `backend` directory.

```powershell
python app.py
```

Backend: `http://127.0.0.1:5000`
Health: `http://127.0.0.1:5000/health`

Requests to ordinary Flask routes are monitored. `/api/*`, `/`, and `/health` are excluded from traffic statistics.

## 5. Run React dashboard

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite local URL, normally `http://127.0.0.1:5173`.

Enter the same `ADMIN_TOKEN` value in the dashboard to use administrator IP controls.

## 6. Test monitoring

Open the dashboard and browse to `http://127.0.0.1:5000/health` or add a simple route to `app.py` for test traffic. The dashboard receives Socket.IO traffic updates and alerts.

Admin API:
- `POST /api/admin/block` JSON `{"ip":"203.0.113.10","seconds":300}`
- `POST /api/admin/unblock` JSON `{"ip":"203.0.113.10"}`
- `GET /api/admin/blocked`

Send header `X-Admin-Token: <your token>`.

## Safety and deployment limitations

- IP blocking is enforced inside this Flask app process only. It is not an OS firewall or network-edge block.
- The app uses in-memory counters and blocklists; they reset on restart and are not suitable for multi-worker production deployments.
- Do not trust client-supplied `X-Forwarded-For`. If deploying behind a reverse proxy, configure trusted proxy handling carefully.
- Use HTTPS, strong secrets, authentication/authorization, audit logs, persistent storage, allowlists, block expiry, rollback, and a human approval process before production deployment.
- Do not expose the development server to the public internet. Test only on systems and traffic you own or are authorized to monitor.
- The dashboard uses a permissive local development setup only; tighten CORS and authentication before deployment.
