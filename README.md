# Network Monitor (Router)

This project contains a small Python backend (FastAPI) and a Vue 3 frontend (Vite) configured to monitor groups of IPs and block them by group name.

Structure
- `backend/`: FastAPI app (`app.py`) and `data.json` with groups. Run with Uvicorn.
- `frontend/TMA_router_frontend`: Vue 3 + Vite project (add Vuetify) and the Monitor component.

Quick start (development)

1. Backend (Python)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app:app --reload --host 0.0.0.0 --port 3000
```

2. Frontend

```bash
cd frontend/TMA_router_frontend
# install dependencies (run once)
npm install
# start dev server
npm run dev
```

Notes
- Blocking IPs uses `iptables` via subprocess. To actually modify iptables you must run the backend with root privileges (or run the specific commands yourself). If `iptables` isn't available or the process lacks permission, the server will simulate the block and save the IPs into `backend/data.json` under `blocked`.
- The frontend proxies `/api` to `http://localhost:3000` during development (check `vite.config.ts`).# TMA_lab
