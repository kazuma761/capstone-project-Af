# Cyber Detection

A full-stack threat detection dashboard. It scans URLs, files, PDFs, images and messages for threats, watches your Downloads folder, and flags running processes that behave like ransomware or cryptominers. It also includes an AI assistant for security questions.

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Zustand, Chart.js
- **Backend:** FastAPI, Prisma (Python client), MongoDB, WebSockets
- **Integrations:** VirusTotal, Google Safe Browsing, ClamAV, Groq (LLM)

## Features

| Feature | What it does |
| --- | --- |
| **URL scanning** | Checks a URL against Google Safe Browsing and VirusTotal, inspects its domain and SSL certificate, and shows a per-vendor verdict table. |
| **File and PDF scanning** | Scans uploads with ClamAV and checks their hash on VirusTotal. |
| **Image scanning** | Reads image metadata and runs an LSB analysis to detect hidden (steganographic) data. |
| **Message scanning** | Flags scam and phishing messages using rules plus an LLM (Groq). |
| **Downloads monitor** | Watches `~/Downloads` for new files, scans them automatically and pushes results to the browser over WebSockets. |
| **Behavioral monitor (APSA)** | Scores each running process on encryption activity, file-access anomalies, network anomalies and CPU abuse. It compares these against a learned baseline (Mahalanobis distance) and sorts processes into `CLEAN`, `MONITOR`, `SUSPICIOUS` or `ALERT`. Processes can be killed from the UI. |
| **Security chatbot** | An in-app assistant powered by Groq. |
| **Auth and history** | JWT sign-up and login. Scans and alerts are stored per user. |

## Project structure

```
.
├── client/                 # React + Vite frontend
│   ├── src/
│   │   ├── pages/          # Dashboard, Scanner, Downloads, BehavioralMonitor, Login, Signup
│   │   ├── components/     # Chatbot, ProcessTable, RiskGauge, AnalysisModal, ...
│   │   ├── hooks/          # useWebSocket, useBehavioralMonitor
│   │   ├── services/       # axios API client, WebSocket service
│   │   ├── store/          # Zustand auth store
│   │   └── config.ts       # API_URL / WS_URL from env vars
│   └── vercel.json
├── Server/                 # FastAPI backend
│   ├── main.py             # App entry, CORS, routers, /ws/{client_id}
│   ├── config.py           # Settings loaded from .env
│   ├── api/                # auth, scan, monitor, downloads, chatbot, behavioral
│   ├── services/           # Scanners, folder monitor, behavioral monitor, chatbot
│   └── prisma/schema.prisma
└── vercel.json             # Frontend deploy config (repo root)
```

## Getting started

### Prerequisites

- Node.js 18 or later
- Python 3.11 or later
- A MongoDB database (MongoDB Atlas works). Prisma needs MongoDB to run as a replica set, which Atlas does by default.
- API keys for [VirusTotal](https://www.virustotal.com/), [Google Safe Browsing](https://developers.google.com/safe-browsing) and [Groq](https://console.groq.com/)
- [ClamAV](https://www.clamav.net/) for file scanning: either `clamd` listening on `127.0.0.1:3310` (or a Unix socket), or `clamscan` on your `PATH`

### 1. Backend

```bash
cd Server
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # then fill in the values
prisma generate
prisma db push                   # sync the schema to MongoDB

uvicorn main:app --reload
```

The API runs at `http://localhost:8000`. Interactive docs are at `http://localhost:8000/docs`.

### 2. Frontend

```bash
cd client
npm install
cp .env.example .env             # set VITE_API_URL if the backend isn't on localhost:8000
npm run dev
```

Open `http://localhost:5173`.

## Environment variables

### `Server/.env`

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | MongoDB connection string |
| `JWT_SECRET` | Secret used to sign auth tokens |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `GROQ_API_KEY` | Groq API key for the chatbot and message scanner |
| `CORS_ORIGINS` | Comma-separated frontend origins allowed to call the API (default: `http://localhost:5173,http://localhost:3000`) |

> **Note:** The chatbot and message scanner read `GROQ_API_KEY` from the process environment. The `.env` file is not loaded into that environment, so also export the key in your shell (`export GROQ_API_KEY=...`) before starting `uvicorn`.

### `client/.env`

| Variable | Description |
| --- | --- |
| `VITE_API_URL` | Public URL of the backend, e.g. `https://api.example.com` (default: `http://localhost:8000`) |
| `VITE_WS_URL` | Optional WebSocket URL. If unset, it is built from `VITE_API_URL` (`http` → `ws`). |

## API overview

All routes are prefixed with `/api`. Everything except sign-up and login requires `Authorization: Bearer <token>`.

| Area | Endpoints |
| --- | --- |
| Auth | `POST /auth/signup`, `POST /auth/login` |
| Scan | `POST /scan/url`, `/scan/pdf`, `/scan/file`, `/scan/image`, `/scan/message` · `GET /scan/history`, `/scan/{scan_id}` |
| Folder monitor | `POST /monitor/start`, `/monitor/stop` · `GET /monitor/status` |
| Downloads | `GET /downloads/list` · `POST /downloads/scan` |
| Behavioral | `POST /behavioral/start`, `/behavioral/stop`, `/behavioral/kill/{pid}` · `GET /behavioral/status`, `/processes`, `/alerts`, `/stats`, `/baseline/{process_name}` |
| Chatbot | `POST /chatbot/chat` |
| Real-time | `WS /ws/{client_id}` (scan progress, folder events and behavioral updates) |

## Deployment

### Frontend on Vercel

1. Import the repository into Vercel. The root `vercel.json` builds `client/`, so you can leave **Root Directory** as the repo root. Setting it to `client` also works, because `client/vercel.json` covers that case.
2. Under **Settings → Environment Variables**, set `VITE_API_URL` to your deployed backend URL.
3. Deploy. `VITE_*` values are baked in at build time, so redeploy whenever you change them.

Both configs send all page routes to `index.html`, so refreshing on a page like `/dashboard` works.

### Backend

The backend needs long-lived WebSockets, file-system watching, local process inspection and ClamAV, so it **cannot run on Vercel's serverless functions**. Host it on a platform that runs a persistent server, such as Render, Railway, Fly.io or a VM:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Set the environment variables above, and add your Vercel URL to `CORS_ORIGINS`, for example:

```
CORS_ORIGINS=https://your-app.vercel.app
```

> The Downloads monitor and the behavioral monitor inspect the machine the **backend** runs on. To protect your own computer, run the backend locally.

## Limitations

- In the URL scan's vendor table, only the Google Safe Browsing and VirusTotal rows come from live lookups. The other vendor rows are generated from the overall verdict so the table is always filled in.
- File scanning uses the ClamAV daemon when it's reachable. Otherwise it falls back to the `clamscan` command, which must be on your `PATH` (or in `clamav/` at the repo root on Windows).
- Killing processes and reading process details may require elevated privileges, depending on the OS.
