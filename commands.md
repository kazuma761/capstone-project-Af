### Backend setup (first time)
```
cd Server
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then fill in real values
prisma generate
```

### Running the backend service
```
cd Server
uvicorn main:app --reload
```

### Running the frontend service
```
cd client
npm install
cp .env.example .env        # optional; defaults to http://localhost:8000
npm run dev
```

### Deploying the frontend to Vercel
Import the repo in Vercel and set **Root Directory** to `client`
(settings come from `client/vercel.json`). Add the env var
`VITE_API_URL=https://<your-backend-host>` and set the backend's
`CORS_ORIGINS` to include your Vercel URL.
