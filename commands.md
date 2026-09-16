### Virtual environment activation (if not activated automatically)
```
.myapp\Scripts\activate
```

### running the backend service
```
cd .\Server
uvicorn main:app --reload
```

### running the frontend service
```
cd .\client
npm run dev
```