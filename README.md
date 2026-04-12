# SafeWatch Backend

## Deployment on Render

### Environment Variables (set in Render dashboard):
```
MONGO_URL=mongodb+srv://luisgeronimofral202005_db_user:8ncawJydRjeCiblE@cluster0.zdvwlhf.mongodb.net/?appName=Cluster0
DB_NAME=safewatch
JWT_SECRET=safewatch-secret-key-2024-production
CORS_ORIGINS=*
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=luisgeronimofral202005@gmail.com
MAIL_PASSWORD=dywh bffk mavh fdha
MAIL_FROM_ADDRESS=luisgeronimofral202005@gmail.com
```

### Run locally:
```bash
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8001
```
