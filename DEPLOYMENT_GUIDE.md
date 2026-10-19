# 🚀 Cloud Deployment Guide - AI Phishing Detector

This project is a full-stack AI web application consisting of:
- **Python Flask Backend**: Serves API endpoints, Jinja2 web dashboard, and SQLite database.
- **Deep Learning Model**: PyTorch + Hugging Face Transformers (`ealvaradob/bert-finetuned-phishing`) requiring ~600MB–800MB RAM.
- **Background Mail Watcher**: Automated IMAP/Gmail inbox scanning daemon.

---

## ⚠️ Why Netlify Shows "No Deploys" or Fails

Netlify is engineered for **static websites and serverless functions** (HTML/CSS/JS, React, Vue, Next.js).
- **RAM Limits**: Netlify serverless functions have strict memory and size limits (max 250MB uncompressed). PyTorch alone is >500MB to 2.5GB.
- **Execution Limits**: Netlify functions terminate after 10–26 seconds and cannot run persistent background workers (like email inbox polling) or maintain long-lived SQLite database connections.

To host this AI system online, use an ML-ready or containerized platform below.

---

## 🏆 Option 1: Hugging Face Spaces (Recommended — 100% Free, 16 GB RAM)

Hugging Face Spaces is the premier free platform for Machine Learning applications:
- **Free Specs**: 2 vCPUs, **16 GB RAM**, 50 GB storage (never crashes from BERT out-of-memory errors).
- **Public URL**: Instant HTTPS link (`https://<username>-phishshield.hf.space`).

### Steps to Deploy:
1. Create a free account at [huggingface.co](https://huggingface.co).
2. Go to **Spaces** -> Click **Create new Space**.
3. Set:
   - **Space name**: `ai-phishing-detector`
   - **License**: `mit` or `apache-2.0`
   - **Space SDK**: Select **Docker** -> **Blank**.
4. Push or upload this repository's files (including `Dockerfile`, `app.py`, `templates/`, `static/`, `requirements.txt`).
5. Under Space **Settings** -> **Variables and secrets**, add any environment variables from `.env.example`:
   - `EMAIL_ACCOUNT` (optional, for auto-scanning)
   - `EMAIL_APP_PASSWORD` (optional)
   - `ENABLE_DESKTOP_NOTIFICATIONS`: `false`
6. Hugging Face will automatically build the Docker image using our optimized CPU PyTorch cache and launch your live dashboard!

---

## 🥈 Option 2: Render.com (Web Service)

Render provides free and paid managed web hosting directly from GitHub.

### Steps to Deploy:
1. Push this project to a GitHub repository:
   ```bash
   git init
   git add .
   git commit -m "Initial commit for production"
   git remote add origin https://github.com/<your-username>/<your-repo-name>.git
   git branch -M main
   git push -u origin main
   ```
2. Go to [render.com](https://render.com) and log in with GitHub.
3. Click **New +** -> **Web Service**.
4. Connect your GitHub repository.
5. Configure:
   - **Runtime**: `Python`
   - **Build Command**:
     ```bash
     pip install --upgrade pip && pip install torch>=2.2.0 --index-url https://download.pytorch.org/whl/cpu && pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     gunicorn --bind 0.0.0.0:$PORT --timeout 180 --workers 1 --threads 4 app:app
     ```
6. Add Environment Variables under **Advanced**:
   - `ENABLE_DESKTOP_NOTIFICATIONS`: `false`
   - `FLASK_DEBUG`: `false`
   - `SECRET_KEY`: `<generate-a-random-string>`
   - `EMAIL_ACCOUNT`: `<your-email>` (optional)
   - `EMAIL_APP_PASSWORD`: `<your-app-password>` (optional)
7. Click **Create Web Service**.

> **Note on Free Tier**: Render's free tier has a 512MB RAM limit. If the BERT model runs out of memory during inference on the free tier, consider upgrading to the Starter plan ($7/mo with 2GB RAM) or using **Hugging Face Spaces** for free 16GB RAM.

---

## 🥉 Option 3: Railway.app / Fly.io (Docker Container)

Railway offers easy 1-click Docker deployment with higher memory allocations.

### Steps for Railway:
1. Go to [railway.app](https://railway.app) and sign in.
2. Click **New Project** -> **Deploy from GitHub repo**.
3. Select this repository. Railway will detect the `Dockerfile` automatically.
4. Go to **Variables** tab and add:
   - `PORT`: `7860` (or leave default)
   - `ENABLE_DESKTOP_NOTIFICATIONS`: `false`
5. Go to **Settings** -> **Networking** -> Click **Generate Domain**.
6. Railway will build the container and provide your live HTTPS domain!

---

## 📦 What About Keeping Netlify for the Frontend?

If you specifically want a Netlify URL:
1. Host the Flask + PyTorch API backend on **Hugging Face Spaces** or **Render**.
2. Deploy a lightweight static HTML/JS frontend to **Netlify** that points API calls (`fetch("https://your-backend.hf.space/api/analyze", ...)`) to your hosted backend.
