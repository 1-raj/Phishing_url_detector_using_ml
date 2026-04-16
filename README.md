# 🛡️ PhishGuard — Phishing URL Detection System
> ML-powered cybersecurity web app | Random Forest | Flask + Vercel + Render

---

## 📁 Project Structure

```
phishguard/
├── backend/                  ← Render pe deploy hoga
│   ├── app.py                ← Flask API
│   ├── requirements.txt      ← Python dependencies
│   ├── render.yaml           ← Render config
│   ├── best_model.pkl        ← Trained Random Forest
│   ├── scaler.pkl            ← StandardScaler
│   └── selected_features.pkl ← 30 feature names
│
└── frontend/                 ← Vercel pe deploy hoga
    ├── public/
    │   └── index.html        ← Complete UI
    └── vercel.json           ← Vercel routing config
```

---

## 🚀 Deployment Steps

### STEP 1 — GitHub pe push karo

```bash
cd phishguard
git init
git add .
git commit -m "PhishGuard v2.0 — initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/phishguard.git
git push -u origin main
```

---

### STEP 2 — Backend: Render pe deploy karo

1. **render.com** pe jao → "New Web Service"
2. GitHub repo connect karo
3. **Root Directory** set karo: `backend`
4. Settings:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
5. **Deploy** karo — URL milegi: `https://phishguard-api.onrender.com`

> ⚠️ Free tier pe pehli request slow hogi (cold start ~30s) — upgrade karo production ke liye

---

### STEP 3 — Frontend: API URL update karo

`frontend/public/index.html` mein yeh line update karo:

```javascript
// Line ~300
const API_BASE = "https://phishguard-api.onrender.com";  // apna Render URL
```

---

### STEP 4 — Frontend: Vercel pe deploy karo

```bash
npm i -g vercel
cd frontend
vercel --prod
```

Ya phir:
1. **vercel.com** pe jao → "New Project"
2. GitHub repo connect karo
3. **Root Directory**: `frontend`
4. Deploy karo

---

## 🧪 Local Testing

```bash
cd backend
pip install -r requirements.txt
python app.py
# Server: http://localhost:5000
```

Test with curl:
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

---

## 🔌 API Reference

### `POST /api/analyze`

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "https://example.com",
  "prediction": "legitimate",
  "is_safe": true,
  "confidence": 94.2,
  "risk_score": 5.8,
  "suspicious_flags": [],
  "features": {
    "url_features":    { "URLLength": 23, "IsHTTPS": 1, ... },
    "html_features":   { "HasTitle": 1, "IsResponsive": 1, ... },
    "domain_features": { "HasCopyrightInfo": 1, ... }
  }
}
```

---

## 🛠️ Tech Stack

| Layer     | Technology         |
|-----------|--------------------|
| ML Model  | Random Forest (sklearn) |
| Backend   | Flask + Gunicorn   |
| Hosting   | Render (backend)   |
| Frontend  | Vanilla HTML/CSS/JS |
| Hosting   | Vercel (frontend)  |
| Features  | BeautifulSoup4, requests |

---

## ⚠️ Notes

- `best_model.pkl` trained on scikit-learn 1.7.2 — same version use karo
- SVM model CPU-intensive hai — Random Forest recommend hai production ke liye
- Feature extraction requires live HTTP fetch — some URLs may timeout
