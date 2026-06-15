# 🛡️ PhishGuard-ML

**AI-Powered Phishing Detection Platform** — detect phishing URLs, emails, and QR codes in real time using Machine Learning, threat intelligence, and a multi-agent response system.

> 🚀 Built with Flask · scikit-learn · Celery · a Chrome Manifest V3 extension, and GenAI-powered risk explanation.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Browser Extension](#-browser-extension)
- [Training a New Model](#-training-a-new-model)
- [Research / Conference Output](#-research--conference-output)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🧠 Overview

**PhishGuard-ML** is a full-stack cybersecurity platform that classifies URLs as **phishing** or **legitimate** and provides deeper analysis for emails, QR codes, and visual content.

The core classifier is a `RandomForest` model trained on 30+ hand-crafted URL features (length, HTTPS, special characters, subdomain depth, IP literals, brand impersonation signals, etc.). At runtime, predictions are enriched with:

- Threat-intelligence lookups (VirusTotal, Google Safe Browsing, AbuseIPDB)
- GenAI-based natural-language risk explanations
- Behavioral anomaly detection on user activity
- Autonomous threat-hunting agents that surface risky domains
- An orchestrated response workflow (notify, block, log)

A Chrome extension brings the same detection engine to the user's browser, scanning every page they visit.

---

## ✨ Key Features

| Module | What it does |
|---|---|
| 🔍 **URL Classifier** | Real-time phishing/legit prediction with confidence score |
| 🧠 **LLM Risk Engine** | Plain-English explanation of *why* a URL is risky |
| 📧 **Email Parser** | Inspects email headers + body for phishing indicators |
| 📱 **QR Scanner** | Detects malicious QR payloads |
| 🖼️ **Visual Analysis** | Screenshot/logo similarity to known brand abuse |
| 🎭 **Deepfake Detector** | Flags suspect media artifacts |
| 👤 **User Behavior Model** | Anomaly detection on per-user activity |
| 🛰️ **Threat Intel Enrichment** | VirusTotal / Google Safe Browsing / AbuseIPDB |
| 🤖 **Threat Hunter Agent** | Autonomous discovery of risky domains |
| 🎼 **Response Orchestrator** | Coordinates multi-step incident response |
| 🧩 **Chrome Extension** | Manifest V3 — scans every URL in real time |
| 🔐 **Auth & Security** | Argon2 hashing, rate limiting, CSRF, session hardening |
| 📊 **Admin Dashboard** | Analytics, scan history, user management |
| 🧵 **Async Pipeline** | Celery workers for non-blocking enrichment |

---

## 🏗️ Architecture

```
                ┌────────────────────────────┐
                │   Chrome Extension (MV3)   │
                │  popup + content script    │
                └─────────────┬──────────────┘
                              │ HTTP
                              ▼
   ┌──────────────────────────────────────────────────────────┐
   │                  Flask Web App  (app.py)                 │
   │  Routes · Auth · Dashboards · API · Rate-limit           │
   └──────┬──────────────────┬──────────────────┬─────────────┘
          │                  │                  │
          ▼                  ▼                  ▼
   ┌──────────────┐  ┌────────────────┐  ┌────────────────────┐
   │  ML Engine   │  │   Services     │  │  Multi-Agent Core  │
   │  (sklearn)   │  │  LLM · QR ·    │  │  threat_hunter ·   │
   │  RF + PCA    │  │  Visual · etc. │  │  response_orchestr.│
   └──────┬───────┘  └────────┬───────┘  └─────────┬──────────┘
          │                   │                    │
          └───────────────────┴────────────────────┘
                              │
                              ▼
                  ┌──────────────────────┐
                  │  Celery Workers +    │
                  │  Threat-Intel Cache  │
                  └──────────┬───────────┘
                             ▼
                  ┌──────────────────────┐
                  │  SQLite / PostgreSQL │
                  └──────────────────────┘
```

---

## 🧪 Tech Stack

- **Language:** Python 3.10+
- **Web:** Flask 3, Flask-Session, Jinja2
- **ML / DS:** scikit-learn, NumPy, pandas, joblib, PCA
- **Async:** Celery + Redis (optional)
- **Security:** Argon2, pyotp, cryptography, rate limiting
- **Threat Intel:** VirusTotal, Google Safe Browsing, AbuseIPDB, WHOIS, DNS
- **LLM (optional):** OpenAI / Anthropic (or any provider behind `services/llm_risk_engine.py`)
- **Browser:** Chrome Manifest V3 (vanilla JS)
- **DB:** SQLite (default) — drop-in PostgreSQL supported via `DATABASE_PATH`
- **Email:** secure-smtplib
- **Visual:** Pillow, OpenCV (deepfake + logo similarity)

---

## 📂 Project Structure

```
project4th/
├── app.py                      # Main Flask app (canonical)
├── app_advanced.py             # Legacy / advanced mode
├── app_ultimate.py             # Legacy / ultimate mode (delegates to app.py)
├── main.py                     # CLI entry — predict URL
├── simple_classifier.py        # RandomForest classifier wrapper
├── featureExtractor.py         # URL → feature frame
├── database.py                 # SQLite persistence
├── security.py                 # Auth, hashing, rate limit
├── config.py                   # Centralized config (env-driven)
│
├── ml/                         # ML pipeline
│   ├── feature_pipeline.py
│   └── inference_engine.py
│
├── services/                   # Domain services
│   ├── cache_service.py
│   ├── enrichment_service.py
│   ├── email_parser.py
│   ├── qr_scanner.py
│   ├── visual_analysis.py
│   ├── deepfake_detector.py
│   ├── user_behavior_model.py
│   └── llm_risk_engine.py
│
├── agents/                     # Autonomous agents
│   ├── threat_hunter.py
│   └── response_orchestrator.py
│
├── workers/                    # Celery async tasks
│   ├── celery_app.py
│   └── tasks/enrich_url.py
│
├── routers/                    # Flask blueprints
│   ├── advanced_api.py
│   └── advanced_features_api.py
│
├── browser_extension/          # Chrome MV3 extension
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html / popup.js
│
├── templates/                  # Jinja2 templates
├── data/                       # SQL schema, migrations
├── dataset/                    # Training dataset
├── model/                      # Trained models (gitignored)
├── logs/                       # App logs (gitignored)
├── tmp/                        # Transient artifacts (gitignored)
│
├── requirements.txt            # Pinned dependencies
├── .env.example                # Environment template
├── .gitignore
└── README.md
```

---

## ⚙️ Installation

### 1. Clone

```bash
git clone https://github.com/keybouzair/PhishGuard-ML-AI-Powered-Phishing-Detection-Platform.git
cd PhishGuard-ML-AI-Powered-Phishing-Detection-Platform
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate     # macOS / Linux
# .venv\Scripts\activate      # Windows
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
# then edit .env with your real keys (SECRET_KEY, API keys, etc.)
```

### 5. Run

```bash
python app.py
```

Open <http://127.0.0.1:5000>.

---

## 🔐 Configuration

All configuration is read from environment variables (see `.env.example`):

| Variable | Purpose | Required |
|---|---|---|
| `SECRET_KEY` | Flask session signing | ✅ |
| `DATABASE_PATH` | SQLite path | ⬜ (default: `phishing_detection.db`) |
| `MODEL_PATH` | Trained model path | ⬜ |
| `CONFIDENCE_THRESHOLD` | Decision boundary (0–1) | ⬜ (default `0.7`) |
| `VIRUSTOTAL_API_KEY` | Threat intel lookup | ⬜ |
| `GOOGLE_SAFE_BROWSING_API_KEY` | GSB lookup | ⬜ |
| `ABUSEIPDB_API_KEY` | IP reputation | ⬜ |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Outgoing mail | ⬜ |
| `OPENAI_API_KEY` | LLM risk explanation | ⬜ |

> 🛡️ `.env` is **gitignored** — never commit real keys.

---

## 🚀 Usage

### Web UI

```bash
python app.py
# → http://127.0.0.1:5000
```

### CLI

```bash
python main.py
# Enter a URL when prompted. Output: prediction_label + score
```

### Programmatic

```python
from main import predict

result = predict("http://secure-paypa1-login.example.com/verify")
print(result)
# {'prediction_label': 1, 'prediction_score': 0.92, 'reason': '...'}
```

### REST API

```bash
curl -X POST http://127.0.0.1:5000/api/predict \
     -H "Content-Type: application/json" \
     -d '{"url":"http://example-login-verify.xyz"}'
```

See `api_docs.py` and the `routers/` blueprints for the full surface.

---

## 🧩 Browser Extension

1. Open `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `browser_extension/` folder
4. The icon ⚡ appears — click it to scan the current page's URL

The extension expects the Flask backend to be running on `http://localhost:5000` (configurable in `background.js`).

---

## 🏋️ Training a New Model

```bash
python train.py
```

Artifacts (gitignored) are written to `model/`:

- `phishingdetection.pkl` — main classifier
- `simple_model.pkl` / `simple_scaler.pkl` — lightweight variant
- `pca_model.pkl` — dimensionality reduction
- `text_phishing_model.pkl` — email/text model
- `training_report.json` — metrics summary ✅ (kept in repo)

---

## 📚 Research / Conference Output

This project includes a reproducible **IEEE-style ML pipeline** for academic presentation:

```bash
python ml_pipeline_ieee.py
```

And an auto-generated conference deck:

```bash
python create_conference_ppt.py
# → ppt_with_image.pptx
```

---

## 🛣️ Roadmap

- [ ] Replace SQLite with PostgreSQL + Alembic migrations
- [ ] Docker + docker-compose (Flask + Celery + Redis)
- [ ] CI/CD (GitHub Actions: lint, test, build extension)
- [ ] Real-time WebSocket alerts to admin dashboard
- [ ] Federated retraining with user feedback
- [ ] Mobile companion app (React Native)
- [ ] Graph-RAG over threat intel feeds

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/amazing-thing`
3. Commit: `git commit -m "feat: add amazing thing"`
4. Push: `git push origin feat/amazing-thing`
5. Open a Pull Request

Please follow conventional commits and add tests where applicable.

---

## 📄 License

This project is licensed under the **MIT License** — see the [`LICENSE`](./LICENSE) file for details.

---

## ✍️ Author

**Uzair Khan** — [@keybouzair](https://github.com/keybouzair)

> If this project helped you, please ⭐ the repo — it means a lot!
