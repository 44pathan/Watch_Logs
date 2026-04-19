# WATCH_LOGS — Open-Source SIEM Dashboard

A lightweight, self-hosted **Security Information and Event Management (SIEM)** platform built for real-time log analysis, threat detection, and endpoint monitoring.

---

## ✨ Features

- **Real-Time Log Ingestion** via Logstash + Elasticsearch
- **Rule-Based Alerting** — custom JSON rules with severity levels
- **Correlated Alerts** — multi-event pattern detection
- **Endpoint Risk Scoring** — dynamic risk scores per host
- **Endpoint Isolation** — lock-out compromised hosts
- **Threat Intelligence** — IP reputation checks
- **Secure Authentication** — JWT-based login with bcrypt password hashing
- **Date & Severity Filtering** in the Log Management view
- **Email Notifications** for critical-severity events

---

## 🗂️ Project Structure

```
watchlogs/
├── backend/
│   ├── app.py               # Flask REST API (main backend)
│   ├── correlator.py        # Correlated alert engine
│   ├── rule_engine.py       # Rule evaluation logic
│   └── users.json           # User store (hashed passwords)
├── frontend/
│   ├── login.html           # Login portal
│   ├── ui.html              # Main dashboard
│   ├── script.js            # All frontend logic
│   └── style.css            # Dashboard styles
├── rules/
│   ├── rules.json           # Detection rules
│   └── correlation_rules.json
├── conf/
│   ├── filebeat.yml.new     # Filebeat config template
│   └── siem.conf.new        # Logstash pipeline config
├── inject_test_logs.py      # Test log injector script
└── .gitignore
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Elasticsearch 8.x (running locally on port 9200)
- Logstash (optional — for live pipeline)
- Filebeat (optional — for host log shipping)

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/watchlogs.git
cd watchlogs
```

### 2. Install Python dependencies

```bash
pip install flask flask-cors elasticsearch werkzeug pyjwt requests
```

### 3. Configure Elasticsearch

Make sure Elasticsearch is running:

```bash
curl http://localhost:9200
```

### 4. Run the backend

```bash
cd backend
python app.py
```

The API will start on `http://localhost:5000`.

### 5. Open the dashboard

Open `frontend/login.html` in your browser (or serve via any static file server).

Default credentials:
- **Username:** `admin`
- **Password:** (set during initial setup — see `users.json`)

---

## ⚙️ Configuration

| File | Purpose |
|------|---------|
| `rules/rules.json` | Detection rules (severity, pattern, action) |
| `rules/correlation_rules.json` | Multi-event correlation patterns |
| `conf/filebeat.yml.new` | Filebeat config for log shipping |
| `conf/siem.conf.new` | Logstash pipeline config |

---

## 🔒 Security Notes

- Passwords are stored as **PBKDF2-SHA256 hashes** — never in plaintext.
- All API endpoints are protected with **JWT Bearer tokens**.
- Brute-force login protection is built in.
- Do **not** commit real secrets or API keys. Use `.env` files (already in `.gitignore`).

---

## 🤝 Contributing

This project is developed collaboratively. To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📜 License

MIT License — feel free to use, modify, and distribute.
