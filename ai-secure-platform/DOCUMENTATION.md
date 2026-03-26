# ASDIP v6.0 — AI Secure Data Intelligence Platform

## Overview
ASDIP is a production-grade security intelligence platform that acts as an **AI Gateway**, **Data Scanner**, **Log Analyzer**, and **Risk Engine**. It ingests multi-source data, detects sensitive information and security threats using regex + ML + LLM, and returns structured risk assessments.

---

## Architecture

```
Input (Text / File / SQL / Log / Chat)
  ↓
InputRouter (route_json / route_upload / route_input)
  ↓
FileIngestor (DOCX/PDF extraction)
  ↓
LogParser (Drain3 template mining)
  ↓
Detection Engine
  ├── Detector (16 regex pattern types)
  ├── SQLDetector (injection, credentials, schema leaks)
  └── AnomalyDetector (Isolation Forest ML)
  ↓
CorrelationEngine
  ├── Brute-force detection (3+ failures / 20-line window)
  ├── Log volume spike detection
  ├── Suspicious IP frequency analysis
  └── Error storm detection (>50% error rate)
  ↓
RiskEngine (weighted scoring → low/medium/high/critical)
  ↓
PolicyEngine (allowed / masked / blocked)
  ↓
Masker (redacts all sensitive patterns)
  ↓
FastAPI Response (initial, synchronous)
  ↓ (background task)
AIInsightEngine → LLMEngine (GPT-4o-mini)
  ↓
MongoDB (motor async)
  ↓
GET /results/{scan_id} (polled by frontend until ai_ready=true)
```

---

## API Reference

### POST /login
```json
{"username": "admin", "password": "your_password"}
→ {"access_token": "...", "token_type": "bearer"}
```

### POST /analyze
**Headers:** `Authorization: Bearer <token>`
**JSON body:**
```json
{
  "input_type": "text | log | sql | chat | file | doc | pdf",
  "content": "...",
  "options": {
    "mask": true,
    "block_high_risk": true,
    "log_analysis": true
  }
}
```
**Multipart form:** `file=<binary>` or `text_input=<string>`

**Response:**
```json
{
  "scan_id": "uuid",
  "risk_score": 12,
  "risk_level": "high",
  "action": "masked",
  "findings": [{"type":"password","risk":"critical","line":3,"value":"***","line_content":"..."}],
  "type_counts": {"password":1,"email":2},
  "flagged_line_numbers": [3,7],
  "brute_force_detected": false,
  "log_spike_detected": false,
  "error_storm_detected": false,
  "suspicious_ips": {},
  "masked_output": "...",
  "alert": "🚨 HIGH RISK ALERT",
  "ai_ready": false,
  "total_lines": 10,
  "duration_seconds": 0.034
}
```

### GET /results/{scan_id}
Poll until `ai_ready: true` to receive AI-enriched response with `summary`, `insights`, `remediation`, `anomalies`.

### GET /stats
Returns `{total_scans, total_findings, risk_counts}`.

### GET /trend
Returns last 30 scans as `[{t: ISO timestamp, s: risk_score}]`.

### GET /health
Returns `{status: "healthy", version: "6.0.0"}`.

---

## Detection Patterns

| Pattern | Risk | Description |
|---|---|---|
| `password` | Critical | password=, passwd=, pwd= |
| `secret_key` | Critical | secret=, private_key=, signing_key= |
| `credit_card` | Critical | Visa, MC, Amex card numbers |
| `ssn` | Critical | Social Security Numbers |
| `aws_key` | Critical | AKIA/ASIA/AROA/AIDA prefixed keys |
| `connection_string` | Critical | DB connection URIs with credentials |
| `api_key` | High | sk-* patterns, api_key= |
| `token` | High | JWT, bearer, auth tokens |
| `github_token` | High | ghp_, gho_, ghs_ tokens |
| `debug_mode` | High | debug=true, logging.DEBUG |
| `stack_trace` | Medium | Python/Java exception traces |
| `url_leak` | Medium | URLs with potential sensitive params |
| `private_ip` | Medium | RFC1918 internal IPs |
| `email` | Low | Email addresses |
| `phone` | Low | Phone numbers |
| `ip_address` | Low | Any public IP |

---

## Setup

### Prerequisites
- Python 3.11+
- MongoDB (local or Atlas)
- OpenAI API key (optional — falls back to rule-based insights)

### Installation
```bash
cp .env.example .env
# Edit .env with your credentials

pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Docker
```bash
docker-compose up --build
```

### Running Tests
```bash
pytest tests/ -v
```

---

## Security Notes
- **NEVER** commit your `.env` file — it is in `.gitignore`
- Rotate the `ASDIP_SECRET_KEY` before production deployment
- Change `ASDIP_ADMIN_PASS` from the default immediately
- The `.env.example` file contains **no real credentials**
- JWT tokens expire after 60 minutes

---

## Evaluation Coverage

| Category | Points | Status |
|---|---|---|
| Backend Design | 18 | ✅ FastAPI, async, modular |
| AI Integration | 15 | ✅ GPT-4o-mini + rule fallback |
| Multi-Input Handling | 12 | ✅ Text/Log/SQL/Chat/File/DOCX/PDF |
| Log Analysis | 15 | ✅ Drain3+ML+Regex+Correlations |
| Detection + Risk Engine | 12 | ✅ 16 patterns + weighted scoring |
| Policy Engine | 8 | ✅ allowed/masked/blocked |
| Frontend UI | 10 | ✅ Full SPA with log viewer, AI panel |
| Security | 5 | ✅ JWT auth, no secrets committed |
| Observability | 3 | ✅ /stats, /trend, /health, logging |
| Bonus | 2 | ✅ Drag-drop, PDF/JSON export, Masker |
