import pytest
from fastapi.testclient import TestClient
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import app

client = TestClient(app)

def get_token():
    r = client.post("/login", json={"username": "admin", "password": "admin123"})
    return r.json()["access_token"]

def auth():
    return {"Authorization": f"Bearer {get_token()}"}

# ── Health ─────────────────────────────────────────────────────────────────
def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["version"] == "6.0.0"

# ── Auth ───────────────────────────────────────────────────────────────────
def test_unauthorized():
    r = client.post("/analyze", json={"input_type": "text", "content": "test"})
    assert r.status_code in [401, 403]

def test_bad_credentials():
    r = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401

def test_login_success():
    r = client.post("/login", json={"username": "admin", "password": "admin123"})
    assert r.status_code == 200
    assert "access_token" in r.json()

# ── Analysis ──────────────────────────────────────────────────────────────
def test_password_detection():
    r = client.post("/analyze", json={"input_type": "text", "content": "password=SuperSecret123"}, headers=auth())
    assert r.status_code == 200
    d = r.json()
    assert d["risk_level"] in ["high", "critical"]
    assert any(f["type"] == "password" for f in d["findings"])
    assert d["scan_id"] != ""

def test_api_key_detection():
    r = client.post("/analyze", json={"input_type": "text", "content": "api_key=sk-prod-1234567890abcdef"}, headers=auth())
    assert r.status_code == 200
    d = r.json()
    assert any(f["type"] in ["api_key", "secret_key"] for f in d["findings"])

def test_sql_injection_detection():
    r = client.post("/analyze", json={"input_type": "sql", "content": "SELECT * FROM users WHERE id=1 OR 1=1"}, headers=auth())
    assert r.status_code == 200
    d = r.json()
    assert any(f["type"] == "sql_injection" for f in d["findings"])

def test_email_detection():
    r = client.post("/analyze", json={"input_type": "text", "content": "user=admin@example.com logged in"}, headers=auth())
    assert r.status_code == 200
    d = r.json()
    assert any(f["type"] == "email" for f in d["findings"])

def test_empty_input():
    r = client.post("/analyze", json={"input_type": "text", "content": "   "}, headers=auth())
    assert r.status_code == 400
    assert "empty" in r.json()["error"].lower()

def test_mask_option():
    r = client.post("/analyze",
        json={"input_type": "text", "content": "password=secret123", "options": {"mask": True}},
        headers=auth())
    assert r.status_code == 200
    d = r.json()
    assert d["masked_output"] is not None
    assert "secret123" not in (d["masked_output"] or "")

def test_findings_have_normalized_fields():
    r = client.post("/analyze", json={"input_type": "text", "content": "password=test api_key=sk-prod-abc1234567890"}, headers=auth())
    assert r.status_code == 200
    for f in r.json()["findings"]:
        assert "type" in f
        assert "risk" in f
        # Both 'line' and 'value' must exist (normalized)
        assert "line" in f or "line_number" in f
        assert "value" in f or "match" in f

def test_policy_block_high_risk():
    r = client.post("/analyze",
        json={"input_type": "text", "content": "password=critical_secret123 api_key=sk-prod-xyz1234567890",
              "options": {"block_high_risk": True}},
        headers=auth())
    assert r.status_code == 200
    d = r.json()
    assert d["action"] in ["blocked", "masked"]

def test_results_endpoint():
    # First scan
    r = client.post("/analyze", json={"input_type": "text", "content": "password=test123"}, headers=auth())
    assert r.status_code == 200
    scan_id = r.json()["scan_id"]
    # Fetch results
    r2 = client.get(f"/results/{scan_id}", headers=auth())
    assert r2.status_code == 200
    assert r2.json()["scan_id"] == scan_id

def test_results_not_found():
    r = client.get("/results/nonexistent-id-xyz", headers=auth())
    assert r.status_code == 404

def test_stats_endpoint():
    r = client.get("/stats", headers=auth())
    assert r.status_code == 200
    d = r.json()
    assert "total_scans" in d
    assert "risk_counts" in d

def test_brute_force_detection():
    log = "\n".join(["2024-01-01 ERROR Authentication failed for user root"] * 5)
    r = client.post("/analyze", json={"input_type": "log", "content": log}, headers=auth())
    assert r.status_code == 200
    assert r.json()["brute_force_detected"] is True

def test_multiple_input_types():
    for itype in ["text", "log", "sql", "chat"]:
        r = client.post("/analyze", json={"input_type": itype, "content": "email=test@test.com"}, headers=auth())
        assert r.status_code == 200, f"Failed for input_type={itype}"

def test_file_upload_log():
    log_content = b"2024-01-01 ERROR password=secret123\n2024-01-01 INFO api_key=sk-prod-xyz1234567890"
    r = client.post("/analyze", files={"file": ("test.log", log_content, "text/plain")}, headers=auth())
    assert r.status_code == 200
    d = r.json()
    assert d["findings"]

def test_response_shape():
    r = client.post("/analyze", json={"input_type": "text", "content": "test log line"}, headers=auth())
    assert r.status_code == 200
    d = r.json()
    required_fields = ["scan_id","risk_level","risk_score","findings","type_counts",
                       "flagged_line_numbers","action","total_lines","ai_ready"]
    for field in required_fields:
        assert field in d, f"Missing field: {field}"
