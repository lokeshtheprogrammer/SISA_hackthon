import time, json, os, uuid, asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Any, Dict
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, UploadFile, File, Form, Request, Depends, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from loguru import logger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from core.parser        import LogParser
from core.detector      import Detector
from core.ml_anomaly    import AnomalyDetector
from core.risk_engine   import RiskEngine
from core.masker        import Masker
from core.correlator    import CorrelationEngine
from core.ai_insight    import AIInsightEngine
from core.alert_sys     import AlertSystem
from core.email_utils   import send_otp_email
from core.auth          import get_current_user, authenticate_admin, AuthManager, check_role, authenticate_user
from core.policy_engine import PolicyEngine
from core.input_router  import InputRouter
from core.sql_detector  import SQLDetector
from core.db            import db
from core.file_ingestor import FileIngestor
from core.hf_anomaly    import HFAnomalyDetector

# Structured Logging
logger.add("logs/asdip_v6.log", rotation="10 MB", format="{time} | {level} | {message}")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="ASDIP v6.0 - AI Secure Data Intelligence Platform", version="6.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    request_id = str(uuid.uuid4())
    with logger.contextualize(request_id=request_id):
        logger.info(f"REQ-START: {request.method} {request.url.path}")
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Request-ID"] = request_id
        
        # Final Logging with Usage
        usage_type = "read" if request.method == "GET" else "write"
        asyncio.create_task(db.save_usage({
            "timestamp": datetime.utcnow(),
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "type": usage_type
        }))
        
        logger.info(f"REQ-END: {request.method} {request.url.path} (took {process_time:.4f}s)")
        return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global Error: {exc} | Path: {request.url.path}")
    return JSONResponse(status_code=500, content={"error": "Internal server error."})


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if Path("static").exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

parser         = LogParser()
detector       = Detector()
anomaly_detector = AnomalyDetector()
risk_engine    = RiskEngine()
masker         = Masker()
correlator     = CorrelationEngine()
ai_insight     = AIInsightEngine()
alert_sys      = AlertSystem()
policy_engine  = PolicyEngine()
input_router   = InputRouter()
sql_detector   = SQLDetector()
hf_anomaly     = HFAnomalyDetector()

_results_cache: dict = {}


def safe_resp(**kw) -> dict:
    return {
        "status":                 kw.get("status", "ok"),
        "scan_id":                kw.get("scan_id", ""),
        "source":                 kw.get("source", "unknown"),
        "why_risk":               kw.get("why_risk", ""),
        "content_type":           kw.get("content_type", "text"),
        "total_lines":            kw.get("total_lines", 0),
        "risk_score":             kw.get("risk_score", 0),
        "risk_level":             kw.get("risk_level", "low"),
        "action":                 kw.get("action", "allowed"),
        "findings":               kw.get("findings", []),
        "insights":               kw.get("insights", []),
        "summary":                kw.get("summary", ""),
        "type_counts":            kw.get("type_counts", {}),
        "flagged_line_numbers":   kw.get("flagged_line_numbers", []),
        "anomalies":              kw.get("anomalies", []),
        "hf_anomalies":           kw.get("hf_anomalies", []),
        "remediation":            kw.get("remediation", []),
        "severity_justification": kw.get("severity_justification", ""),
        "brute_force_detected":   kw.get("brute_force_detected", False),
        "log_spike_detected":     kw.get("log_spike_detected", False),
        "error_storm_detected":   kw.get("error_storm_detected", False),
        "suspicious_ips":         kw.get("suspicious_ips", {}),
        "drain3_available":       kw.get("drain3_available", False),
        "drain3_clusters":        kw.get("drain3_clusters", []),
        "policy":                 kw.get("policy", {}),
        "masked_output":          kw.get("masked_output", None),
        "alert":                  kw.get("alert", ""),
        "analyzed_at":            kw.get("analyzed_at", datetime.utcnow().isoformat() + "Z"),
        "duration_seconds":       kw.get("duration_seconds", 0),
        "ai_ready":               kw.get("ai_ready", False),
    }

_stats = {
    "total_scans": 0,
    "total_findings": 0,
    "risk_counts": {lvl: 0 for lvl in ["low", "medium", "high", "critical"]},
}


async def process_ai_and_db(scan_id: str, raw_text: str, res: dict, itype: str):
    try:
        ai_res = await ai_insight.generate_insight(
            raw_text=raw_text,
            findings=res["findings"],
            type_counts=res["type_counts"],
            score=res["score"],
            level=res["risk_level"],
            anomalies=res["anomaly_lines"],
            brute_force=res["brute_force"],
            log_spike=res["log_spike"],
            clusters=res["clusters"],
        )
        if scan_id in _results_cache:
            _results_cache[scan_id].update({
                "insights":               ai_res.get("insights", []),
                "summary":                ai_res.get("summary", ""),
                "remediation":            ai_res.get("remediation", []),
                "anomalies":              ai_res.get("anomalies", []),
                "severity_justification": ai_res.get("severity_justification", ""),
                "ai_ready": True,
            })

        doc = {
            "scan_id":        scan_id,
            "timestamp":      datetime.utcnow(),
            "source":         res.get("source", "unknown"),
            "risk_score":     res["score"],
            "risk_level":     res["risk_level"],
            "findings_count": len(res["findings"]),
            "ai_insights":    ai_res,
            "itype":          itype,
            "tenant_id":      res.get("tenant_id", "default"),
        }
        await db.save_scan(doc)
        logger.info(f"Scan {scan_id} AI insights ready.")
        
        # Trigger external alerts for high/critical risks
        await alert_sys.trigger_alerts(res["risk_level"], scan_id, len(res["findings"]))
        
    except Exception as e:
        logger.error(f"Background task error for {scan_id}: {e}")
        if scan_id in _results_cache:
            _results_cache[scan_id]["ai_ready"] = True  # unblock polling


def chunk_text(text, size=5000):
    for i in range(0, len(text), size):
        yield text[i:i+size]

async def analyze_pipeline(raw_text: str, input_type: str, options: dict) -> dict:
    parsed_logs = []
    for chunk in chunk_text(raw_text):
        parsed_logs.extend(parser.parse_logs(chunk))
    clusters    = parser.get_clusters()

    gen_res, ml_anomalies, hf_anomalies = await asyncio.gather(
        asyncio.to_thread(detector.detect, parsed_logs),
        asyncio.to_thread(anomaly_detector.detect_anomalies, parsed_logs),
        asyncio.to_thread(hf_anomaly.detect, parsed_logs)
    )

    if input_type == "sql":
        findings, type_counts = sql_detector.detect(raw_text)
        for f in gen_res[0]:
            findings.append(f)
            type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1
    else:
        findings, type_counts = gen_res
    anomaly_lines = list(set(ml_anomalies + hf_anomalies))
    
    batch_anomaly = anomaly_detector.predict(parsed_logs)

    brute_force    = correlator.detect_bruteforce(parsed_logs)
    log_spike      = correlator.detect_log_spike(parsed_logs)
    suspicious_ips = correlator.detect_suspicious_ips(parsed_logs)
    error_storm    = correlator.detect_error_storm(parsed_logs)

    score, risk_level = risk_engine.calculate(
        findings,
        is_brute_force=brute_force,
        suspicious_ips=suspicious_ips,
        error_storm=error_storm,
        anomaly_lines=anomaly_lines,
    )

    mask_needed = options.get("mask", False) or risk_level in ["high", "critical"]
    masked_out  = masker.mask_data(raw_text) if mask_needed else None
    alert_msg   = alert_sys.generate_alert(risk_level)

    flagged_line_nums = sorted(set([f.get("line") or f.get("line_number")
                                     for f in findings
                                     if f.get("line") or f.get("line_number")]))

    return {
        "total_lines":     len(raw_text.splitlines()),
        "clusters":        clusters,
        "findings":        findings,
        "type_counts":     type_counts,
        "anomaly_lines":   anomaly_lines,
        "hf_anomalies":    hf_anomalies,
        "batch_anomaly":   batch_anomaly,
        "brute_force":     brute_force,
        "log_spike":       log_spike,
        "suspicious_ips":  suspicious_ips,
        "error_storm":     error_storm,
        "score":           score,
        "risk_level":      risk_level,
        "masked_out":      masked_out,
        "alert_msg":       alert_msg,
        "flagged_line_numbers": flagged_line_nums,
    }


class AnalyzeRequest(BaseModel):
    input_type: str
    content: str
    options: Optional[dict] = {}


class LoginRequest(BaseModel):
    username: str
    password: str

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str

class VerifyOTPRequest(BaseModel):
    email: str
    otp: str
    context: str # 'signup' or 'login'
    # for signup we might want to pass the pending user data if not stored, 
    # but we'll store user after OTP or store user with 'inactive' status.
    # Let's store user after OTP for simplicity if it's a new user, 
    # or just use a temporary cache.
    password: Optional[str] = None
    username: Optional[str] = None

# Temporary cache for signup data
_signup_cache: Dict[str, Dict] = {}

@app.post("/signup")
async def signup(req: SignupRequest):
    # Check if user exists
    existing = await db.get_user_by_username(req.username)
    if existing: raise HTTPException(status_code=400, detail="Username taken")
    existing_email = await db.get_user_by_email(req.email)
    if existing_email: raise HTTPException(status_code=400, detail="Email already registered")
    
    # Generate OTP
    otp = AuthManager.generate_otp()
    if send_otp_email(req.email, otp):
        await db.save_otp(req.email, otp)
        # Cache signup data
        _signup_cache[req.email] = {
            "username": req.username,
            "email": req.email,
            "password": AuthManager.get_password_hash(req.password)
        }
        return {"status": "otp_sent", "email": req.email}
    else:
        raise HTTPException(status_code=500, detail="Failed to send verification email")

@app.post("/login")
async def login(req: LoginRequest):
    user = await authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Logic: Admin bypasses OTP for convenience or has OTP too? 
    # User wants "after otp verification dashboard", so let's do OTP for everyone with an email.
    email = user.get("email")
    if not email and user.get("role") == "admin":
        # Fallback for admin if no email provided in env
        email = os.environ.get("EMAIL_USER")
    
    if email:
        otp = AuthManager.generate_otp()
        if send_otp_email(email, otp):
            await db.save_otp(email, otp)
            return {"status": "otp_sent", "email": email, "username": req.username}
        else:
            raise HTTPException(status_code=500, detail="Failed to send verification email")
    
    # If no email (unlikely with this setup), just give token
    token = AuthManager.create_access_token(user)
    return {"access_token": token, "token_type": "bearer", "status": "authenticated"}

@app.post("/verify-otp")
async def verify_otp(req: VerifyOTPRequest):
    is_valid = await db.verify_otp(req.email, req.otp)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
    if req.context == "signup":
        data = _signup_cache.get(req.email)
        if not data: raise HTTPException(status_code=400, detail="Signup session expired")
        # Create user
        await db.create_user({
            "username": data["username"],
            "email": data["email"],
            "password": data["password"],
            "role": "user",
            "tenant_id": str(uuid.uuid4())[:8]
        })
        del _signup_cache[req.email]
        user_payload = {"sub": data["username"], "role": "user", "tenant_id": "new"}
    else:
        # Login context
        # We need to get the user data again to create token
        # For simplicity, we assume the user exists if it was 'login' context
        # but for safety let's find them
        user_db = await db.get_user_by_email(req.email)
        if not user_db:
            # Check if it's admin
            if req.email == os.environ.get("EMAIL_USER"):
                user_payload = {"sub": "admin", "role": "admin", "tenant_id": "system"}
            else:
                raise HTTPException(status_code=404, detail="User not found")
        else:
            user_payload = {"sub": user_db["username"], "role": user_db.get("role", "user"), "tenant_id": user_db.get("tenant_id", "default")}

    token = AuthManager.create_access_token(user_payload)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/health")
async def health():
    return {"status": "healthy", "version": "6.0.0"}


@app.get("/stats")
async def get_stats(user: dict = Depends(get_current_user)):
    usage = await db.get_usage_stats(tenant_id=user.get("tenant_id", "default"))
    distribution = await db.get_risk_distribution()
    
    # Overwrite risk counts with real DB aggregate if available
    db_risk_counts = {item['_id']: item['count'] for item in distribution if item['_id']}
    if db_risk_counts:
        _stats["risk_counts"].update(db_risk_counts)
        
    return {**_stats, "usage": usage}


@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze(request: Request, background_tasks: BackgroundTasks,
                  user: dict = Depends(get_current_user)):
    t0 = time.time()
    raw_text, source, itype, options = "", "unknown", "text", {}
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = await request.json()
            data = AnalyzeRequest(**body)
            options = data.options or {}
            raw_text, itype, source = input_router.route_json(data.input_type, data.content)
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": f"JSON error: {e}"})
    else:
        try:
            form = await request.form()
            text_input = form.get("text_input")
            file       = form.get("file")
            if file and hasattr(file, "filename"):
                raw_text, itype, source = await input_router.route_upload(file)
            elif text_input:
                raw_text, itype, source = input_router.route_input("text", str(text_input), source="text_input")
                itype = input_router._heuristic_type(raw_text, itype)
            else:
                return JSONResponse(status_code=400, content={"error": "No input provided"})
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": f"Form error: {e}"})

    if not raw_text.strip():
        return JSONResponse(status_code=400, content={"error": "Input is empty"})
        
    MAX_SIZE = 2 * 1024 * 1024
    if len(raw_text) > MAX_SIZE:
        return JSONResponse(status_code=400, content={"error": "Input too large"})

    if "<script>" in raw_text:
        raise HTTPException(400, "Invalid input")

    try:
        res     = await analyze_pipeline(raw_text, itype, options)
        elapsed = round(time.time() - t0, 3)
        res     = policy_engine.apply_policy(res, options)
        scan_id = str(uuid.uuid4())
        res["source"] = source

        for ip in res["suspicious_ips"]:
            count = await db.get_similar_threats(ip)
            if count > 3:
                res["risk_level"] = "critical"

        rl = res["risk_level"]
        why_risk = f"Detected {len(res['findings'])} issues including {', '.join(set([f['type'] for f in res['findings']]))}"

        full_result = safe_resp(
            scan_id=scan_id, source=source, content_type=itype,
            why_risk=why_risk, total_lines=res["total_lines"], 
            risk_score=res["score"], risk_level=rl, action=res["action"],
            brute_force_detected=res["brute_force"],
            log_spike_detected=res["log_spike"],
            error_storm_detected=res["error_storm"],
            suspicious_ips=res["suspicious_ips"],
            drain3_available=parser.drain3_available,
            drain3_clusters=res["clusters"],
            type_counts=res["type_counts"],
            flagged_line_numbers=res["flagged_line_numbers"],
            findings=res["findings"],
            anomalies=res["anomaly_lines"],
            hf_anomalies=res["hf_anomalies"],
            policy=res["policy"],
            masked_output=res["masked_out"],
            alert=res["alert_msg"],
            duration_seconds=elapsed,
            ai_ready=False,
        )

        res["tenant_id"] = user.get("tenant_id", "default")
        _results_cache[scan_id] = full_result
        background_tasks.add_task(process_ai_and_db, scan_id, raw_text, res, itype)

        _stats["total_scans"]    += 1
        _stats["total_findings"] += len(res["findings"])
        _stats["risk_counts"][rl] += 1

        return full_result
    except Exception as e:
        logger.error(str(e))
        return JSONResponse(status_code=500, content={"error": "Internal server error"})


@app.post("/analyze/batch")
@limiter.limit("2/minute")
async def analyze_batch(request: Request,
                        inputs: List[AnalyzeRequest],
                        background_tasks: BackgroundTasks,
                        user: dict = Depends(get_current_user)):

    async def single_scan(item: AnalyzeRequest):
        raw_text, itype, source = input_router.route_json(item.input_type, item.content)
        res = await analyze_pipeline(raw_text, itype, item.options or {})
        res["tenant_id"] = user.get("tenant_id", "default")
        scan_id = str(uuid.uuid4())
        background_tasks.add_task(process_ai_and_db, scan_id, raw_text, res, itype)
        return {"scan_id": scan_id, "risk_level": res["risk_level"], "status": "processing"}
    
    results = await asyncio.gather(*[single_scan(i) for i in inputs])
    
    # Usage Analytics logging
    usage_doc = {
        "timestamp": datetime.utcnow(),
        "user": user.get("sub"),
        "tenant_id": user.get("tenant_id"),
        "type": "batch",
        "count": len(inputs)
    }
    background_tasks.add_task(db.save_usage, usage_doc)
    
    return {"status": "ok", "batch_results": results}

# WebSocket Managers
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    async def broadcast(self, message: str):
        for conn in self.active_connections:
            await conn.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            raw_text, itype, source = input_router.route_input("text", data, source="ws")
            res = await analyze_pipeline(raw_text, itype, {})
            await websocket.send_json({
                "progress": 100,
                "risk_level": res["risk_level"],
                "score": res["score"],
                "findings": res["findings"][:5]
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/results/{scan_id}")
async def get_results(scan_id: str, user: dict = Depends(get_current_user)):
    if scan_id not in _results_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _results_cache[scan_id]


@app.get("/clusters")
async def get_clusters(user: dict = Depends(check_role("admin"))):
    return {"clusters": parser.get_clusters()}


@app.get("/trend")
async def get_trend(user: dict = Depends(get_current_user)):
    scans = await db.get_recent_scans(limit=30, tenant_id=user.get("tenant_id", "default"))
    return [{"t": s["timestamp"].isoformat(), "s": s["risk_score"]} for s in scans][::-1]


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    for p in [Path("static/index.html"), Path("index.html")]:
        if p.exists():
            return HTMLResponse(p.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>ASDIP v6.0</h2>")
