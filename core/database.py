from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./aegismesh.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True)
    country = Column(String, default="Unknown")
    lat = Column(Float, default=0.0)
    lon = Column(Float, default=0.0)
    method = Column(String)
    path = Column(String)
    threats = Column(String)       # Virgülle ayrılmış tehdit türleri
    risk_score = Column(Integer)
    severity = Column(String)
    entropy = Column(Float)
    payload_sample = Column(String)
    is_honeypot = Column(Boolean, default=False)
    waf_rule = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    reason = Column(String)
    blocked_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)
