from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class Sample(Base):
    """Malware samples uploaded for analysis"""
    __tablename__ = "samples"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # File information
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)  # Local filesystem path
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100))
    
    # Hashes for identification
    md5 = Column(String(32), index=True)
    sha1 = Column(String(40), index=True)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    ssdeep = Column(String(255))
    
    # Timestamps
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    deleted_at = Column(DateTime)  # Soft delete
    
    # Relationships
    analyses = relationship("Analysis", back_populates="sample", cascade="all, delete-orphan")


class Analysis(Base):
    """Analysis runs for malware samples"""
    __tablename__ = "analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    sample_id = Column(Integer, ForeignKey("samples.id"), nullable=False)
    
    # Status tracking
    status = Column(String(50), default="pending", nullable=False)  # pending, running, completed, failed
    
    # Configuration
    analysis_type = Column(String(50), default="static")  # static, dynamic, both
    
    # Results (stored as JSON for flexibility)
    threat_score = Column(Integer)  # 0-100
    static_results = Column(JSON)  # Hashes, strings, PE info, YARA matches
    virustotal_results = Column(JSON)  # VirusTotal API response
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Error tracking
    error_message = Column(String(1000))
    
    # Relationships
    sample = relationship("Sample", back_populates="analyses")


class YaraRule(Base):
    """Custom YARA rules for malware detection"""
    __tablename__ = "yara_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(String(1000))
    rule_content = Column(String, nullable=False)  # YARA rule text
    
    # Metadata
    author = Column(String(255))
    severity = Column(String(50))  # low, medium, high, critical
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

