from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from pathlib import Path
import shutil
import hashlib
import os

from config import settings
from database import get_db, engine, SAMPLES_DIR
from models import Base, Sample, Analysis

# Create database tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Lightweight standalone malware analysis tool"
)

# CORS not needed - local only app
# No authentication - single user mode

# Mount static files
static_dir = Path(__file__).parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def root():
    """Serve the frontend"""
    static_dir = Path(__file__).parent.parent / "static"
    index_file = static_dir / "index.html"
    
    if index_file.exists():
        return FileResponse(index_file)
    else:
        return {
            "app": settings.APP_NAME,
            "version": settings.VERSION,
            "status": "running",
            "mode": "standalone",
            "note": "Frontend not found. Please create static/index.html"
        }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "database": "sqlite",
        "samples_count": 0  # TODO: Get from DB
    }


# ============ Sample Management ============

def calculate_hashes(file_path: str) -> dict:
    """Calculate file hashes"""
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    
    return {
        'md5': hashes['md5'].hexdigest(),
        'sha1': hashes['sha1'].hexdigest(),
        'sha256': hashes['sha256'].hexdigest()
    }


@app.post("/api/samples/upload")
async def upload_sample(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload a malware sample"""
    
    # Validate file size
    file_size = 0
    contents = await file.read()
    file_size = len(contents)
    
    print(f"DEBUG: Upload request - {file.filename} ({file_size} bytes)")
    
    if file_size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(400, "File too large (max 100MB)")
    
    # Check file extension
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"File type not allowed. Allowed: {', '.join(settings.ALLOWED_EXTENSIONS)}")
    
    # Save file temporarily to calculate hashes
    temp_path = SAMPLES_DIR / f"temp_{file.filename}"
    with open(temp_path, 'wb') as f:
        f.write(contents)
    
    # Calculate hashes
    try:
        hashes = calculate_hashes(str(temp_path))
    except Exception as e:
        os.remove(temp_path)
        raise HTTPException(500, f"Failed to calculate hashes: {str(e)}")
    
    # Check for duplicates
    existing = db.query(Sample).filter(Sample.sha256 == hashes['sha256']).first()
    if existing:
        os.remove(temp_path)
        
        # If it was deleted, restore it
        if existing.deleted_at:
            print(f"DEBUG: Restoring deleted sample {existing.id}")
            existing.deleted_at = None
            db.commit()
            return {
                "message": "Sample restored successfully",
                "sample_id": existing.id,
                "filename": existing.filename,
                "sha256": existing.sha256,
                "duplicate": False,
                "restored": True
            }
            
        return {
            "message": "Sample already exists",
            "sample_id": existing.id,
            "duplicate": True
        }
    
    # Rename file to SHA256 hash
    final_path = SAMPLES_DIR / f"{hashes['sha256']}{file_ext}"
    shutil.move(str(temp_path), str(final_path))
    
    # Create database record
    new_sample = Sample(
        filename=file.filename,
        file_path=str(final_path),
        file_size=file_size,
        mime_type=file.content_type,
        md5=hashes['md5'],
        sha1=hashes['sha1'],
        sha256=hashes['sha256']
    )
    
    db.add(new_sample)
    db.commit()
    db.refresh(new_sample)
    
    return {
        "message": "Sample uploaded successfully",
        "sample_id": new_sample.id,
        "filename": new_sample.filename,
        "sha256": new_sample.sha256,
        "duplicate": False
    }


@app.get("/api/samples")
async def list_samples(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List all uploaded samples"""
    samples = db.query(Sample).filter(Sample.deleted_at.is_(None)).offset(skip).limit(limit).all()
    total = db.query(Sample).filter(Sample.deleted_at.is_(None)).count()
    
    return {
        "samples": [
            {
                "id": s.id,
                "filename": s.filename,
                "file_size": s.file_size,
                "sha256": s.sha256,
                "uploaded_at": s.uploaded_at.isoformat(),
            }
            for s in samples
        ],
        "total": total,
        "skip": skip,
        "limit": limit
    }


@app.get("/api/samples/{sample_id}")
async def get_sample(sample_id: int, db: Session = Depends(get_db)):
    """Get sample details"""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")
    
    return {
        "id": sample.id,
        "filename": sample.filename,
        "file_size": sample.file_size,
        "mime_type": sample.mime_type,
        "md5": sample.md5,
        "sha1": sample.sha1,
        "sha256": sample.sha256,
        "uploaded_at": sample.uploaded_at.isoformat()
    }


@app.delete("/api/samples/{sample_id}")
async def delete_sample(sample_id: int, db: Session = Depends(get_db)):
    """Delete a sample (soft delete)"""
    from datetime import datetime
    
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")
    
    sample.deleted_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Sample deleted successfully"}


# ============ Analysis ============

@app.post("/api/analysis/{sample_id}/start")
async def start_analysis(sample_id: int, db: Session = Depends(get_db)):
    """Start analysis for a sample"""
    from analyzer import StaticAnalyzer, calculate_threat_score
    from datetime import datetime
    
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(404, "Sample not found")
    
    # Create analysis record
    analysis = Analysis(
        sample_id=sample.id,
        status="running",
        analysis_type="static"
    )
    
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    
    try:
        # Update status
        analysis.started_at = datetime.utcnow()
        db.commit()
        
        # Run static analysis
        analyzer = StaticAnalyzer(sample.file_path)
        results = analyzer.analyze()
        
        # Calculate threat score
        threat_score = calculate_threat_score(results)
        
        # Update analysis with results
        analysis.static_results = results
        analysis.threat_score = threat_score
        analysis.status = "completed"
        analysis.completed_at = datetime.utcnow()
        
        db.commit()
        db.refresh(analysis)
        
        return {
            "message": "Analysis completed",
            "analysis_id": analysis.id,
            "status": "completed",
            "threat_score": threat_score
        }
        
    except Exception as e:
        # Update analysis with error
        analysis.status = "failed"
        analysis.error_message = str(e)
        analysis.completed_at = datetime.utcnow()
        db.commit()
        
        raise HTTPException(500, f"Analysis failed: {str(e)}")


@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Get analysis results"""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    
    return {
        "id": analysis.id,
        "sample_id": analysis.sample_id,
        "status": analysis.status,
        "threat_score": analysis.threat_score,
        "static_results": analysis.static_results,
        "virustotal_results": analysis.virustotal_results,
        "created_at": analysis.created_at.isoformat(),
        "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
