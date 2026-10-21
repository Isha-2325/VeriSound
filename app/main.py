import json
import uuid
import math
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import numpy as np

from app.config import EVIDENCE_DIR, REPORTS_DIR, settings
from app.core.hasher import ForensicHasher
from app.core.metadata_parser import ForensicMetadataParser
from app.core.signal_analyzer import ForensicSignalAnalyzer
from app.core.tamper_detector import ForensicTamperDetector
from app.core.ai_explainer import AIForensicExplainer
from app.core.reporter import ForensicReportGenerator

app = FastAPI(
    title="Audio Tamper & Splice Spotter",
    description="AI-Automated Digital Audio Forensic & Tamper Detection Suite",
    version="2.0.0"
)

# Ensure runtime folders exist on D drive
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Mount static and templates
BASE_DIR = Path(__file__).resolve().parent
static_dir = BASE_DIR / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

def sanitize_json(data):
    """Recursively clean NaN, Infinity, and numpy datatypes for strict JSON compliance."""
    if isinstance(data, dict):
        return {k: sanitize_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_json(v) for v in data]
    elif isinstance(data, (float, np.floating)):
        val = float(data)
        return 0.0 if (math.isnan(val) or math.isinf(val)) else round(val, 6)
    elif isinstance(data, (bool, np.bool_)):
        return bool(data)
    elif isinstance(data, (int, np.integer)):
        return int(data)
    elif isinstance(data, np.ndarray):
        return sanitize_json(data.tolist())
    return data

@app.get("/", response_class=HTMLResponse)
async def home_page(request: Request):
    """Main user-friendly forensic workbench interface."""
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/scan")
async def scan_audio_endpoint(file: UploadFile = File(...)):
    """
    Direct forensic audio scan endpoint:
    Processes uploaded audio, runs signal analysis, detects splices/cuts,
    and returns AI automated diagnostic findings.
    """
    ext = Path(file.filename).suffix.lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '{ext}'. Supported: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )

    # Save to disk
    file_id = uuid.uuid4().hex[:12]
    stored_path = EVIDENCE_DIR / f"{file_id}_{file.filename}"
    with open(stored_path, "wb") as buffer:
        while chunk := await file.read(65536):
            buffer.write(chunk)

    # 1. Hashes & Entropy
    hashes = ForensicHasher.calculate_hashes(stored_path)
    hashes["entropy"] = ForensicHasher.calculate_shannon_entropy(stored_path)

    # 2. Metadata & Container signatures
    metadata = ForensicMetadataParser.analyze_metadata(stored_path)

    # 3. Audio Signal & High-Resolution Spectrogram
    y, sr, channels = ForensicSignalAnalyzer.load_audio(stored_path)
    sig_metrics = ForensicSignalAnalyzer.compute_signal_metrics(y, sr, channels)
    waveform = ForensicSignalAnalyzer.generate_decimated_waveform(y, num_points=800)
    spectrogram_uri = ForensicSignalAnalyzer.generate_spectrogram_image(y, sr)

    # 4. Tamper & Splice Detection
    tamper = ForensicTamperDetector.run_tamper_suite(y, sr)

    # 5. AI Automated Forensic Reasoning & Root-Cause Diagnosis
    ai_assessment = AIForensicExplainer.generate_assessment(
        tamper_results=tamper,
        metadata_results=metadata,
        signal_metrics=sig_metrics,
        hasher_results=hashes
    )

    results = {
        "file_id": file_id,
        "filename": file.filename,
        "audio_url": f"/api/audio/{stored_path.name}",
        "hashes": hashes,
        "metadata": metadata,
        "signal_metrics": sig_metrics,
        "waveform": waveform,
        "spectrogram_uri": spectrogram_uri,
        "tamper": tamper,
        "ai_assessment": ai_assessment
    }

    clean_results = sanitize_json(results)
    return JSONResponse(content=clean_results)

@app.get("/api/audio/{filename}")
async def stream_audio(filename: str):
    """Stream audio to player safely."""
    path = EVIDENCE_DIR / filename
    if not path.exists():
        # Check samples folder
        samples_dir = BASE_DIR.parent / "tests" / "samples"
        path = samples_dir / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Audio file not found.")

    media_type = "audio/wav"
    if path.suffix.lower() == ".mp3":
        media_type = "audio/mpeg"
    elif path.suffix.lower() == ".flac":
        media_type = "audio/flac"
    elif path.suffix.lower() == ".ogg":
        media_type = "audio/ogg"

    return FileResponse(path=path, media_type=media_type)

@app.get("/api/samples")
async def list_available_samples():
    """List 3 spliced samples and 5 clean samples with descriptions."""
    samples = [
        {"id": "tampered_speech_redaction", "name": "Speech Redaction Cut", "category": "Spliced", "description": "Inserted artificial zero flatline (redaction) at 2.2s - 2.8s"},
        {"id": "tampered_two_speakers_spliced", "name": "Two Speakers Spliced", "category": "Spliced", "description": "Hard digital cut joining male and female voices at 2.5s with 22 dB jump"},
        {"id": "tampered_room_shift", "name": "Acoustic Room Shift", "category": "Spliced", "description": "Indoor studio audio spliced with sudden 18 dB outdoor ambient noise at 2.8s"},
        {"id": "clean_male_speech", "name": "Natural Male Speech", "category": "Clean", "description": "Continuous male vocal tone with natural room tone floor (-55 dB)"},
        {"id": "clean_female_speech", "name": "Natural Female Speech", "category": "Clean", "description": "Continuous female vocal tone with organic vibrato and room decay"},
        {"id": "clean_telephone_call", "name": "Telephone Bandpass Call", "category": "Clean", "description": "300Hz-3400Hz bandpassed telephony audio with steady line noise"},
        {"id": "clean_podcast_studio", "name": "Podcast Studio Recording", "category": "Clean", "description": "Dynamic vocal cadence with smooth speech pauses and uniform ambiance"},
        {"id": "clean_ambient_interview", "name": "Ambient Room Interview", "category": "Clean", "description": "Dialogue with continuous acoustic background ambiance, zero cuts"}
    ]
    return samples

@app.get("/api/sample/{sample_name}")
async def get_test_sample(sample_name: str):
    """Provide pre-generated samples (pristine or tampered) for quick 1-click test."""
    clean_name = sample_name.removesuffix(".wav")
    samples_dir = BASE_DIR.parent / "tests" / "samples"
    sample_file = samples_dir / f"{clean_name}.wav"
    
    if not sample_file.exists():
        from tests.generate_more_samples import generate_all_samples
        generate_all_samples()

    if not sample_file.exists():
        raise HTTPException(status_code=404, detail="Sample not found.")

    return FileResponse(path=sample_file, media_type="audio/wav", filename=f"{clean_name}.wav")

@app.post("/api/export-pdf")
async def export_pdf_report(request: Request):
    """Generate and return court-admissible PDF forensic report from scan data."""
    body = await request.json()
    filename = body.get("filename", "audio_evidence")
    pdf_path = REPORTS_DIR / f"Forensic_Report_{uuid.uuid4().hex[:8]}.pdf"

    evidence_info = {
        "filename": filename,
    }

    ForensicReportGenerator.generate_pdf(pdf_path, evidence_info, body)

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"Forensic_Report_{Path(filename).stem}.pdf"
    )
