import pytest
from pathlib import Path
from starlette.testclient import TestClient
from app.main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_home_page_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Audio Tamper &amp; Splice Spotter" in r.text
    assert "Drop Audio Recording" in r.text

def test_scan_tampered_audio_pipeline(client):
    sample = Path("tests/samples/tampered_splice_cut.wav")
    assert sample.exists()

    with open(sample, "rb") as f:
        r = client.post("/api/scan", files={"file": ("tampered_splice_cut.wav", f, "audio/wav")})

    assert r.status_code == 200
    data = r.json()
    assert "ai_assessment" in data
    assert data["ai_assessment"]["is_tampered"] is True
    assert "TAMPERED" in data["ai_assessment"]["verdict"]
    assert data["ai_assessment"]["tamper_probability_pct"] >= 70.0
    assert len(data["ai_assessment"]["findings"]) > 0

    # Test PDF Export endpoint
    r_pdf = client.post("/api/export-pdf", json=data)
    assert r_pdf.status_code == 200
    assert r_pdf.headers["content-type"] == "application/pdf"
    assert len(r_pdf.content) > 1000

def test_scan_pristine_audio_pipeline(client):
    sample = Path("tests/samples/pristine_recording.wav")
    assert sample.exists()

    with open(sample, "rb") as f:
        r = client.post("/api/scan", files={"file": ("pristine_recording.wav", f, "audio/wav")})

    assert r.status_code == 200
    data = r.json()
    assert "ai_assessment" in data
    assert data["ai_assessment"]["is_tampered"] is False
    assert "AUTHENTIC" in data["ai_assessment"]["verdict"]
