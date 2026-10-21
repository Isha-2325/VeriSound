import pytest
from pathlib import Path
from tests.generate_samples import generate_test_samples
from app.core.hasher import ForensicHasher
from app.core.metadata_parser import ForensicMetadataParser
from app.core.signal_analyzer import ForensicSignalAnalyzer
from app.core.tamper_detector import ForensicTamperDetector
from app.core.ai_explainer import AIForensicExplainer
from app.core.reporter import ForensicReportGenerator

@pytest.fixture(scope="session", autouse=True)
def setup_samples():
    generate_test_samples()

def test_hasher_and_integrity():
    sample = Path("tests/samples/pristine_recording.wav")
    hashes = ForensicHasher.calculate_hashes(sample)
    assert "sha256" in hashes
    assert len(hashes["sha256"]) == 64
    assert ForensicHasher.verify_integrity(sample, hashes["sha256"]) is True
    entropy = ForensicHasher.calculate_shannon_entropy(sample)
    assert 4.0 <= entropy <= 8.0

def test_splice_and_tamper_detection():
    sample = Path("tests/samples/tampered_splice_cut.wav")
    y, sr, channels = ForensicSignalAnalyzer.load_audio(sample)
    assert sr == 44100
    assert len(y) > 0

    tamper = ForensicTamperDetector.run_tamper_suite(y, sr)
    assert tamper["is_tampered"] is True
    assert tamper["anomaly_count"] > 0

    # Test AI forensic explainer
    hashes = ForensicHasher.calculate_hashes(sample)
    metadata = ForensicMetadataParser.analyze_metadata(sample)
    sig_metrics = ForensicSignalAnalyzer.compute_signal_metrics(y, sr, channels)

    ai_assessment = AIForensicExplainer.generate_assessment(
        tamper_results=tamper,
        metadata_results=metadata,
        signal_metrics=sig_metrics,
        hasher_results=hashes
    )

    assert ai_assessment["is_tampered"] is True
    assert ai_assessment["tamper_probability_pct"] >= 70.0
    assert "TAMPERED" in ai_assessment["verdict"]
    assert len(ai_assessment["findings"]) > 0

def test_pristine_audio_integrity():
    sample = Path("tests/samples/pristine_recording.wav")
    y, sr, channels = ForensicSignalAnalyzer.load_audio(sample)
    tamper = ForensicTamperDetector.run_tamper_suite(y, sr)
    assert tamper["is_tampered"] is False

    hashes = ForensicHasher.calculate_hashes(sample)
    metadata = ForensicMetadataParser.analyze_metadata(sample)
    sig_metrics = ForensicSignalAnalyzer.compute_signal_metrics(y, sr, channels)

    ai = AIForensicExplainer.generate_assessment(tamper, metadata, sig_metrics, hashes)
    assert ai["is_tampered"] is False
    assert "AUTHENTIC" in ai["verdict"]

def test_pdf_report_generation(tmp_path):
    out_pdf = tmp_path / "test_tamper_report.pdf"
    evidence_info = {"filename": "tampered_audio.wav"}
    results = {
        "hashes": {"sha256": "abcdef1234567890", "md5": "123456", "file_size_bytes": 10240, "entropy": 5.4},
        "signal_metrics": {"duration_seconds": 5.0, "sample_rate_hz": 44100, "channels": 1},
        "ai_assessment": {
            "verdict": "TAMPERED / SPLICED AUDIO DETECTED",
            "tamper_probability_pct": 92.5,
            "is_tampered": True,
            "summary_statement": "Automated splice detected.",
            "total_anomalies_count": 1,
            "findings": [
                {"timestamp": "00:02.00", "type": "Splice Cut Boundary", "severity": "CRITICAL", "ai_diagnosis": "Hard splice amplitude step."}
            ]
        }
    }
    ForensicReportGenerator.generate_pdf(out_pdf, evidence_info, results)
    assert out_pdf.exists()
    assert out_pdf.stat().st_size > 1000
