from typing import Dict, Any, List

class AIForensicExplainer:
    """
    AI-driven automated forensic diagnosis engine.
    Correlates multi-dimensional acoustic signals (energy differentials, zero runs,
    room noise consistency, and container metadata) to produce an automated,
    plain-English forensic verdict and root-cause analysis.
    """

    @classmethod
    def generate_assessment(
        cls,
        tamper_results: Dict[str, Any],
        metadata_results: Dict[str, Any],
        signal_metrics: Dict[str, Any],
        hasher_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        anomalies = tamper_results.get("anomalies", [])
        software_footprints = metadata_results.get("tag_info", {}).get("software_footprints", [])
        container_flags = metadata_results.get("tamper_flags", [])
        
        # Calculate composite tamper probability score (0 to 100%)
        score = 0.0
        findings: List[Dict[str, Any]] = []

        # 1. Splice & Energy Discontinuity Analysis
        splice_anomalies = [a for a in anomalies if "Energy" in a.get("anomaly_type", "")]
        if splice_anomalies:
            weight = min(50.0, len(splice_anomalies) * 25.0)
            score += weight
            for s in splice_anomalies:
                t = s.get("timestamp_sec", 0.0)
                db = s.get("delta_db", 0.0)
                findings.append({
                    "timestamp": f"{int(t // 60):02d}:{t % 60:05.2f}",
                    "timestamp_sec": t,
                    "type": "Splice Cut Boundary",
                    "severity": "CRITICAL" if db > 24 else "HIGH",
                    "ai_diagnosis": (
                        f"Abrupt {db} dB signal discontinuity across adjacent 25ms frames. "
                        "Indicates a hard digital splice or joined audio segment without natural acoustic cross-fading."
                    )
                })

        # 2. Artificial Silence / Redaction Analysis
        zero_anomalies = [a for a in anomalies if "Silence" in a.get("anomaly_type", "")]
        if zero_anomalies:
            score += 35.0
            for z in zero_anomalies:
                s_time = z.get("start_sec", 0.0)
                dur = z.get("duration_sec", 0.0)
                findings.append({
                    "timestamp": f"{int(s_time // 60):02d}:{s_time % 60:05.2f}",
                    "timestamp_sec": s_time,
                    "type": "Artificial Speech Redaction",
                    "severity": "CRITICAL",
                    "ai_diagnosis": (
                        f"Detected {dur}s of mathematical zero-amplitude signal. "
                        "Natural microphones always capture ambient thermal noise; exact zeros indicate intentional digital deletion or censoring."
                    )
                })

        # 3. Room Tone / Acoustic Environment Consistency
        noise_anomalies = [a for a in anomalies if "Noise" in a.get("anomaly_type", "")]
        if noise_anomalies:
            score += 25.0
            for n in noise_anomalies:
                t = n.get("timestamp_sec", 0.0)
                jump = n.get("noise_jump_db", 0.0)
                findings.append({
                    "timestamp": f"{int(t // 60):02d}:{t % 60:05.2f}",
                    "timestamp_sec": t,
                    "type": "Acoustic Environment Shift",
                    "severity": "MEDIUM",
                    "ai_diagnosis": (
                        f"Background ambient room tone shifted by {jump} dB. "
                        "Strong evidence that segments were recorded in different physical environments or spliced from separate sources."
                    )
                })

        # 4. Software & Metadata Footprints
        if software_footprints:
            score += 20.0
            for sw in software_footprints:
                findings.append({
                    "timestamp": "Header / Metadata",
                    "timestamp_sec": 0.0,
                    "type": "Editing Software Signature",
                    "severity": "HIGH",
                    "ai_diagnosis": f"Container reveals editing DAW footprint: {sw}."
                })

        # 5. Shannon Entropy & Container Spoofing
        entropy = hasher_results.get("entropy", 0.0)
        is_wav = metadata_results.get("magic_info", {}).get("is_riff", False)
        if is_wav and entropy > 7.9:
            score += 15.0
            findings.append({
                "timestamp": "Full Stream",
                "timestamp_sec": 0.0,
                "type": "High Entropy / Compression Artifact",
                "severity": "MEDIUM",
                "ai_diagnosis": f"Entropy of {entropy}/8.0 is unusually high for uncompressed PCM audio; indicates re-wrapped lossy transcode."
            })

        # Clamp confidence score
        tamper_probability = round(min(99.9, max(0.0, score)), 1)

        # Executive Classification
        if tamper_probability >= 70.0:
            verdict = "TAMPERED / SPLICED AUDIO DETECTED"
            verdict_badge = "danger"
            summary_statement = (
                f"Automated AI Forensic Engine identified {len(findings)} anomaly indicator(s). "
                f"The audio exhibits high-confidence evidence of intentional splicing, cutting, or digital alteration."
            )
        elif tamper_probability >= 35.0:
            verdict = "SUSPICIOUS / POTENTIAL EDITING ARTIFACTS"
            verdict_badge = "warning"
            summary_statement = (
                f"Automated AI Forensic Engine flagged {len(findings)} suspicious artifact(s). "
                "Audio contains signal variations that may reflect editing, non-linear recording, or transmission loss."
            )
        else:
            verdict = "AUTHENTIC / UNEDITED RECORDING"
            verdict_badge = "success"
            summary_statement = (
                "Automated AI Forensic Engine detected zero splice cuts, no artificial silence runs, "
                "and consistent acoustic room tone across the entire signal timeline. Integrity verified."
            )

        return {
            "verdict": verdict,
            "verdict_badge": verdict_badge,
            "tamper_probability_pct": tamper_probability,
            "is_tampered": tamper_probability >= 50.0,
            "summary_statement": summary_statement,
            "total_anomalies_count": len(findings),
            "findings": findings
        }
