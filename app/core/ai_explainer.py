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
        
        # This is a conservative screening score, not a calibrated probability.
        score = 0.0
        findings: List[Dict[str, Any]] = []

        # 1. Splice & Energy Discontinuity Analysis
        splice_anomalies = [a for a in anomalies if "Energy" in a.get("anomaly_type", "")]
        if splice_anomalies:
            weight = min(30.0, len(splice_anomalies) * 15.0)
            score += weight
            for s in splice_anomalies:
                t = s.get("timestamp_sec", 0.0)
                db = s.get("delta_db", 0.0)
                findings.append({
                    "timestamp": f"{int(t // 60):02d}:{t % 60:05.2f}",
                    "timestamp_sec": t,
                    "type": "Abrupt Level Change (Candidate)",
                    "severity": "MEDIUM",
                    "ai_diagnosis": (
                        f"A {db} dB level change was found between adjacent analysis frames. "
                        "This can occur at an edit, but also from music beats, speech dynamics, or audio processing; "
                        "this signal alone does not establish a splice."
                    )
                })

        # Exact zeros can occur in intentionally silent or digitally generated audio,
        # so they are only a supporting indicator and never proof of redaction.
        zero_anomalies = [a for a in anomalies if "Silence" in a.get("anomaly_type", "")]
        if zero_anomalies:
            score += 40.0
            for z in zero_anomalies:
                s_time = z.get("start_sec", 0.0)
                dur = z.get("duration_sec", 0.0)
                findings.append({
                    "timestamp": f"{int(s_time // 60):02d}:{s_time % 60:05.2f}",
                    "timestamp_sec": s_time,
                    "type": "Exact Digital Silence",
                    "severity": "MEDIUM",
                    "ai_diagnosis": (
                        f"Detected {dur}s of exact zero-amplitude samples. "
                        "This may be an intentional mute or a naturally/digitally silent section; by itself it does not prove editing."
                    )
                })

        # Changes in estimated room tone are common in mixed music and speech and
        # are reported for review, but do not contribute to the edit score.
        noise_anomalies = [a for a in anomalies if "Noise" in a.get("anomaly_type", "")]
        if noise_anomalies:
            for n in noise_anomalies:
                t = n.get("timestamp_sec", 0.0)
                jump = n.get("noise_jump_db", 0.0)
                findings.append({
                    "timestamp": f"{int(t // 60):02d}:{t % 60:05.2f}",
                    "timestamp_sec": t,
                    "type": "Background Level Variation",
                    "severity": "MEDIUM",
                    "ai_diagnosis": (
                        f"The estimated background level changed by {jump} dB. "
                        "Changing content, music, or recording conditions can cause this; it is not proof of a splice."
                    )
                })

        # Metadata can identify processing, but processing alone is not evidence of
        # deceptive editing.
        if software_footprints:
            for sw in software_footprints:
                findings.append({
                    "timestamp": "Header / Metadata",
                    "timestamp_sec": 0.0,
                    "type": "Audio Processing Metadata",
                    "severity": "INFO",
                    "ai_diagnosis": f"Metadata references audio software ({sw}); this does not establish that the audio was deceptively edited."
                })

        indicator_score = round(min(99.9, max(0.0, score)), 1)

        # A high score requires exact digital silence plus multiple abrupt level
        # changes; isolated changes are common in ordinary music and speech.
        if indicator_score >= 70.0:
            verdict = "STRONG EDIT INDICATORS — REVIEW REQUIRED"
            verdict_badge = "danger"
            summary_statement = (
                f"Automated screening found {len(findings)} indicator(s) that merit manual review. "
                "These heuristics cannot confirm whether audio was edited or establish its authenticity."
            )
        elif indicator_score >= 20.0:
            verdict = "POTENTIAL EDIT INDICATORS — NOT A CONCLUSION"
            verdict_badge = "warning"
            summary_statement = (
                f"Automated screening flagged {len(findings)} signal variation(s). "
                "Music, speech dynamics, compression, and ordinary processing can produce these; review the timestamps in context."
            )
        else:
            verdict = "NO STRONG EDIT INDICATORS DETECTED"
            verdict_badge = "success"
            summary_statement = (
                "The automated checks found no strong edit indicators. This is not proof that the recording is authentic or unedited."
            )

        return {
            "verdict": verdict,
            "verdict_badge": verdict_badge,
            "indicator_score_pct": indicator_score,
            "tamper_probability_pct": indicator_score,
            "is_tampered": indicator_score >= 70.0,
            "summary_statement": summary_statement,
            "total_anomalies_count": len(findings),
            "findings": findings
        }
