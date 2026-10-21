from typing import Dict, Any, List, Tuple
import numpy as np

class ForensicTamperDetector:
    """
    Forensic splice, cut, and edit detection engine.
    Detects abrupt energy transitions, zero-sample digital muting,
    zero-crossing anomalies, and background noise floor shifts across segments.
    """

    @classmethod
    def detect_digital_silence_runs(cls, y: np.ndarray, sr: int, min_duration_sec: float = 0.05) -> List[Dict[str, Any]]:
        """
        Detect runs of perfect digital zeros (exact flatline).
        Real-world microphone recordings always contain thermal and acoustic room noise.
        Exact zeros indicate artificial redaction, muting, or DAW zeroing.
        """
        min_samples = int(sr * min_duration_sec)
        zero_runs = []
        
        is_zero = np.abs(y) < 1e-8
        
        # Find continuous runs
        diff = np.diff(is_zero.astype(np.int8))
        starts = np.where(diff == 1)[0] + 1
        ends = np.where(diff == -1)[0] + 1
        
        if is_zero[0]:
            starts = np.insert(starts, 0, 0)
        if is_zero[-1]:
            ends = np.append(ends, len(y))
            
        for s, e in zip(starts, ends):
            length = e - s
            if length >= min_samples:
                start_time = round(s / sr, 3)
                end_time = round(e / sr, 3)
                duration = round((e - s) / sr, 3)
                zero_runs.append({
                    "start_sec": start_time,
                    "end_sec": end_time,
                    "duration_sec": duration,
                    "anomaly_type": "Synthetic Digital Silence (Exact Zeros)",
                    "severity": "HIGH",
                    "explanation": f"Detected {duration}s of mathematically flat zero amplitude, impossible in genuine analog/microphone captures."
                })
                
        return zero_runs

    @classmethod
    def detect_energy_discontinuities(
        cls, y: np.ndarray, sr: int, frame_ms: float = 25.0, hop_ms: float = 10.0, threshold_sigma: float = 3.5
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Detect abrupt splice cuts using short-time RMS energy differentials.
        Splices create unnatural step changes in signal amplitude between frames.
        """
        frame_len = max(64, int(sr * (frame_ms / 1000.0)))
        hop_len = max(32, int(sr * (hop_ms / 1000.0)))
        
        if len(y) < frame_len * 2:
            return [], {"rms_series": [], "timestamps": []}

        # Frame the signal
        num_frames = 1 + (len(y) - frame_len) // hop_len
        frames = np.lib.stride_tricks.as_strided(
            y,
            shape=(num_frames, frame_len),
            strides=(y.strides[0] * hop_len, y.strides[0])
        )
        
        # Calculate RMS energy per frame
        rms_values = np.sqrt(np.mean(frames ** 2, axis=1))
        # Log RMS energy in dB
        rms_db = 20 * np.log10(rms_values + 1e-9)
        
        # Compute first-order absolute differential
        delta_rms = np.abs(np.diff(rms_db))
        timestamps = np.arange(num_frames) * (hop_len / sr)
        
        mean_delta = np.mean(delta_rms)
        std_delta = np.std(delta_rms)
        cutoff = mean_delta + (threshold_sigma * std_delta)
        
        anomaly_indices = np.where(delta_rms > max(cutoff, 18.0))[0]  # At least 18 dB step change
        
        anomalies = []
        # Group adjacent frames to report distinct splice points
        for idx in anomaly_indices:
            t = round(float(timestamps[idx]), 3)
            jump_db = round(float(delta_rms[idx]), 2)
            # Avoid reporting duplicate alerts within 0.15s
            if not anomalies or (t - anomalies[-1]["timestamp_sec"]) > 0.15:
                anomalies.append({
                    "timestamp_sec": t,
                    "delta_db": jump_db,
                    "anomaly_type": "Abrupt Energy Discontinuity (Splice Candidate)",
                    "severity": "CRITICAL" if jump_db > 25.0 else "MEDIUM",
                    "explanation": f"Instantaneous amplitude step of {jump_db} dB detected across adjacent frames."
                })

        # Decimate series for frontend visualization (e.g. 300 points)
        step = max(1, len(rms_db) // 300)
        decimated_rms = [round(float(v), 2) for v in rms_db[::step]]
        decimated_time = [round(float(t), 2) for t in timestamps[::step]]

        chart_data = {
            "rms_series": decimated_rms,
            "timestamps": decimated_time
        }

        return anomalies, chart_data

    @classmethod
    def analyze_noise_floor_stability(cls, y: np.ndarray, sr: int, segment_sec: float = 2.0) -> List[Dict[str, Any]]:
        """
        Evaluate acoustic room noise consistency across longer segments.
        If segments have wildly differing minimum noise floors, the audio was likely
        compiled from recordings made in different environments or microphone setups.
        """
        seg_samples = int(sr * segment_sec)
        total_samples = len(y)
        
        if total_samples < seg_samples * 2:
            return []

        num_segs = total_samples // seg_samples
        noise_floors = []

        for i in range(num_segs):
            chunk = y[i * seg_samples:(i + 1) * seg_samples]
            # Use 5th percentile of amplitude envelope as noise floor proxy
            envelope = np.abs(chunk)
            floor_val = np.percentile(envelope, 5)
            floor_db = 20 * np.log10(floor_val + 1e-9)
            noise_floors.append(floor_db)

        noise_floors = np.array(noise_floors)
        anomalies = []
        
        # Check for sudden noise floor jumps (> 12 dB) between consecutive 2s blocks
        for i in range(1, len(noise_floors)):
            diff_db = abs(noise_floors[i] - noise_floors[i - 1])
            if diff_db > 14.0:
                seg_time = round(i * segment_sec, 2)
                anomalies.append({
                    "timestamp_sec": seg_time,
                    "noise_jump_db": round(float(diff_db), 2),
                    "anomaly_type": "Acoustic Environment / Noise Floor Shift",
                    "severity": "MEDIUM",
                    "explanation": f"Background room noise floor shifted by {round(float(diff_db), 1)} dB between adjacent recording segments."
                })

        return anomalies

    @classmethod
    def run_tamper_suite(cls, y: np.ndarray, sr: int) -> Dict[str, Any]:
        """
        Execute comprehensive tampering analysis combining zero runs,
        energy discontinuities, and ambient noise shifts.
        """
        silence_runs = cls.detect_digital_silence_runs(y, sr)
        energy_splices, chart_data = cls.detect_energy_discontinuities(y, sr)
        noise_shifts = cls.analyze_noise_floor_stability(y, sr)

        all_anomalies = []
        all_anomalies.extend(silence_runs)
        all_anomalies.extend(energy_splices)
        all_anomalies.extend(noise_shifts)

        # Sort anomalies chronologically
        all_anomalies.sort(key=lambda x: x.get("timestamp_sec", x.get("start_sec", 0.0)))

        is_tampered = len(all_anomalies) > 0
        critical_count = sum(1 for a in all_anomalies if a.get("severity") == "CRITICAL")

        verdict = "INCONCLUSIVE / CLEAN"
        if critical_count > 0:
            verdict = "HIGH PROBABILITY OF TAMPERING (Splices Detected)"
        elif len(all_anomalies) > 0:
            verdict = "POTENTIAL EDITING / ANOMALIES FLAGGED"
        else:
            verdict = "NO EDITING ARTIFACTS DETECTED"

        return {
            "verdict": verdict,
            "is_tampered": is_tampered,
            "anomaly_count": len(all_anomalies),
            "anomalies": all_anomalies,
            "chart_data": chart_data
        }
