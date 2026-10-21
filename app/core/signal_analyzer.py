import io
import base64
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
from scipy import signal
from scipy.io import wavfile
import soundfile as sf
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server environments
import matplotlib.pyplot as plt

class ForensicSignalAnalyzer:
    """
    Forensic signal processing engine.
    Calculates audio statistics, spectral characteristics (STFT, Centroid, Flux),
    generates forensic spectrogram visual assets, and detects digital clipping.
    """

    @staticmethod
    def load_audio(file_path: Path) -> Tuple[np.ndarray, int, int]:
        """
        Load audio file reliably. Returns (data_float32, sample_rate, original_channels).
        Data is normalized to [-1.0, 1.0] and converted to mono for spectral calculations.
        """
        try:
            data, sr = sf.read(str(file_path), dtype="float32", always_2d=True)
            channels = data.shape[1]
            # Convert to mono by averaging channels
            mono_data = np.mean(data, axis=1)
            return mono_data, sr, channels
        except Exception:
            # Fallback to scipy.io.wavfile if soundfile fails
            sr, data = wavfile.read(str(file_path))
            if data.dtype == np.int16:
                data = data.astype(np.float32) / 32768.0
            elif data.dtype == np.int32:
                data = data.astype(np.float32) / 2147483648.0
            elif data.dtype == np.uint8:
                data = (data.astype(np.float32) - 128.0) / 128.0
            else:
                data = data.astype(np.float32)

            if data.ndim == 2:
                channels = data.shape[1]
                mono_data = np.mean(data, axis=1)
            else:
                channels = 1
                mono_data = data
            return mono_data, sr, channels

    @classmethod
    def compute_signal_metrics(cls, y: np.ndarray, sr: int, channels: int) -> Dict[str, Any]:
        """
        Calculate key physical and statistical metrics of the audio signal.
        """
        total_samples = len(y)
        duration_sec = total_samples / sr if sr > 0 else 0.0

        if total_samples == 0:
            return {"error": "Empty audio buffer"}

        # Peak and RMS Amplitude
        peak = float(np.max(np.abs(y)))
        rms = float(np.sqrt(np.mean(y ** 2)))
        rms_db = 20 * np.log10(rms + 1e-12)
        peak_db = 20 * np.log10(peak + 1e-12)

        # Crest Factor (Peak to RMS ratio in dB)
        crest_factor_db = peak_db - rms_db if rms > 0 else 0.0

        # DC Offset
        dc_offset = float(np.mean(y))

        # Digital Clipping Detection (Samples near 1.0 or -1.0)
        clipping_threshold = 0.999
        clipped_samples = int(np.sum(np.abs(y) >= clipping_threshold))
        clipping_percentage = (clipped_samples / total_samples) * 100.0

        # Dynamic Range
        # Estimate noise floor from bottom 5th percentile of windowed energy
        window_size = min(int(sr * 0.05), total_samples)
        if window_size > 0:
            num_windows = total_samples // window_size
            if num_windows > 1:
                reshaped = y[:num_windows * window_size].reshape((num_windows, window_size))
                win_rms = np.sqrt(np.mean(reshaped ** 2, axis=1))
                noise_floor_rms = np.percentile(win_rms[win_rms > 0], 5) if np.any(win_rms > 0) else 1e-9
                dynamic_range_db = float(20 * np.log10((peak + 1e-12) / (noise_floor_rms + 1e-12)))
            else:
                dynamic_range_db = float(peak_db - rms_db)
        else:
            dynamic_range_db = 0.0

        return {
            "duration_seconds": round(duration_sec, 3),
            "sample_rate_hz": sr,
            "channels": channels,
            "total_samples": total_samples,
            "peak_amplitude": round(peak, 4),
            "peak_db": round(peak_db, 2),
            "rms_amplitude": round(rms, 4),
            "rms_db": round(rms_db, 2),
            "crest_factor_db": round(crest_factor_db, 2),
            "dc_offset": round(dc_offset, 6),
            "clipped_samples_count": clipped_samples,
            "clipping_percentage": round(clipping_percentage, 4),
            "dynamic_range_db": round(dynamic_range_db, 2),
            "is_heavily_clipped": clipping_percentage > 0.1,
            "has_dc_bias": abs(dc_offset) > 0.01
        }

    @classmethod
    def generate_decimated_waveform(cls, y: np.ndarray, num_points: int = 1000) -> Dict[str, List[float]]:
        """
        Generate decimated min/max envelope points for fast, interactive canvas rendering.
        """
        if len(y) == 0:
            return {"min": [], "max": []}

        step = max(1, len(y) // num_points)
        min_vals = []
        max_vals = []

        for i in range(0, len(y), step):
            chunk = y[i:i + step]
            if len(chunk) > 0:
                min_vals.append(float(round(np.min(chunk), 4)))
                max_vals.append(float(round(np.max(chunk), 4)))

        return {"min": min_vals, "max": max_vals}

    @classmethod
    def generate_spectrogram_image(
        cls, y: np.ndarray, sr: int, nperseg: int = 1024, noverlap: int = 512, max_freq_hz: Optional[int] = None
    ) -> str:
        """
        Compute STFT and render a high-resolution dark-mode forensic spectrogram.
        Returns a base64 encoded PNG data URI.
        """
        if len(y) < nperseg:
            nperseg = max(64, len(y) // 2)
            noverlap = nperseg // 2

        freqs, times, Zxx = signal.stft(y, fs=sr, nperseg=nperseg, noverlap=noverlap)
        magnitude = np.abs(Zxx)
        # Convert to dB relative to maximum
        ref = np.max(magnitude) if np.max(magnitude) > 0 else 1.0
        spectrogram_db = 20 * np.log10(magnitude / ref + 1e-6)
        spectrogram_db = np.clip(spectrogram_db, -80.0, 0.0)

        if max_freq_hz is not None:
            freq_mask = freqs <= max_freq_hz
            freqs = freqs[freq_mask]
            spectrogram_db = spectrogram_db[freq_mask, :]

        # Render forensic visualization with Matplotlib
        fig, ax = plt.subplots(figsize=(12, 4.5), facecolor="#0f172a")
        ax.set_facecolor("#0f172a")

        c = ax.pcolormesh(
            times, freqs, spectrogram_db,
            shading="gouraud", cmap="inferno", vmin=-80, vmax=0
        )

        ax.set_title("Forensic High-Resolution STFT Spectrogram", color="#e2e8f0", fontsize=12, pad=10, fontweight="bold")
        ax.set_xlabel("Time (seconds)", color="#94a3b8", fontsize=10)
        ax.set_ylabel("Frequency (Hz)", color="#94a3b8", fontsize=10)
        ax.tick_params(colors="#94a3b8", labelsize=9)
        for spine in ax.spines.values():
            spine.set_color("#334155")

        cb = fig.colorbar(c, ax=ax, pad=0.02)
        cb.set_label("Magnitude (dB)", color="#94a3b8", fontsize=9)
        cb.ax.tick_params(colors="#94a3b8", labelsize=8)

        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format="png", dpi=120, bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
        plt.close(fig)
        buf.seek(0)
        
        base64_data = base64.b64encode(buf.read()).decode("utf-8")
        return f"data:image/png;base64,{base64_data}"
