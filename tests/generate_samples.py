from pathlib import Path
import numpy as np
from scipy.io import wavfile

def generate_test_samples():
    """
    Generate verifiable test audio files:
    1. pristine_recording.wav - Clean signal with natural room noise and 50Hz hum
    2. tampered_splice_cut.wav - Contains an abrupt splice jump and artificial zero silence
    3. lossy_transcode_sim.wav - Sharp 16kHz lowpass brick-wall filter mimicking MP3 transcode
    """
    samples_dir = Path(__file__).resolve().parent / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    
    sr = 44100
    duration = 5.0  # 5 seconds
    t = np.linspace(0, duration, int(sr * duration), endpoint=False)

    # 1. Generate Pristine Sample: Voice formants (220Hz, 440Hz, 880Hz) + subtle room noise + 50Hz hum
    voice = (
        0.35 * np.sin(2 * np.pi * 220 * t) +
        0.20 * np.sin(2 * np.pi * 440 * t) +
        0.10 * np.sin(2 * np.pi * 880 * t)
    )
    # Natural breathing modulation
    envelope = 0.5 + 0.4 * np.sin(2 * np.pi * 0.4 * t)
    voice = voice * envelope
    # Natural thermal/room noise (-60 dB)
    room_noise = np.random.normal(0, 0.002, len(t))
    # Subtle 50Hz electrical hum
    mains_hum = 0.005 * np.sin(2 * np.pi * 50.0 * t)
    pristine = voice + room_noise + mains_hum

    # 2. Generate Tampered Sample: Abrupt splice at 2.5s and digital zeros at 3.5s - 4.0s
    tampered = pristine.copy()
    # Splice edit: abrupt phase shift and 20dB amplitude jump at 2.0s
    splice_idx = int(sr * 2.0)
    tampered[splice_idx:] = tampered[splice_idx:] * 2.8 + 0.2 * np.sin(2 * np.pi * 520 * t[splice_idx:])
    
    # Digital zero insertion (artificial mute/cutout) between 3.5s and 4.0s
    mute_start = int(sr * 3.5)
    mute_end = int(sr * 4.0)
    tampered[mute_start:mute_end] = 0.0

    # 3. Generate Lossy Transcode Simulation: Zero out frequencies above 16 kHz
    fft = np.fft.rfft(pristine)
    freqs = np.fft.rfftfreq(len(pristine), 1.0 / sr)
    fft[freqs > 16000] = 0.0
    lossy = np.fft.irfft(fft, n=len(pristine))

    # Normalize to 16-bit PCM
    def to_pcm16(sig):
        max_val = np.max(np.abs(sig))
        norm = sig / (max_val + 1e-12) * 0.9
        return (norm * 32767).astype(np.int16)

    p1 = samples_dir / "pristine_recording.wav"
    p2 = samples_dir / "tampered_splice_cut.wav"
    p3 = samples_dir / "lossy_transcode_sim.wav"

    wavfile.write(str(p1), sr, to_pcm16(pristine))
    wavfile.write(str(p2), sr, to_pcm16(tampered))
    wavfile.write(str(p3), sr, to_pcm16(lossy))

    print(f"[OK] Generated sample files:\n - {p1}\n - {p2}\n - {p3}")

if __name__ == "__main__":
    generate_test_samples()
