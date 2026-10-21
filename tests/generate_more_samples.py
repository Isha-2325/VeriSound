from pathlib import Path
import numpy as np
from scipy.io import wavfile
from scipy import signal

def generate_all_samples():
    """
    Generate 3 spliced/tampered samples and 5 clean/pristine audio samples.
    """
    samples_dir = Path(__file__).resolve().parent / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    
    sr = 44100
    
    def to_pcm16(sig):
        max_val = np.max(np.abs(sig))
        norm = sig / (max_val + 1e-12) * 0.90
        return (norm * 32767).astype(np.int16)

    # ==========================================
    # 5 CLEAN SAMPLES
    # ==========================================

    # 1. clean_male_speech.wav (5.0s, fundamental ~130Hz)
    dur = 5.0
    t = np.linspace(0, dur, int(sr * dur), endpoint=False)
    f0 = 130.0 + 3.0 * np.sin(2 * np.pi * 0.8 * t)  # natural subtle pitch drift
    voice = (
        0.40 * np.sin(2 * np.pi * f0 * t) +
        0.25 * np.sin(2 * np.pi * 2 * f0 * t) +
        0.15 * np.sin(2 * np.pi * 3 * f0 * t) +
        0.08 * np.sin(2 * np.pi * 4 * f0 * t)
    )
    cadence = 0.5 + 0.45 * np.sin(2 * np.pi * 0.35 * t)  # syllable cadence
    noise = np.random.normal(0, 0.003, len(t))           # natural room tone
    clean_male = voice * cadence + noise
    wavfile.write(str(samples_dir / "clean_male_speech.wav"), sr, to_pcm16(clean_male))

    # 2. clean_female_speech.wav (5.0s, fundamental ~225Hz)
    f0_f = 225.0 + 4.0 * np.sin(2 * np.pi * 1.2 * t)
    voice_f = (
        0.42 * np.sin(2 * np.pi * f0_f * t) +
        0.22 * np.sin(2 * np.pi * 2 * f0_f * t) +
        0.14 * np.sin(2 * np.pi * 3 * f0_f * t) +
        0.06 * np.sin(2 * np.pi * 4 * f0_f * t)
    )
    cadence_f = 0.5 + 0.42 * np.cos(2 * np.pi * 0.4 * t)
    noise_f = np.random.normal(0, 0.0025, len(t))
    clean_female = voice_f * cadence_f + noise_f
    wavfile.write(str(samples_dir / "clean_female_speech.wav"), sr, to_pcm16(clean_female))

    # 3. clean_telephone_call.wav (5.0s, 300Hz-3400Hz bandpassed speech)
    b, a = signal.butter(4, [300 / (sr/2), 3400 / (sr/2)], btype="band")
    tele_raw = clean_male + 0.01 * np.sin(2 * np.pi * 1000 * t)
    clean_tele = signal.filtfilt(b, a, tele_raw) + np.random.normal(0, 0.005, len(t))
    wavfile.write(str(samples_dir / "clean_telephone_call.wav"), sr, to_pcm16(clean_tele))

    # 4. clean_podcast_studio.wav (5.5s, rich harmonics + smooth speech pauses)
    dur4 = 5.5
    t4 = np.linspace(0, dur4, int(sr * dur4), endpoint=False)
    voice_pod = (
        0.38 * np.sin(2 * np.pi * 165 * t4) +
        0.26 * np.sin(2 * np.pi * 330 * t4) +
        0.18 * np.sin(2 * np.pi * 495 * t4) +
        0.10 * np.sin(2 * np.pi * 660 * t4)
    )
    pod_envelope = 0.5 + 0.48 * np.sin(2 * np.pi * 0.28 * t4)
    pod_noise = np.random.normal(0, 0.0018, len(t4))
    clean_podcast = voice_pod * pod_envelope + pod_noise
    wavfile.write(str(samples_dir / "clean_podcast_studio.wav"), sr, to_pcm16(clean_podcast))

    # 5. clean_ambient_interview.wav (6.0s, speech with steady room air conditioner ambiance)
    dur5 = 6.0
    t5 = np.linspace(0, dur5, int(sr * dur5), endpoint=False)
    voice_int = 0.35 * np.sin(2 * np.pi * 190 * t5) + 0.20 * np.sin(2 * np.pi * 380 * t5)
    int_env = 0.5 + 0.44 * np.sin(2 * np.pi * 0.32 * t5)
    steady_ambiance = np.random.normal(0, 0.006, len(t5))  # steady acoustic room ambiance
    clean_interview = voice_int * int_env + steady_ambiance
    wavfile.write(str(samples_dir / "clean_ambient_interview.wav"), sr, to_pcm16(clean_interview))

    # ==========================================
    # 3 SPLICED / TAMPERED SAMPLES
    # ==========================================

    # 1. tampered_speech_redaction.wav (5.0s, mathematical zero flatline inserted at 2.2s - 2.8s)
    redaction = clean_male.copy()
    zero_start = int(sr * 2.2)
    zero_end = int(sr * 2.8)
    redaction[zero_start:zero_end] = 0.0  # Artificial digital silence / muting
    wavfile.write(str(samples_dir / "tampered_speech_redaction.wav"), sr, to_pcm16(redaction))

    # 2. tampered_two_speakers_spliced.wav (5.0s, hard cut joining male and female voices at 2.5s)
    spliced_duo = np.zeros(len(t))
    split_idx = int(sr * 2.5)
    spliced_duo[:split_idx] = clean_male[:split_idx] * 0.7
    # Abrupt splice cut with 22 dB jump in amplitude and abrupt fundamental frequency shift
    spliced_duo[split_idx:] = clean_female[split_idx:] * 2.4
    wavfile.write(str(samples_dir / "tampered_two_speakers_spliced.wav"), sr, to_pcm16(spliced_duo))

    # 3. tampered_room_shift.wav (5.5s, indoor room tone abruptly spliced with loud outdoor noise at 2.8s)
    room_cut = clean_podcast.copy()
    cut_idx = int(sr * 2.8)
    # Inject loud 18 dB ambient room shift starting at 2.8s
    room_cut[cut_idx:] = room_cut[cut_idx:] + np.random.normal(0, 0.045, len(room_cut) - cut_idx)
    wavfile.write(str(samples_dir / "tampered_room_shift.wav"), sr, to_pcm16(room_cut))

    print("[SUCCESS] Generated 5 Clean and 3 Spliced audio samples in tests/samples/.")

if __name__ == "__main__":
    generate_all_samples()
