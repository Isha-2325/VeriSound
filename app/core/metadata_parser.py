import struct
from pathlib import Path
from typing import Dict, Any, List, Optional
import mutagen

class ForensicMetadataParser:
    """
    Forensic metadata parser and container integrity validator.
    Performs deep binary header inspection for RIFF/WAV formats,
    detects tampering, and extracts audio container tags.
    """

    MAGIC_NUMBERS = {
        b"RIFF": "WAV / RIFF Audio",
        b"ID3": "MP3 Audio (ID3v2 Tagged)",
        b"\xff\xfb": "MP3 Audio (MPEG-1 Layer 3)",
        b"\xff\xf3": "MP3 Audio (MPEG-2 Layer 3)",
        b"\xff\xf2": "MP3 Audio (MPEG-2.5 Layer 3)",
        b"fLaC": "FLAC Lossless Audio",
        b"OggS": "OGG Vorbis Container",
        b"ftyp": "M4A / MP4 Audio",
    }

    @classmethod
    def identify_format_by_magic(cls, file_path: Path) -> Dict[str, Any]:
        """
        Verify the actual file format using magic bytes rather than relying on file extension.
        """
        with open(file_path, "rb") as f:
            header = f.read(32)

        matched_format = "Unknown / Raw Binary"
        is_riff = header.startswith(b"RIFF")
        
        for magic, desc in cls.MAGIC_NUMBERS.items():
            if header.startswith(magic):
                matched_format = desc
                break
            elif magic == b"ftyp" and b"ftyp" in header[4:12]:
                matched_format = desc
                break

        return {
            "magic_bytes_hex": header[:8].hex().upper(),
            "detected_format": matched_format,
            "is_riff": is_riff
        }

    @classmethod
    def parse_riff_chunks(cls, file_path: Path) -> Dict[str, Any]:
        """
        Deep binary parse of RIFF/WAV chunks:
        Checks fmt chunk, data chunk, chunk sizes, byte rates, and block alignment.
        Flags tampering if computed parameters disagree with recorded headers.
        """
        anomalies: List[str] = []
        chunks: List[Dict[str, Any]] = []
        file_size = file_path.stat().st_size
        
        info: Dict[str, Any] = {
            "audio_format": None,
            "channels": None,
            "sample_rate": None,
            "byte_rate": None,
            "block_align": None,
            "bits_per_sample": None,
            "data_size": 0,
            "calculated_duration_sec": 0.0,
            "chunks": chunks,
            "anomalies": anomalies
        }

        try:
            with open(file_path, "rb") as f:
                riff_tag = f.read(4)
                if riff_tag != b"RIFF":
                    return {"is_valid_riff": False, "message": "Not a valid RIFF file."}

                riff_size = struct.unpack("<I", f.read(4))[0]
                wave_tag = f.read(4)

                if wave_tag != b"WAVE":
                    anomalies.append("Header contains 'RIFF' but missing 'WAVE' identifier.")
                    return {"is_valid_riff": False, "anomalies": anomalies}

                # Check if RIFF header length matches physical file size
                expected_file_size = riff_size + 8
                if abs(expected_file_size - file_size) > 4:
                    anomalies.append(
                        f"RIFF size header mismatch: header claims {expected_file_size} bytes, "
                        f"actual file size is {file_size} bytes (difference: {file_size - expected_file_size} bytes). Possible trailing data or truncation."
                    )

                # Parse subsequent chunks
                while f.tell() < file_size - 8:
                    chunk_id = f.read(4)
                    if len(chunk_id) < 4:
                        break
                    
                    try:
                        chunk_size = struct.unpack("<I", f.read(4))[0]
                    except struct.error:
                        break

                    chunk_id_str = chunk_id.decode("ascii", errors="replace")
                    chunk_offset = f.tell() - 8

                    chunks.append({
                        "id": chunk_id_str,
                        "size": chunk_size,
                        "offset": chunk_offset
                    })

                    if chunk_id == b"fmt ":
                        fmt_data = f.read(min(chunk_size, 40))
                        if len(fmt_data) >= 16:
                            audio_fmt, channels, sample_rate, byte_rate, block_align, bits = struct.unpack("<HHIIHH", fmt_data[:16])
                            info["audio_format"] = "PCM (Uncompressed)" if audio_fmt == 1 else f"Compressed / Codec ID: {audio_fmt}"
                            info["channels"] = channels
                            info["sample_rate"] = sample_rate
                            info["byte_rate"] = byte_rate
                            info["block_align"] = block_align
                            info["bits_per_sample"] = bits

                            # Integrity checks on audio math
                            expected_block_align = channels * (bits // 8)
                            if block_align != expected_block_align:
                                anomalies.append(
                                    f"BlockAlign anomaly: header specifies {block_align}, expected {expected_block_align}."
                                )

                            expected_byte_rate = sample_rate * expected_block_align
                            if byte_rate != expected_byte_rate:
                                anomalies.append(
                                    f"ByteRate anomaly: header specifies {byte_rate}, expected {expected_byte_rate}."
                                )

                        # Skip remaining fmt chunk bytes if extended
                        if chunk_size > len(fmt_data):
                            f.seek(chunk_size - len(fmt_data), 1)

                    elif chunk_id == b"data":
                        info["data_size"] = chunk_size
                        if info["byte_rate"] and info["byte_rate"] > 0:
                            info["calculated_duration_sec"] = round(chunk_size / info["byte_rate"], 3)
                        # Skip data content to inspect remaining chunks (e.g. LIST, INFO)
                        f.seek(chunk_size, 1)

                    elif chunk_id == b"LIST":
                        list_type = f.read(4).decode("ascii", errors="replace")
                        list_content = f.read(chunk_size - 4).decode("latin-1", errors="replace")
                        chunks[-1]["type"] = list_type
                        chunks[-1]["content_snippet"] = list_content[:100]
                    else:
                        # Skip chunk
                        f.seek(chunk_size, 1)

                    # RIFF chunks are word-aligned (padded with 0 if odd)
                    if chunk_size % 2 != 0:
                        f.seek(1, 1)

        except Exception as e:
            anomalies.append(f"Parsing error occurred during RIFF traversal: {str(e)}")

        info["is_valid_riff"] = True
        return info

    @classmethod
    def extract_mutagen_tags(cls, file_path: Path) -> Dict[str, Any]:
        """
        Extract container-level metadata tags (encoder tags, software, title, date).
        Flags editing software footprints (Audacity, Adobe Audition, Pro Tools, FFmpeg/Lavf).
        """
        tags: Dict[str, Any] = {}
        suspicious_footprints: List[str] = []

        try:
            audio_file = mutagen.File(file_path)
            if audio_file is not None and audio_file.tags:
                for k, v in audio_file.tags.items():
                    val_str = str(v)
                    tags[k] = val_str
                    
                    # Check for editing/encoding software signatures
                    lower_val = val_str.lower()
                    if any(sig in lower_val for sig in ["audacity", "audition", "pro tools", "reaper", "lavf", "sound forge", "logic", "goldwave"]):
                        suspicious_footprints.append(f"Editing software signature found in tag '{k}': {val_str}")
        except Exception:
            # Not all files have standard mutagen tags (e.g. raw wav without id3)
            pass

        return {
            "tags": tags,
            "software_footprints": suspicious_footprints
        }

    @classmethod
    def analyze_metadata(cls, file_path: Path) -> Dict[str, Any]:
        """
        Execute full forensic metadata evaluation combining magic bytes, RIFF chunk layout,
        and container tags.
        """
        magic_info = cls.identify_format_by_magic(file_path)
        riff_info = cls.parse_riff_chunks(file_path) if magic_info["is_riff"] else {"is_valid_riff": False}
        tag_info = cls.extract_mutagen_tags(file_path)

        extension = file_path.suffix.lower()
        tamper_flags = []

        # Extension vs Magic mismatch
        if extension == ".wav" and not magic_info["is_riff"]:
            tamper_flags.append(f"Extension spoofing: File has .wav extension but magic header indicates {magic_info['detected_format']}.")
        elif extension == ".mp3" and "MP3" not in magic_info["detected_format"]:
            tamper_flags.append(f"Extension spoofing: File has .mp3 extension but magic header indicates {magic_info['detected_format']}.")

        if riff_info.get("anomalies"):
            tamper_flags.extend(riff_info["anomalies"])
            
        if tag_info.get("software_footprints"):
            tamper_flags.extend(tag_info["software_footprints"])

        return {
            "filename": file_path.name,
            "magic_info": magic_info,
            "riff_info": riff_info,
            "tag_info": tag_info,
            "tamper_flags": tamper_flags,
            "has_metadata_tampering": len(tamper_flags) > 0
        }
