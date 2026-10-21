import hashlib
import math
from pathlib import Path
from typing import Dict, Any, List

class ForensicHasher:
    """
    Cryptographic integrity and hashing engine for digital audio forensics.
    Provides verifiable chain-of-custody hashes and byte entropy analysis.
    """
    
    @staticmethod
    def calculate_hashes(file_path: Path) -> Dict[str, str]:
        """
        Compute MD5, SHA-1, SHA-256, and SHA-512 hashes using streaming reads
        to prevent memory exhaustion on large audio files.
        """
        md5_h = hashlib.md5()
        sha1_h = hashlib.sha1()
        sha256_h = hashlib.sha256()
        sha512_h = hashlib.sha512()
        
        file_size = 0
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                file_size += len(chunk)
                md5_h.update(chunk)
                sha1_h.update(chunk)
                sha256_h.update(chunk)
                sha512_h.update(chunk)
                
        return {
            "md5": md5_h.hexdigest(),
            "sha1": sha1_h.hexdigest(),
            "sha256": sha256_h.hexdigest(),
            "sha512": sha512_h.hexdigest(),
            "file_size_bytes": file_size,
        }

    @staticmethod
    def verify_integrity(file_path: Path, expected_sha256: str) -> bool:
        """
        Verify if the file currently matches the expected SHA-256 registered in the chain of custody.
        """
        sha256_h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256_h.update(chunk)
        return sha256_h.hexdigest().lower() == expected_sha256.lower()

    @staticmethod
    def calculate_shannon_entropy(file_path: Path) -> float:
        """
        Calculate the Shannon byte entropy (0.0 to 8.0 bits per byte).
        - Uncompressed PCM audio: ~4.5 - 6.5
        - Compressed audio (MP3/AAC): ~7.5 - 7.98
        - Encrypted / Random data: ~7.99 - 8.0
        """
        byte_counts = [0] * 256
        total_bytes = 0
        
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                total_bytes += len(chunk)
                for b in chunk:
                    byte_counts[b] += 1
                    
        if total_bytes == 0:
            return 0.0
            
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)
                
        return round(entropy, 4)

    @staticmethod
    def get_hex_preview(file_path: Path, max_bytes: int = 128) -> List[Dict[str, Any]]:
        """
        Extract the first N bytes formatted as forensic hex dump with ASCII representation.
        """
        rows = []
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
            
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            rows.append({
                "offset": f"{i:08X}",
                "hex": hex_str.ljust(48),
                "ascii": ascii_str
            })
            
        return rows
