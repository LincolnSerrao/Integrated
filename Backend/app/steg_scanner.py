import os
from pathlib import Path
from typing import Any

def _scan_jpeg(file_path: Path, file_size: int, content: bytes) -> dict[str, Any]:
    # JPEG end of image marker is FF D9
    eoi_index = content.rfind(b'\xff\xd9')
    if eoi_index == -1:
        return {
            "engine": "steg",
            "decision": "BLOCKED",
            "fused_risk": 0.9,
            "reasons": ["Missing End of Image (FF D9) marker for JPEG"]
        }
    
    extra_bytes = file_size - (eoi_index + 2)
    if extra_bytes > 0:
        return {
            "engine": "steg",
            "decision": "BLOCKED",
            "fused_risk": 0.95,
            "reasons": [f"Appended data detected after JPEG EOI marker ({extra_bytes} bytes)"]
        }
        
    return {
        "engine": "steg",
        "decision": "ALLOWED",
        "fused_risk": 0.1,
        "reasons": ["No hidden data found after JPEG EOI marker"]
    }

def _scan_png(file_path: Path, file_size: int, content: bytes) -> dict[str, Any]:
    # PNG end of file is IEND chunk: 00 00 00 00 49 45 4E 44 AE 42 60 82
    # Let's search for the IEND string
    iend_idx = content.rfind(b'IEND')
    if iend_idx == -1:
        return {
            "engine": "steg",
            "decision": "BLOCKED",
            "fused_risk": 0.9,
            "reasons": ["Missing IEND chunk for PNG"]
        }
    
    # IEND chunk is 4 bytes 'IEND' + 4 bytes CRC
    eoi_index = iend_idx + 8
    extra_bytes = file_size - eoi_index
    if extra_bytes > 0:
        return {
            "engine": "steg",
            "decision": "BLOCKED",
            "fused_risk": 0.95,
            "reasons": [f"Appended data detected after PNG IEND chunk ({extra_bytes} bytes)"]
        }
        
    return {
        "engine": "steg",
        "decision": "ALLOWED",
        "fused_risk": 0.1,
        "reasons": ["No hidden data found after PNG IEND chunk"]
    }

def scan_image(file_path: str | Path) -> dict[str, Any]:
    target = Path(file_path)
    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Target file not found: {target}")

    file_size = target.stat().st_size
    try:
        with target.open("rb") as f:
            content = f.read()
    except Exception as exc:
        return {
            "engine": "steg",
            "decision": "UNCERTAIN",
            "fused_risk": 0.5,
            "reasons": [f"Failed to read file for steganalysis: {exc}"]
        }
        
    magic = content[:4]
    
    # Check Magic Bytes
    if magic.startswith(b'\xff\xd8'): # JPEG
        return _scan_jpeg(target, file_size, content)
    elif magic.startswith(b'\x89PNG'): # PNG
        return _scan_png(target, file_size, content)
    else:
        return {
            "engine": "steg",
            "decision": "UNCERTAIN",
            "fused_risk": 0.4,
            "reasons": ["Not a recognized JPEG or PNG image format for steganalysis"]
        }
