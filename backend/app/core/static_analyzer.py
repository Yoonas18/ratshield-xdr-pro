from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Dict, List

PRINTABLE = set(bytes(range(32, 127)))


def sha256_file(path: str, limit_mb: int = 100) -> str:
    p = Path(path)
    if not p.exists() or not p.is_file() or p.stat().st_size > limit_mb * 1024 * 1024:
        return ""
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy_file(path: str, max_bytes: int = 1024 * 1024) -> float:
    try:
        data = Path(path).read_bytes()[:max_bytes]
    except Exception:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c:
            p = c / len(data)
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def extract_ascii_strings(path: str, min_len: int = 5, max_bytes: int = 2 * 1024 * 1024) -> List[str]:
    try:
        data = Path(path).read_bytes()[:max_bytes]
    except Exception:
        return []
    out, cur = [], bytearray()
    for b in data:
        if b in PRINTABLE:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode(errors="ignore"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode(errors="ignore"))
    return out[:5000]


def lightweight_yara_match(path: str, rule_terms: Dict[str, List[str]]) -> List[str]:
    text = "\n".join(extract_ascii_strings(path)).lower()
    hits = []
    for rule_name, terms in rule_terms.items():
        score = sum(1 for term in terms if term.lower() in text)
        if score >= max(2, min(4, len(terms))):
            hits.append(rule_name)
    return hits
