"""Extract and validate IP addresses from text."""
import re
from typing import List

_IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

_PRIVATE_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^169\.254\.'),
    re.compile(r'^::1$'),
    re.compile(r'^0\.0\.0\.0$'),
]


def is_private(ip: str) -> bool:
    return any(p.match(ip) for p in _PRIVATE_RANGES)


def extract_ips(text: str) -> List[str]:
    """Extract unique public IPs from text."""
    found = _IP_RE.findall(text or "")
    return list(dict.fromkeys(ip for ip in found if not is_private(ip)))
