"""Email header analyser for phishing signals."""
import re
from typing import Dict, Any


# Known spoofable free mail domains
_FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "yandex.com", "mail.com",
}

# Suspicious keywords in subjects
_SUSPICIOUS_SUBJECT_KEYWORDS = [
    "urgent", "action required", "verify", "confirm", "account",
    "suspended", "password", "click here", "limited time", "winner",
    "congratulations", "free", "prize", "lucky", "invoice", "payment",
]


def analyse_headers(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyse parsed email headers for phishing indicators.

    Args:
        parsed_email: dict from eml_parser.parse_eml()

    Returns:
        dict with keys:
            score: float (0.0 to 1.0, higher = more suspicious)
            flags: list[str] describing detected issues
            reply_to_mismatch: bool
            free_sender_domain: bool
            suspicious_subject: bool
            no_message_id: bool
            received_hop_count: int
    """
    flags = []
    score = 0.0

    sender = parsed_email.get("sender", "")
    reply_to = parsed_email.get("reply_to")
    subject = parsed_email.get("subject", "").lower()
    message_id = parsed_email.get("message_id", "")
    sender_domain = parsed_email.get("sender_domain", "")
    headers = parsed_email.get("headers", {})

    # Check reply-to mismatch
    reply_to_mismatch = False
    if reply_to:
        sender_at = re.search(r'@([\w.-]+)', sender or "")
        reply_at = re.search(r'@([\w.-]+)', reply_to or "")
        if sender_at and reply_at:
            if sender_at.group(1).lower() != reply_at.group(1).lower():
                reply_to_mismatch = True
                flags.append("reply_to_domain_mismatch")
                score += 0.3

    # Check free sender domain
    free_sender_domain = sender_domain in _FREE_MAIL_DOMAINS
    if free_sender_domain:
        flags.append("free_sender_domain")
        score += 0.1

    # Check suspicious subject keywords
    suspicious_subject = any(kw in subject for kw in _SUSPICIOUS_SUBJECT_KEYWORDS)
    if suspicious_subject:
        flags.append("suspicious_subject_keyword")
        score += 0.15

    # Check missing message ID
    no_message_id = not message_id or message_id.startswith("00000000")
    if no_message_id:
        flags.append("no_message_id")
        score += 0.1

    # Count received hops
    received = headers.get("Received", [])
    if isinstance(received, str):
        received = [received]
    received_hop_count = len(received)

    # Excessive hops can indicate relay abuse
    if received_hop_count > 8:
        flags.append("excessive_received_hops")
        score += 0.1

    # Check for auth results
    auth_results = headers.get("Authentication-Results", "")
    if isinstance(auth_results, list):
        auth_results = " ".join(auth_results)
    auth_results = auth_results.lower()
    
    if "dkim=fail" in auth_results or "dkim=none" in auth_results:
        flags.append("dkim_fail")
        score += 0.25
    if "spf=fail" in auth_results or "spf=softfail" in auth_results:
        flags.append("spf_fail")
        score += 0.2
    if "dmarc=fail" in auth_results or "dmarc=none" in auth_results:
        flags.append("dmarc_fail")
        score += 0.2

    return {
        "score": min(score, 1.0),
        "flags": flags,
        "reply_to_mismatch": reply_to_mismatch,
        "free_sender_domain": free_sender_domain,
        "suspicious_subject": suspicious_subject,
        "no_message_id": no_message_id,
        "received_hop_count": received_hop_count,
    }
