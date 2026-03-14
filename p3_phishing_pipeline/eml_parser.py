"""EML parser for phishing pipeline."""
import email
import re
import uuid
from email import policy
from email.parser import BytesParser, Parser
from typing import IO, Union


# URL regex
_URL_RE = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE,
)

# IP in Received header: "from x.x.x.x" or "[x.x.x.x]"
_IP_RE = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)


def _extract_urls(text: str) -> list:
    """Extract HTTP/HTTPS URLs from text."""
    return list(dict.fromkeys(_URL_RE.findall(text or "")))


def _extract_ips_from_received(received_headers: list) -> list:
    """Extract IPs from Received headers."""
    ips = []
    for h in (received_headers or []):
        found = _IP_RE.findall(h)
        for ip in found:
            if ip not in ips and not ip.startswith("127.") and ip != "0.0.0.0":
                ips.append(ip)
    return ips


def _sender_domain(sender: str) -> str:
    """Extract domain from email sender string."""
    match = re.search(r'@([\w.-]+)', sender or "")
    return match.group(1).lower() if match else ""


def parse_eml(source: Union[str, bytes, IO]) -> dict:
    """
    Parse an EML file/string/bytes.

    Args:
        source: file path string, bytes, or file-like object

    Returns:
        dict with parsed email fields
    """
    if isinstance(source, str) and not source.startswith(("From ", "Return-Path", "Received", "MIME", "Date", "Message")):
        # Treat as file path
        try:
            with open(source, "rb") as fh:
                msg = BytesParser(policy=policy.default).parse(fh)
        except (OSError, IOError):
            # Try parsing as raw string
            msg = Parser(policy=policy.default).parsestr(source)
    elif isinstance(source, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(source)
    elif hasattr(source, "read"):
        msg = BytesParser(policy=policy.default).parse(source)
    else:
        msg = Parser(policy=policy.default).parsestr(str(source))

    # Extract fields
    message_id = msg.get("Message-ID", "").strip("<>") or str(uuid.uuid4())
    subject = str(msg.get("Subject", ""))
    sender = str(msg.get("From", ""))
    sender_domain = _sender_domain(sender)
    
    # Recipients
    to_header = msg.get("To", "") or ""
    cc_header = msg.get("CC", "") or ""
    recipients = [r.strip() for r in (to_header + "," + cc_header).split(",") if r.strip()]
    
    reply_to = msg.get("Reply-To")
    date = msg.get("Date", "")
    
    # All received headers
    received_headers = msg.get_all("Received") or []
    sending_ips = _extract_ips_from_received(received_headers)
    
    # All headers as dict
    headers = {}
    for key in set(msg.keys()):
        vals = msg.get_all(key)
        headers[key] = vals[0] if len(vals) == 1 else vals

    # Body
    body_text = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = part.get_content_disposition() or ""
            if "attachment" in cd:
                attachments.append({
                    "filename": part.get_filename() or "unknown",
                    "content_type": ct,
                    "size": len(part.get_payload(decode=True) or b""),
                })
            elif ct == "text/plain" and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True)
                    body_text = payload.decode("utf-8", errors="replace") if payload else ""
            elif ct == "text/html" and not body_html:
                try:
                    body_html = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True)
                    body_html = payload.decode("utf-8", errors="replace") if payload else ""
    else:
        ct = msg.get_content_type()
        try:
            payload_text = msg.get_content()
        except Exception:
            raw = msg.get_payload(decode=True)
            payload_text = raw.decode("utf-8", errors="replace") if raw else ""
        if ct == "text/html":
            body_html = payload_text
        else:
            body_text = payload_text

    # URLs
    all_text = body_text + " " + body_html
    urls = _extract_urls(all_text)

    return {
        "message_id": message_id,
        "subject": subject,
        "sender": sender,
        "sender_domain": sender_domain,
        "recipients": recipients,
        "reply_to": reply_to,
        "date": date,
        "headers": headers,
        "body_text": body_text,
        "body_html": body_html,
        "attachments": attachments,
        "urls": urls,
        "sending_ips": sending_ips,
    }
