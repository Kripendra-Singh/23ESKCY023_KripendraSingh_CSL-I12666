"""
protocol.py - message format and HMAC authentication for IoT messages.

Every message carries three freshness fields:
    seq   : per-device increasing sequence number
    ts    : sender timestamp (seconds since epoch)
    nonce : random 128-bit value used only once
and an HMAC-SHA256 tag computed over all other fields with the DH session key.
"""
import hashlib
import hmac
import json
import secrets

FIELDS = ("dev", "seq", "ts", "nonce", "payload")


def _canonical(msg: dict) -> bytes:
    return json.dumps({k: msg[k] for k in FIELDS}, sort_keys=True,
                      separators=(",", ":")).encode()


def compute_mac(key: bytes, msg: dict) -> str:
    return hmac.new(key, _canonical(msg), hashlib.sha256).hexdigest()


def verify_mac(key: bytes, msg: dict) -> bool:
    try:
        return hmac.compare_digest(compute_mac(key, msg), msg.get("mac", ""))
    except (KeyError, TypeError):
        return False


class IoTDevice:
    """Simulated IoT device (sensor / smart lock) that signs every message."""

    def __init__(self, dev_id: str, key: bytes, clock):
        self.dev_id, self.key, self.clock, self.seq = dev_id, key, clock, 0

    def send(self, payload: str, with_mac: bool = True) -> dict:
        self.seq += 1
        msg = {"dev": self.dev_id, "seq": self.seq, "ts": int(self.clock()),
               "nonce": secrets.token_hex(16), "payload": payload}
        if with_mac:
            msg["mac"] = compute_mac(self.key, msg)
        return msg
