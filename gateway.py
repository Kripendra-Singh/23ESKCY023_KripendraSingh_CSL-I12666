"""
gateway.py - IoT gateway that accepts or rejects messages.

Protection switches (each can be enabled independently):
    use_mac       - verify HMAC-SHA256 tag (integrity + authenticity)
    use_nonce     - reject a nonce that was already seen
    use_timestamp - reject messages older/newer than +/- window seconds
    use_sequence  - reject seq <= last accepted seq of that device
"""
from protocol import verify_mac


class Gateway:
    def __init__(self, key: bytes, clock, window: int = 30,
                 use_mac=True, use_nonce=False, use_timestamp=False,
                 use_sequence=False, nonce_cache_limit=None):
        self.key, self.clock, self.window = key, clock, window
        self.use_mac, self.use_nonce = use_mac, use_nonce
        self.use_timestamp, self.use_sequence = use_timestamp, use_sequence
        self.nonce_cache_limit = nonce_cache_limit      # None = unlimited
        self.seen_nonces = {}                           # nonce -> ts
        self.last_seq = {}                              # device -> last seq
        self.log = []                                   # (seq, verdict, reason)

    # ---------------------------------------------------------------
    def receive(self, msg: dict):
        """Returns (accepted: bool, reason: str)."""
        ok, reason = self._check(msg)
        self.log.append((msg.get("seq"), "ACCEPT" if ok else "REJECT", reason))
        return ok, reason

    def _check(self, msg):
        if self.use_mac and not verify_mac(self.key, msg):
            return False, "bad MAC (forged / modified)"
        if self.use_timestamp:
            if abs(self.clock() - msg["ts"]) > self.window:
                return False, "stale timestamp (outside %ds window)" % self.window
        if self.use_nonce:
            if msg["nonce"] in self.seen_nonces:
                return False, "duplicate nonce"
        if self.use_sequence:
            if msg["seq"] <= self.last_seq.get(msg["dev"], 0):
                return False, "old sequence number"
        if not (self.use_mac or self.use_nonce or self.use_timestamp or self.use_sequence):
            return True, "no verification performed"
        # message is fresh -> update state
        if self.use_nonce:
            self.seen_nonces[msg["nonce"]] = msg["ts"]
            self._trim_nonce_cache()
        if self.use_sequence:
            self.last_seq[msg["dev"]] = msg["seq"]
        return True, "fresh and authentic"

    def _trim_nonce_cache(self):
        if self.nonce_cache_limit and len(self.seen_nonces) > self.nonce_cache_limit:
            oldest = sorted(self.seen_nonces, key=self.seen_nonces.get)
            for n in oldest[: len(self.seen_nonces) - self.nonce_cache_limit]:
                del self.seen_nonces[n]
