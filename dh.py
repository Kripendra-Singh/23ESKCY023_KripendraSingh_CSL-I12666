"""
dh.py - Diffie-Hellman key exchange (Experiment 2) used to create the
per-device session key for the IoT replay-protection project.

Alice (device)  : computes A = g^a mod p
Bob   (gateway) : computes B = g^b mod p
Both            : K = (peer public)^(own private) mod p
The session key is derived as SHA-256(K) so it has a fixed 256-bit size.
"""
import hashlib
import secrets

# Small textbook parameters taken from the class theory (P = 23, G = 5)
TOY_P, TOY_G = 23, 5

# RFC 3526, 2048-bit MODP Group 14 (used for the real, secure run)
RFC3526_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
RFC3526_G = 2


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply modular exponentiation (base^exp mod mod).

    Faster than the simple loop used in the class JavaScript demo:
    O(log exp) multiplications instead of O(exp).
    """
    result, base = 1, base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


class DHParty:
    def __init__(self, name, p, g, private=None):
        self.name, self.p, self.g = name, p, g
        # private key: random number in [2, p-2]
        self.private = private if private is not None else secrets.randbelow(p - 3) + 2
        self.public = mod_pow(g, self.private, p)

    def shared_secret(self, peer_public: int) -> int:
        return mod_pow(peer_public, self.private, self.p)

    def session_key(self, peer_public: int) -> bytes:
        k = self.shared_secret(peer_public)
        return hashlib.sha256(k.to_bytes((k.bit_length() + 7) // 8 or 1, "big")).digest()


def establish_session_key(p=RFC3526_P, g=RFC3526_G):
    """Run a complete exchange; returns (device, gateway, device_key, gateway_key)."""
    device = DHParty("Device (Alice)", p, g)
    gateway = DHParty("Gateway (Bob)", p, g)
    return device, gateway, device.session_key(gateway.public), gateway.session_key(device.public)


if __name__ == "__main__":
    # Reproduces the worked example from the theory notes (P=23, G=5, a=6, b=15)
    a = DHParty("Alice", TOY_P, TOY_G, private=6)
    b = DHParty("Bob", TOY_P, TOY_G, private=15)
    print("Alice public =", a.public, "| Bob public =", b.public)
    print("Alice secret =", a.shared_secret(b.public), "| Bob secret =", b.shared_secret(a.public))
