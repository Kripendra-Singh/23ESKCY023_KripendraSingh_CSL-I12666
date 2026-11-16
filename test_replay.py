"""Automated test cases (unittest).  Run:  python3 test_replay.py -v"""
import unittest
from dh import DHParty, TOY_P, TOY_G, establish_session_key, mod_pow
from protocol import IoTDevice, compute_mac, verify_mac
from gateway import Gateway
from attacker import Eve
from demo import Clock


def setup(**gwargs):
    _, _, key, _ = establish_session_key()
    clk = Clock()
    return IoTDevice("d1", key, clk), Gateway(key, clk, **gwargs), Eve(), clk


class TestDH(unittest.TestCase):
    def test_toy_example(self):
        a, b = DHParty("A", TOY_P, TOY_G, 6), DHParty("B", TOY_P, TOY_G, 15)
        self.assertEqual((a.public, b.public), (8, 19))
        self.assertEqual(a.shared_secret(b.public), 2)
        self.assertEqual(b.shared_secret(a.public), 2)

    def test_mod_pow_matches_builtin(self):
        self.assertEqual(mod_pow(7, 560, 561), pow(7, 560, 561))

    def test_keys_match(self):
        _, _, k1, k2 = establish_session_key()
        self.assertEqual(k1, k2); self.assertEqual(len(k1), 32)

    def test_keys_differ_between_sessions(self):
        self.assertNotEqual(establish_session_key()[2], establish_session_key()[2])


class TestMAC(unittest.TestCase):
    def test_valid_mac(self):
        d, g, e, c = setup(); self.assertTrue(g.receive(d.send("x"))[0])

    def test_modified_payload_rejected(self):
        d, g, e, c = setup(); m = d.send("x"); e.sniff(m)
        self.assertFalse(g.receive(e.tamper(payload="y"))[0])

    def test_wrong_key_rejected(self):
        d, g, e, c = setup(); d.key = b"\x00" * 32
        self.assertFalse(g.receive(d.send("x"))[0])


class TestReplay(unittest.TestCase):
    def test_mac_only_is_vulnerable(self):
        d, g, e, c = setup(); m = d.send("UNLOCK"); e.sniff(m)
        self.assertTrue(g.receive(m)[0]); self.assertTrue(g.receive(e.replay())[0])

    def test_nonce_blocks_replay(self):
        d, g, e, c = setup(use_nonce=True); m = d.send("U"); e.sniff(m); g.receive(m)
        self.assertEqual(g.receive(e.replay()), (False, "duplicate nonce"))

    def test_timestamp_blocks_delayed_replay(self):
        d, g, e, c = setup(use_timestamp=True); m = d.send("U"); e.sniff(m); g.receive(m)
        c.advance(31); self.assertFalse(g.receive(e.replay())[0])

    def test_timestamp_allows_replay_inside_window(self):
        d, g, e, c = setup(use_timestamp=True); m = d.send("U"); e.sniff(m); g.receive(m)
        c.advance(5); self.assertTrue(g.receive(e.replay())[0])   # known limitation

    def test_sequence_blocks_replay(self):
        d, g, e, c = setup(use_sequence=True); m = d.send("U"); e.sniff(m); g.receive(m)
        self.assertEqual(g.receive(e.replay()), (False, "old sequence number"))

    def test_sequence_tolerates_gaps(self):
        d, g, e, c = setup(use_sequence=True); ms = [d.send("t") for _ in range(4)]
        self.assertTrue(g.receive(ms[0])[0]); self.assertTrue(g.receive(ms[3])[0])

    def test_edited_freshness_fields_fail_mac(self):
        d, g, e, c = setup(use_nonce=True, use_timestamp=True, use_sequence=True)
        m = d.send("U"); e.sniff(m); g.receive(m); c.advance(100)
        self.assertEqual(g.receive(e.tamper(seq=50, ts=c(), nonce="a" * 32))[1],
                         "bad MAC (forged / modified)")

    def test_full_protection_blocks_all(self):
        d, g, e, c = setup(use_nonce=True, use_timestamp=True, use_sequence=True)
        m = d.send("U"); e.sniff(m); g.receive(m)
        for delay in (0, 10, 40, 500):
            c.advance(delay); self.assertFalse(g.receive(e.replay())[0])
        self.assertTrue(g.receive(d.send("fresh"))[0])

    def test_bounded_nonce_cache_weakness(self):
        d, g, e, c = setup(use_nonce=True, nonce_cache_limit=2)
        m = d.send("U"); e.sniff(m); g.receive(m)
        for _ in range(3): g.receive(d.send("t"))
        self.assertTrue(g.receive(e.replay())[0])   # evicted -> accepted

    def test_no_mac_gateway_accepts_forgery(self):
        d, g, e, c = setup(use_mac=False); m = d.send("U", with_mac=False)
        self.assertTrue(g.receive(dict(m, payload="EVIL"))[0])


if __name__ == "__main__":
    unittest.main()
