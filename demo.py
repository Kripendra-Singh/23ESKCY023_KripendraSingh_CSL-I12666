"""
demo.py - Replay Attack Detection for IoT Messages
Runs every scenario of the project and prints the results.
Usage:  python3 demo.py
"""
from dh import establish_session_key, DHParty, TOY_P, TOY_G, mod_pow
from protocol import IoTDevice
from gateway import Gateway
from attacker import Eve


class Clock:
    """Simulated clock so that delays can be tested instantly."""
    def __init__(self, t=1_800_000_000): self.t = t
    def __call__(self): return self.t
    def advance(self, s): self.t += s


def line(c="-"): print(c * 70)


def show(tag, ok, reason):
    print("  %-34s -> %-6s (%s)" % (tag, "ACCEPT" if ok else "REJECT", reason))


def stage_dh():
    line("="); print("STAGE 1: Diffie-Hellman key exchange (Experiment 2)"); line("=")
    a = DHParty("Alice", TOY_P, TOY_G, private=6)
    b = DHParty("Bob", TOY_P, TOY_G, private=15)
    print("Toy example  P=%d G=%d  a=6 b=15" % (TOY_P, TOY_G))
    print("  Alice public = %d, Bob public = %d" % (a.public, b.public))
    print("  Alice secret = %d, Bob secret = %d" % (a.shared_secret(b.public), b.shared_secret(a.public)))
    dev, gw, kd, kg = establish_session_key()
    print("Real run with 2048-bit RFC 3526 group")
    print("  Device public (first 32 hex) :", hex(dev.public)[2:34], "...")
    print("  Gateway public (first 32 hex):", hex(gw.public)[2:34], "...")
    print("  Session key (device)  :", kd.hex())
    print("  Session key (gateway) :", kg.hex())
    print("  Keys equal?           :", kd == kg)
    return kd


def scenario(title, build_gateway, key, delay=0, steps=None):
    line(); print(title); line()
    clk = Clock()
    dev = IoTDevice("lock-01", key, clk)
    gw = build_gateway(key, clk)
    eve = Eve()
    # legitimate traffic
    m1 = dev.send("TEMP=27.4C"); eve.sniff(m1); show("Device msg #1 (TEMP=27.4C)", *gw.receive(m1))
    clk.advance(2)
    m2 = dev.send("UNLOCK_DOOR"); eve.sniff(m2); show("Device msg #2 (UNLOCK_DOOR)", *gw.receive(m2))
    # attack 1: immediate replay of the unlock command
    clk.advance(5)
    show("Eve replays msg #2 (after 5 s)", *gw.receive(eve.replay(1)))
    # attack 2: delayed replay
    clk.advance(delay)
    show("Eve replays msg #2 (after %d s)" % (delay + 5), *gw.receive(eve.replay(1)))
    # attack 3: replay with tampered freshness fields
    t = eve.tamper(1, seq=99, ts=clk(), nonce="f" * 32)
    show("Eve replays with edited seq/ts/nonce", *gw.receive(t))
    # a fresh genuine message must still work
    m3 = dev.send("TEMP=27.6C"); show("Device msg #3 (genuine, fresh)", *gw.receive(m3))
    return gw


def main():
    key = stage_dh()
    print()
    line("="); print("STAGE 2: Replay attack and countermeasures"); line("=")

    # S1: no MAC at all (plain messages)
    clk = Clock(); dev = IoTDevice("lock-01", key, clk); gw = Gateway(key, clk, use_mac=False)
    line(); print("Scenario 1: NO protection (plain messages, no MAC)"); line()
    m = dev.send("UNLOCK_DOOR", with_mac=False); show("Device UNLOCK_DOOR", *gw.receive(m))
    show("Eve replays captured packet", *gw.receive(dict(m)))
    forged = dict(m, payload="DISABLE_ALARM"); show("Eve forges new command", *gw.receive(forged))

    scenario("Scenario 2: HMAC only (authentic but NOT fresh)",
             lambda k, c: Gateway(k, c, use_mac=True), key, delay=120)
    scenario("Scenario 3: HMAC + Nonce (unbounded cache)",
             lambda k, c: Gateway(k, c, use_mac=True, use_nonce=True), key, delay=120)
    scenario("Scenario 4: HMAC + Timestamp (window = 30 s)",
             lambda k, c: Gateway(k, c, use_mac=True, use_timestamp=True, window=30), key, delay=120)
    scenario("Scenario 5: HMAC + Sequence number",
             lambda k, c: Gateway(k, c, use_mac=True, use_sequence=True), key, delay=120)
    scenario("Scenario 6: HMAC + Nonce + Timestamp + Sequence (full protection)",
             lambda k, c: Gateway(k, c, use_mac=True, use_nonce=True, use_timestamp=True,
                                  use_sequence=True, window=30), key, delay=120)

    # S7: bounded nonce cache weakness
    line(); print("Scenario 7: Nonce-only gateway with small cache (limit = 3)"); line()
    clk = Clock(); dev = IoTDevice("lock-01", key, clk)
    gw = Gateway(key, clk, use_mac=True, use_nonce=True, nonce_cache_limit=3); eve = Eve()
    first = dev.send("UNLOCK_DOOR"); eve.sniff(first); show("Device UNLOCK_DOOR", *gw.receive(first))
    for i in range(4):
        clk.advance(1); show("Device filler msg %d" % (i + 1), *gw.receive(dev.send("TEMP=2%d" % i)))
    show("Eve replays old UNLOCK (evicted nonce)", *gw.receive(eve.replay(0)))
    print("  -> a bounded nonce cache alone is NOT enough; combine with timestamp.")
    gw2 = Gateway(key, clk, use_mac=True, use_nonce=True, use_timestamp=True, window=30,
                  nonce_cache_limit=3)
    first = dev.send("UNLOCK_DOOR"); gw2.receive(first)
    for i in range(4):
        clk.advance(1); gw2.receive(dev.send("TEMP=2%d" % i))
    clk.advance(60)
    show("Same attack vs nonce+timestamp", *gw2.receive(dict(first)))

    # S8: sequence number tolerance for packet loss
    line(); print("Scenario 8: Sequence numbers with packet loss (messages 2,3 lost)"); line()
    clk = Clock(); dev = IoTDevice("sensor-07", key, clk)
    gw = Gateway(key, clk, use_mac=True, use_sequence=True)
    msgs = [dev.send("TEMP=2%d" % i) for i in range(5)]
    for i in (0, 3, 4): show("Delivered msg seq=%d" % msgs[i]["seq"], *gw.receive(msgs[i]))
    show("Late out-of-order seq=2", *gw.receive(msgs[1]))
    print("  -> gaps are tolerated, but late/old packets are rejected.")
    line("=")
    print("Demo complete. Run  python3 test_replay.py  for the automated test-suite.")


if __name__ == "__main__":
    main()
