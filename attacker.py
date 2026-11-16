"""
attacker.py - passive sniffer + active replay/tamper attacker (Eve).
Used ONLY inside the simulated lab on the author's own machine.
"""
import copy


class Eve:
    def __init__(self):
        self.captured = []

    def sniff(self, msg):                 # passive: copy every packet seen
        self.captured.append(copy.deepcopy(msg))

    def replay(self, index=-1):           # active: resend a captured packet unchanged
        return copy.deepcopy(self.captured[index])

    def tamper(self, index=-1, **changes):  # active: modify fields, keep old MAC
        m = copy.deepcopy(self.captured[index])
        m.update(changes)
        return m
