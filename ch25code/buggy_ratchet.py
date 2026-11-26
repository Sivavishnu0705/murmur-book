# buggy_ratchet.py
"""The lab's planted flaw. A 'performance optimization' removed the copy in decrypt():
state is mutated in place, so a message whose HEADER carries a new ratchet key triggers a DH
ratchet step BEFORE the AEAD check — and a forged header corrupts the session even though the
forgery itself is rejected."""
from ratchet import Ratchet, Header

class BuggyRatchet(Ratchet):
    def decrypt(self, header_bytes, ct, ad):
        return self._decrypt(Header.decode(header_bytes), header_bytes, ct, ad)   # ⚠️ no copy/commit
