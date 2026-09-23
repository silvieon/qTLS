
from qtls.crypto import TLS13KeySchedule

def test_finished_is_deterministic():
    ks=TLS13KeySchedule()
    c,s=ks.handshake(b"x"*32,b"h"*32)
    assert c != s
    assert ks.finished(c,b"t"*32)==ks.finished(c,b"t"*32)
