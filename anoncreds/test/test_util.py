from anoncreds.protocol.globals import PAIRING_GROUP
from anoncreds.protocol.utils import get_hash
from anoncreds.test.conftest import primes
from config.config import cmod


def testGetHashInt():
    input = [0xb1134a647eb818069c089e7694f63e6d,
             0x57fbf9dc8c8e6acde33de98c6d747b28c,
             0x77fbf9dc8c8e6acde33de98c6d747b28c]

    _checkHashEqual(input)


def testGetHashInteger():
    P_PRIME1, Q_PRIME1 = primes.get("prime1")
    P_PRIME2, Q_PRIME2 = primes.get("prime2")
    input = [P_PRIME1, Q_PRIME1, P_PRIME2, Q_PRIME2]

    _checkHashEqual(input)


def testGetHashGroup():
    group = cmod.PairingGroup(PAIRING_GROUP)
    input = [group.random(cmod.G1),
             group.random(cmod.G1),
             group.random(cmod.G1)]

    _checkHashEqual(input)


def testGetHashMixed():
    group = cmod.PairingGroup(PAIRING_GROUP)
    P_PRIME1, Q_PRIME1 = primes.get("prime1")
    input = [P_PRIME1, Q_PRIME1,
             group.random(cmod.G1), group.random(cmod.G1),
             0xb1134a647eb818069c089e7694f63e6d,
             0x57fbf9dc8c8e6acde33de98c6d747b28c]

    _checkHashEqual(input)


def _checkHashEqual(input):
    h1 = get_hash(*input)
    h2 = get_hash(*reversed(input))
    assert h1 == h2
