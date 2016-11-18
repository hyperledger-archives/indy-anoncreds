from anoncreds.protocol.utils import get_hash


def testGetHash():
    input = ['b1134a647eb818069c089e7694f63e6d',
             '57fbf9dc8c8e6acde33de98c6d747b28c',
             '77fbf9dc8c8e6acde33de98c6d747b28c']
    mathInput = [int(i, 16) for i in input]
    h1 = get_hash(*mathInput)
    h2 = get_hash(*reversed(sorted(mathInput)))

    assert h1 == h2
