from collections import OrderedDict

import pytest

from anoncreds.protocol.globals import PAIRING_GROUP
from anoncreds.protocol.utils import toDictWithStrValues, \
    deserializeFromStr, serializeToStr, fromDictWithStrValues, get_hash_as_int, intToArrayBytes, bytesToInt
from anoncreds.test.conftest import primes
from config.config import cmod


def testStrSerializeToFromStr():
    value = 'aaa'
    assert value == deserializeFromStr(serializeToStr(value))


def testIntSerializeToFromStr():
    value = 111
    assert value == deserializeFromStr(serializeToStr(value))


def testCryptoIntSerializeToFromStr():
    value = cmod.integer(44444444444444444)
    assert value == deserializeFromStr(serializeToStr(value))


def testCryptoIntModSerializeToFromStr():
    value = cmod.integer(44444444444444444) % 33
    assert value == deserializeFromStr(serializeToStr(value))


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testGroupElementSerializeToFromStr():
    value = cmod.PairingGroup(PAIRING_GROUP).random(cmod.G1)
    assert value == deserializeFromStr(serializeToStr(value))


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testGroupElementZRIdentitySerializeToFromStr():
    elem = cmod.PairingGroup(PAIRING_GROUP).init(cmod.ZR, 555)
    identity = elem / elem
    assert identity == deserializeFromStr(serializeToStr(identity))


def testGroupElementG1IdentitySerializeToFromStr():
    elem = cmod.PairingGroup(PAIRING_GROUP).random(cmod.G1)
    identity = cmod.PairingGroup(PAIRING_GROUP).init(cmod.G1, elem / elem)
    assert identity == deserializeFromStr(serializeToStr(identity))


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testToFromDictWithStrValues():
    group = cmod.PairingGroup(PAIRING_GROUP)
    dictionary = OrderedDict((
        ('43', '43'),
        ('3', 3),
        ('5', cmod.integer(111) % 11),
        ('10', group.random(cmod.G1))
    ))
    assert dictionary == fromDictWithStrValues(toDictWithStrValues(dictionary))


def testToFromDictWithStrValuesInteKeys():
    dictionary = OrderedDict((
        (11, '43'),
        (12, 3)
    ))
    assert dictionary == fromDictWithStrValues(toDictWithStrValues(dictionary))


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testToFromDictWithStrValuesLists():
    group = cmod.PairingGroup(PAIRING_GROUP)
    dictionary = OrderedDict((
        ('47', []),
        ('7',
         [cmod.integer(111) % 11, cmod.integer(222), cmod.integer(333) % 45]),
        ('6', [group.init(cmod.ZR, 555), group.random(cmod.G1),
               group.random(cmod.G1)])
    ))
    assert dictionary == fromDictWithStrValues(toDictWithStrValues(dictionary))


def testToFromDictWithStrValuesSets():
    dictionary = OrderedDict((
        ('44', {'aaa', 'bbb'}),
        ('4', {111, 2222}),
        ('1', {}),
        ('3', 3),
    ))
    assert dictionary == fromDictWithStrValues(toDictWithStrValues(dictionary))


def testToFromDictWithStrValuesSubDicts():
    group = cmod.PairingGroup(PAIRING_GROUP)
    dictionary = OrderedDict((
        ('4', {'aaa', 'bbb'}),
        ('2', OrderedDict((
            ('33',
             OrderedDict((('45', 45), ('11', 11)))
             ),
            ('23',
             OrderedDict((('47', 47), ('34', 34)))
             )
        ))),
        ('3', 3)
    ))
    assert dictionary == fromDictWithStrValues(toDictWithStrValues(dictionary))


@pytest.mark.skipif('sys.platform == "win32"', reason='SOV-86')
def testToFromDictWithStrValuesMixed():
    group = cmod.PairingGroup(PAIRING_GROUP)
    dictionary = OrderedDict((
        ('4', {'aaa', 'bbb'}),
        ('2', OrderedDict((
            ('33',
             OrderedDict((('45', 45), ('11', 11)))
             ),
            ('23',
             OrderedDict((('47', 47), ('34', 34)))
             )
        ))),
        ('1', {}),
        ('3', 3),
        ('5', cmod.integer(111) % 11),
        ('7',
         [cmod.integer(111) % 11, cmod.integer(222), cmod.integer(333) % 45]),
        ('6', [group.init(cmod.ZR, 555), group.random(cmod.G1),
               group.random(cmod.G1)]),
        ('10', group.random(cmod.G1))
    ))
    assert dictionary == fromDictWithStrValues(toDictWithStrValues(dictionary))


def testToFromDictWithStrValuesDictInList():
    dictionary = OrderedDict((
        ('2', [
            OrderedDict((
                ('33',
                 OrderedDict((('45', 45), ('11', 11)))
                 ),
                ('23',
                 OrderedDict((('47', 47), ('34', 34)))
                 )
            )),
            OrderedDict((
                ('63',
                 OrderedDict((('65', 45), ('61', 11)))
                 ),
                ('63',
                 OrderedDict((('67', 47), ('64', 34)))
                 )
            ))
        ]
         ),
        ('3', 3)
    ))
    assert dictionary == fromDictWithStrValues(toDictWithStrValues(dictionary))


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
    h1 = get_hash_as_int(*input)
    h2 = get_hash_as_int(*reversed(input))
    assert h1 == h2


def testIntToArrayBytes():
    val = cmod.integer(1606507817390189252221968804450207070282033)
    res = [18, 113, 26, 39, 35, 240, 231, 239, 92, 226, 84, 46, 230, 174, 230, 41, 225, 49]
    assert res == intToArrayBytes(val)

def testBytesToInt():
    val = [18, 113, 26, 39, 35, 240, 231, 239, 92, 226, 84, 46, 230, 174, 230, 41, 225, 49]
    res = 1606507817390189252221968804450207070282033
    assert res == bytesToInt(val)

def testIntToArrayBytesAndBack():
    val = cmod.integer(1606507817390189252221968804450207070282033)
    assert val == bytesToInt(intToArrayBytes(val))