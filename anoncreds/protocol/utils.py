import logging
import string
import time
from collections import OrderedDict
from enum import Enum
from hashlib import sha256
from math import sqrt, floor
from random import randint, sample
from sys import byteorder
from typing import Dict, List, Set

import base58

from anoncreds.protocol.globals import KEYS, PK_R
from anoncreds.protocol.globals import LARGE_PRIME, LARGE_MASTER_SECRET, \
    LARGE_VPRIME, PAIRING_GROUP
from config.config import cmod
import sys


def encodeAttr(attrValue):
    return cmod.Conversion.bytes2integer(sha256(str(attrValue).encode()).digest())


def randomQR(n):
    return cmod.random(n) ** 2


def get_hash_as_int(*args, group: cmod.PairingGroup = None):
    """
    Enumerate over the input tuple and generate a hash using the tuple values

    :param args: sequence of either group or integer elements
    :param group: pairing group if an element is a group element
    :return:
    """

    group = group if group else cmod.PairingGroup(PAIRING_GROUP)
    h_challenge = sha256()

    serialedArgs = [group.serialize(arg) if isGroupElement(arg)
                    else cmod.Conversion.IP2OS(arg)
                    for arg in args]

    for arg in sorted(serialedArgs):
        h_challenge.update(arg)
    return bytes_to_int(h_challenge.digest())


CRYPTO_INT_PREFIX = 'CryptoInt_'
INT_PREFIX = 'Int_'
GROUP_PREFIX = 'Group_'
BYTES_PREFIX = 'Bytes_'


def serializeToStr(n):
    if isCryptoInteger(n):
        return CRYPTO_INT_PREFIX + cmod.serialize(n).decode()
    if isInteger(n):
        return INT_PREFIX + str(n)
    if isGroupElement(n):
        return GROUP_PREFIX + cmod.PairingGroup(PAIRING_GROUP).serialize(
            n).decode()
    return n


def deserializeFromStr(n: str):
    if isStr(n) and n.startswith(CRYPTO_INT_PREFIX):
        n = n[len(CRYPTO_INT_PREFIX):].encode()
        return cmod.deserialize(n)

    if isStr(n) and n.startswith(INT_PREFIX):
        n = n[len(INT_PREFIX):]
        return int(n)

    if isStr(n) and n.startswith(GROUP_PREFIX):
        n = n[len(GROUP_PREFIX):].encode()
        res = cmod.PairingGroup(PAIRING_GROUP).deserialize(n)
        # A fix for Identity element as serialized/deserialized not correctly
        if str(res) == '[0, 0]':
            return groupIdentityG1()
        return res

    return n


def isCryptoInteger(n):
    return isinstance(n, cmod.integer)


def isGroupElement(n):
    return isinstance(n, cmod.pc_element)


def isInteger(n):
    return isinstance(n, int)


def isStr(n):
    return isinstance(n, str)


def isNamedTuple(n):
    return isinstance(n, tuple)  # TODO: assume it's a named tuple


def toDictWithStrValues(d):
    if isNamedTuple(d):
        return toDictWithStrValues(d._asdict())
    if not isinstance(d, Dict):
        return serializeToStr(d)
    result = OrderedDict()
    for key, value in d.items():
        if isinstance(value, Dict):
            result[serializeToStr(key)] = toDictWithStrValues(value)
        elif isinstance(value, str):
            result[serializeToStr(key)] = serializeToStr(value)
        elif isNamedTuple(value):
            result[serializeToStr(key)] = toDictWithStrValues(value._asdict())
        elif isinstance(value, Set):
            result[serializeToStr(key)] = {toDictWithStrValues(v) for v in
                                           value}
        elif isinstance(value, List):
            result[serializeToStr(key)] = [toDictWithStrValues(v) for v in
                                           value]
        elif value:
            result[serializeToStr(key)] = serializeToStr(value)
    return result


def fromDictWithStrValues(d):
    if not isinstance(d, Dict) and not isinstance(d, tuple):
        return deserializeFromStr(d)
    result = OrderedDict()
    for key, value in d.items():
        if isinstance(value, Dict):
            result[deserializeFromStr(key)] = fromDictWithStrValues(value)
        elif isinstance(value, str):
            result[deserializeFromStr(key)] = deserializeFromStr(value)
        elif isinstance(value, Set):
            result[deserializeFromStr(key)] = {fromDictWithStrValues(v) for v in
                                               value}
        elif isinstance(value, List):
            result[deserializeFromStr(key)] = [fromDictWithStrValues(v) for v in
                                               value]
        elif value:
            result[deserializeFromStr(key)] = deserializeFromStr(value)
    return result


def bytes_to_int(bytesHash):
    return int.from_bytes(bytesHash, byteorder=byteorder)


def int_to_ZR(intHash, group):
    return group.init(cmod.ZR, intHash)


def groupIdentityG1():
    return cmod.PairingGroup(PAIRING_GROUP).init(cmod.G1, 0)

def groupIdentityG2():
    return cmod.PairingGroup(PAIRING_GROUP).init(cmod.G2, 0)

def get_values_of_dicts(*args):
    l = list()
    for d in args:
        l.extend(list(d.values()))
    return l


def get_prime_in_range(start, end):
    n = 0
    maxIter = 100000
    while n < maxIter:
        r = randint(start, end)
        if cmod.isPrime(r):
            logging.debug("Found prime in {} iterations".format(n))
            return r
        n += 1
    raise Exception("Cannot find prime in {} iterations".format(maxIter))


def splitRevealedAttrs(encodedAttrs, revealedAttrs):
    # Revealed attributes
    Ar = {}
    # Unrevealed attributes
    Aur = {}

    for k, value in encodedAttrs.items():
        if k in revealedAttrs:
            Ar[k] = value.encoded
        else:
            Aur[k] = value.encoded
    return Ar, Aur


def randomString(size: int = 20,
                 chars: str = string.ascii_letters + string.digits) -> str:
    """
    Generate a random string of the specified size.

    Ensure that the size is less than the length of chars as this function uses random.choice
    which uses random sampling without replacement.

    :param size: size of the random string to generate
    :param chars: the set of characters to use to generate the random string. Uses alphanumerics by default.
    :return: the random string generated
    """

    return ''.join(sample(chars, size))


def getUnrevealedAttrs(encodedAttrs, revealedAttrsList):
    revealedAttrs, unrevealedAttrs = splitRevealedAttrs(encodedAttrs,
                                                        revealedAttrsList)
    return unrevealedAttrs


def flattenDict(attrs):
    return {x: y for z in attrs.values()
            for x, y in z.items()}


def largestSquareLessThan(x: int):
    sqrtx = int(floor(sqrt(x)))
    return sqrtx


def fourSquares(delta: int):
    u1 = largestSquareLessThan(delta)
    u2 = largestSquareLessThan(delta - (u1 ** 2))
    u3 = largestSquareLessThan(delta - (u1 ** 2) - (u2 ** 2))
    u4 = largestSquareLessThan(delta - (u1 ** 2) - (u2 ** 2) - (u3 ** 2))
    if (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta:
        return {'0': u1, '1': u2, '2': u3, '3': u4}
    else:
        raise Exception(
            "Cannot get the four squares for delta {0}".format(delta))


def strToCryptoInteger(n):
    if "mod" in n:
        a, b = n.split("mod")
        return cmod.integer(int(a.strip())) % cmod.integer(int(b.strip()))
    else:
        return cmod.integer(int(n))


def to_crypto_int(a, b=None):
    return strToCryptoInteger(a + 'mod' + b) if b else strToCryptoInteger(a)


def crypto_int_to_str(n):
    return cmod.toInt(n)


def strToInt(s):
    return bytes_to_int(sha256(s.encode()).digest())


def genPrime():
    """
    Generate 2 large primes `p_prime` and `q_prime` and use them
    to generate another 2 primes `p` and `q` of 1024 bits
    """
    prime = cmod.randomPrime(LARGE_PRIME)
    i = 0
    while not cmod.isPrime(2 * prime + 1):
        prime = cmod.randomPrime(LARGE_PRIME)
        i += 1
    return prime


def base58encode(i):
    return base58.b58encode(str(i).encode())


def base58decode(i):
    return base58.b58decode(str(i)).decode()


def base58decodedInt(i):
    try:
        return int(base58.b58decode(str(i)).decode())
    except Exception as ex:
        raise AttributeError from ex


class SerFmt(Enum):
    default = 1
    py3Int = 2
    base58 = 3


SerFuncs = {
    SerFmt.py3Int: int,
    SerFmt.default: cmod.integer,
    SerFmt.base58: base58encode,
}


def serialize(data, serFmt):
    serfunc = SerFuncs[serFmt]
    if KEYS in data:
        for k, v in data[KEYS].items():
            if isinstance(v, cmod.integer):
                # int casting works with Python 3 only.
                # for Python 2, charm's serialization api must be used.
                data[KEYS][k] = serfunc(v)
            if k == PK_R:
                data[KEYS][k] = {key: serfunc(val) for key, val in v.items()}
    return data


def generateMasterSecret():
    # Generate the master secret
    return cmod.integer(
        cmod.randomBits(LARGE_MASTER_SECRET))


def generateVPrime():
    return cmod.randomBits(LARGE_VPRIME)


def shorten(s, size=None):
    size = size or 10
    if isinstance(s, str):
        if len(s) <= size:
            return s
        else:
            head = int((size - 2) * 5 / 8)
            tail = int(size) - 2 - head
            return s[:head] + '..' + s[-tail:]
    else:  # assume it's an iterable
        return [shorten(x, size) for x in iter(s)]


def shortenMod(s, size=None):
    return ' mod '.join(shorten(str(s).split(' mod '), size))


def shortenDictVals(d, size=None):
    r = {}
    for k, v in d.items():
        if isinstance(v, dict):
            r[k] = shortenDictVals(v, size)
        else:
            r[k] = shortenMod(v, size)
    return r


def currentTimestampMillisec():
    return int(time.time() * 1000)  # millisec


def intToArrayBytes(value):
    value = int(value)
    result = []
    for i in range(0, sys.getsizeof(value)):
        b = value >> (i * 8) & 0xff
        result.append(b)

    result.reverse()

    first_non_zero = next((i for i, x in enumerate(result) if x), None)
    result = result[first_non_zero::]

    return result


def bytesToInt(bytes):
    result = 0

    for b in bytes:
        result = result * 256 + int(b)

    return result
