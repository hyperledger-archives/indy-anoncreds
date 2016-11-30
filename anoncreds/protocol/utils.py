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
from anoncreds.protocol.globals import LARGE_PRIME, LARGE_MASTER_SECRET, LARGE_VPRIME, PAIRING_GROUP
from config.config import cmod


def randomQR(n):
    return cmod.random(n) ** 2


def get_hash(*args, group: cmod.PairingGroup = None):
    """
    Enumerate over the input tuple and generate a hash using the tuple values

    :param args:
    :return:
    """

    group = group if group else cmod.PairingGroup(PAIRING_GROUP)
    h_challenge = sha256()

    serialedArgs = [group.serialize(arg) if isGroupElement(arg)
                    else cmod.Conversion.IP2OS(arg)
                    for arg in args]

    for arg in sorted(serialedArgs):
        h_challenge.update(arg)
    return h_challenge.digest()


CRYPTO_INT_PREFIX = 'CryptoInt_'
INT_PREFIX = 'Int_'
GROUP_PREFIX = 'Group_'
LIST_PREFIX = '['
LIST_SUFFIX = ']'
SET_PREFIX = '{'
SET_SUFFIX = '}'
STR_DICT_LIST_SEPARATOR = ","


def serializeToStr(n):
    if isCryptoInteger(n):
        return CRYPTO_INT_PREFIX + cmod.serialize(n).decode()
    if isInteger(n):
        return INT_PREFIX + str(n)
    if isGroupElement(n):
        return GROUP_PREFIX + cmod.PairingGroup(PAIRING_GROUP).serialize(n).decode()
    if isStr(n):
        return n
    if isinstance(n, Set):
        return SET_PREFIX + STR_DICT_LIST_SEPARATOR.join([serializeToStr(v) for v in n]) + SET_SUFFIX
    if isinstance(n, List):
        return LIST_PREFIX + STR_DICT_LIST_SEPARATOR.join([serializeToStr(v) for v in n]) + LIST_SUFFIX

    raise NotImplementedError('Unsupported type for serialization: {}'.format(n))


def deserializeFromStr(n: str):
    if n.startswith(CRYPTO_INT_PREFIX):
        n = n[len(CRYPTO_INT_PREFIX):].encode()
        return cmod.deserialize(n)

    if n.startswith(INT_PREFIX):
        n = n[len(INT_PREFIX):]
        return int(n)

    if n.startswith(GROUP_PREFIX):
        n = n[len(GROUP_PREFIX):].encode()
        res = cmod.PairingGroup(PAIRING_GROUP).deserialize(n)
        # A fix for Identity element as serialized/deserialized not correctly
        if str(res) == '[0, 0]':
            return groupIdentityG1()
        return res

    if n.startswith(LIST_PREFIX) and n.endswith(LIST_SUFFIX):
        n = n[len(LIST_PREFIX):-len(LIST_SUFFIX)]
        return [deserializeFromStr(v) for v in n.split(STR_DICT_LIST_SEPARATOR)]

    if n.startswith(SET_PREFIX) and n.endswith(SET_SUFFIX):
        n = n[len(SET_PREFIX):-len(SET_SUFFIX)]
        return {deserializeFromStr(v) for v in n.split(STR_DICT_LIST_SEPARATOR)}

    return n


def isCryptoInteger(n):
    return isinstance(n, cmod.integer)


def isGroupElement(n):
    return isinstance(n, cmod.pc_element)


def isInteger(n):
    return isinstance(n, int)


def isStr(n):
    return isinstance(n, str)


def toDictWithStrValues(d):
    result = OrderedDict()
    for key, value in d.items():
        if isinstance(value, Dict):
            result[str(key)] = toDictWithStrValues(value)
        elif isinstance(value, tuple):  # assume it's a named tuple
            result[str(key)] = toDictWithStrValues(value._asdict())
        elif value:
            result[str(key)] = serializeToStr(value)
    return result


def fromDictWithStrValues(d):
    result = OrderedDict()
    for key, value in d.items():
        if isinstance(value, Dict):
            result[str(key)] = fromDictWithStrValues(value)
        elif value:
            result[str(key)] = deserializeFromStr(value)
    return result


def bytes_to_int(bytesHash):
    return int.from_bytes(bytesHash, byteorder=byteorder)


def bytes_to_ZR(bytesHash, group):
    cHNum = bytes_to_int(bytesHash)
    return group.init(cmod.ZR, cHNum)


def groupIdentityG1():
    #elem = cmod.PairingGroup(PAIRING_GROUP).random(cmod.G1)
    #return elem / elem
    return cmod.PairingGroup(PAIRING_GROUP).init(cmod.G1, 0)


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
            Ar[k] = value
        else:
            Aur[k] = value
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
    revealedAttrs, unrevealedAttrs = splitRevealedAttrs(encodedAttrs, revealedAttrsList)
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
        raise Exception("Cannot get the four squares for delta {0}".format(delta))


def strToCryptoInteger(n):
    if "mod" in n:
        a, b = n.split("mod")
        return cmod.integer(int(a.strip())) % cmod.integer(int(b.strip()))
    else:
        return cmod.integer(int(n))


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
