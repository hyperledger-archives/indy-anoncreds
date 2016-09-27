import logging
import string
from hashlib import sha256
from random import randint, sample

import base58
from charm.core.math.integer import random, isPrime, integer, randomPrime
from charm.toolbox.conversion import Conversion

from anoncreds.protocol.globals import LARGE_PRIME, KEYS, PK_R
from anoncreds.protocol.types import SerFmt


def randomQR(n):
    return random(n) ** 2


# def encodeAttrs(attrs):
#     """
#     This function will encode all the attributes to 256 bit integers
#
#     :param attrs: The attributes to pass in credentials
#     :return:
#     """
#
#     return {key: Conversion.bytes2integer(sha256(value.encode()).digest())
#             for key, value in attrs.items()}


def get_hash(*args):
    """
    Enumerate over the input tuple and generate a hash using the tuple values

    :param args:
    :return:
    """

    h_challenge = sha256()
    for arg in args:
        h_challenge.update(Conversion.IP2OS(arg))
    return h_challenge.digest()


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
        if isPrime(r):
            logging.debug("Found prime in {} iteration between {} and {}".
                  format(n, start, end))
            return r
        n += 1
    raise Exception("Cannot find prime in {} iterations".format(maxIter))


def splitRevealedAttrs(attrs, revealedAttrs):
    # Revealed attributes
    Ar = {}
    # Unrevealed attributes
    Aur = {}

    for k, value in attrs.items():
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
    flatAttrs = flattenDict(encodedAttrs)
    revealedAttrs, unrevealedAttrs = splitRevealedAttrs(flatAttrs, revealedAttrsList)
    return flatAttrs, unrevealedAttrs


def flattenDict(attrs):
    return {x: y for z in attrs.values()
            for x, y in z.items()}


def strToCharmInteger(n):
    if "mod" in n:
        a, b = n.split("mod")
        return integer(int(a.strip())) % integer(int(b.strip()))
    else:
        return integer(int(n))


def genPrime():
    """
    Generate 2 large primes `p_prime` and `q_prime` and use them
    to generate another 2 primes `p` and `q` of 1024 bits
    """
    prime = randomPrime(LARGE_PRIME)
    i = 0
    while not isPrime(2 * prime + 1):
        prime = randomPrime(LARGE_PRIME)
        i += 1
    print("In {} iterations, found prime {}".format(i, prime))
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


SerFuncs = {
    SerFmt.py3Int: int,
    SerFmt.default: integer,
    SerFmt.base58: base58encode,
}


def serialize(data, serFmt):
    serfunc = SerFuncs[serFmt]
    if KEYS in data:
        for k, v in data[KEYS].items():
            if isinstance(v, integer):
                # int casting works with Python 3 only.
                # for Python 2, charm's serialization api must be used.
                data[KEYS][k] = serfunc(v)
            if k == PK_R :
                data[KEYS][k] = {key: serfunc(val) for key, val in v.items()}
    return data
