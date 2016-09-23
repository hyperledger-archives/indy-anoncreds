import logging
import string
from hashlib import sha256
from math import sqrt, floor
from random import randint, sample
from typing import Dict
from sys import byteorder

from charm.core.math.integer import random, isPrime, integer
from charm.toolbox.conversion import Conversion
from charm.toolbox.pairinggroup import PairingGroup, pc_element, ZR

from anoncreds.protocol.types import T


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


def get_hash(*args, group: PairingGroup = None):
    """
    Enumerate over the input tuple and generate a hash using the tuple values

    :param args:
    :return:
    """

    h_challenge = sha256()
    for arg in args:
        if (type(arg) == pc_element):
            byteArg = group.serialize(arg)
            h_challenge.update(byteArg)
        else:
            h_challenge.update(Conversion.IP2OS(arg))
    return h_challenge.digest()


def bytes_to_ZR(bytesHash, group):
    cHNum = int.from_bytes(bytesHash, byteorder=byteorder)
    return group.init(ZR, cHNum)


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


def largestSquareLessThan(x: int):
    sqrtx = int(floor(sqrt(x)))
    return sqrtx


def fourSquares(delta: int):
    u1 = largestSquareLessThan(delta)
    u2 = largestSquareLessThan(delta - (u1 ** 2))
    u3 = largestSquareLessThan(delta - (u1 ** 2) - (u2 ** 2))
    u4 = largestSquareLessThan(delta - (u1 ** 2) - (u2 ** 2) - (u3 ** 2))
    if (u1 ** 2) + (u2 ** 2) + (u3 ** 2) + (u4 ** 2) == delta:
        return list((u1, u2, u3, u4))
    else:
        raise Exception("Cannot get the four squares for delta {0}".format(delta))


def updateDict(obj: Dict[str, Dict[str, T]], parentKey: str,
               key: str, val: any):
    parentVal = obj.get(parentKey, {})
    parentVal[key] = val
    obj[parentKey] = parentVal
