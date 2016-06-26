import string
from hashlib import sha256
from random import randint, sample
from typing import Dict

from charm.core.math.integer import random, isPrime
from charm.toolbox.conversion import Conversion


def randomQR(n):
    return random(n) ** 2


# def encodeAttrs(attrs):
#     """
#     This function will encode all the attributes to 256 bit integers
#     :param attrs: The attributes to pass in credentials
#     :return:
#     """
#     encoded = {}
#     for attr_type, value in attrs.items():
#         if attr_type.encode:
#             encoded[attr_type.name] = Conversion.bytes2integer(sha256(str(value).encode()).digest())
#         else:
#             encoded[attr_type.name] = value
#     return encoded

def encodeAttrs(attrs):
    """
    This function will encode all the attributes to 256 bit integers
    :param attrs: The attributes to pass in credentials
    :return:
    """
    return {key: Conversion.bytes2integer(sha256(value.encode()).digest())
            for key, value in attrs.items()}


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
            print("Found prime in {} iteration between {} and {}".
                  format(n, start, end))
            return r
        n += 1
    raise Exception("Cannot find prime in {} iterations".format(maxIter))


def splitRevealedAttributes(attrs, revealedAttrs):
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


def getUnrevealedAttrs(attrs, revealedAttrsList):
    flatAttrs = {x: y for z in attrs.values() for x, y in z.items()}

    revealedAttrs, unrevealedAttrs = splitRevealedAttributes(flatAttrs, revealedAttrsList)

    return flatAttrs, unrevealedAttrs