from hashlib import sha256
from random import randint

from charm.core.math.integer import random, isPrime
from charm.toolbox.conversion import Conversion


def randomQR(n):
    return random(n) ** 2


def encodeAttrs(attrs):
    """
    This function will encode all the attributes to 256 bit integers
    :param attrs: The attributes to pass in credentials
    :return:
    """
    return {key: Conversion.bytes2integer(sha256(str(value).encode()).digest())
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
