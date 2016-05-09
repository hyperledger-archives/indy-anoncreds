import hashlib
from charm.core.math.integer import random
from charm.toolbox.conversion import Conversion


def randomQR(n):
    return random(n) ** 2


def encodeAttrs(attrs):
    """
    This function will encode all the attributes to 256 bit integers
    :param attrs: The attributes to pass in credentials
    :return:
    """
    for id, value in attrs.items():
        h_challenge = hashlib.new('sha256')
        h_challenge.update(value.encode())
        attrs[id] = Conversion.bytes2integer(h_challenge.digest())
    return attrs


def get_hash(a, b, c):
    h_challenge = hashlib.sha256()
    h_challenge.update(a, b, c)
    return h_challenge.digest()

