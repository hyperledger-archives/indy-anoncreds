from copy import copy

from config.config import cmod

from anoncreds.protocol.utils import strToCryptoInteger, base58decode
from anoncreds.protocol.globals import MASTER_SEC_RAND, \
    PK_N, PK_S, PK_Z, PK_R
from anoncreds.protocol.types import SerFmt
from anoncreds.protocol.utils import serialize


class IssuerKey:
    """
    Public key an Issuer creates and publishes for a particular credential
    definition.
    """
    def __init__(self, uid, N, R, S, Z):
        self.uid = uid
        self.N = cmod.integer(N)
        self.R = {k: cmod.integer(v) % N for k, v in R.items()}
        self.S = cmod.integer(S) % N
        self.Z = cmod.integer(Z) % N

    def __repr__(self):
        return str(self.uid)

    @classmethod
    def fromKeys(cls, keys, desz=base58decode):
        N = strToCryptoInteger(desz(keys["N"]))
        S = strToCryptoInteger(desz(keys["S"]))
        Z = strToCryptoInteger(desz(keys["Z"]))
        R = {}
        for k, v in keys["R"].items():
            R[k] = strToCryptoInteger(desz(v))
        return cls(N, R, S, Z)

    @staticmethod
    def deser(v, n):
        if isinstance(v, cmod.integer):
            return v % n
        elif isinstance(v, int):
            return cmod.integer(v) % n
        else:
            raise RuntimeError("unknown type: {}".format(type(v)))

    def inFieldN(self):
        """
        Returns new Public Key with same values, in field N
        :return:
        """

        r = {k: self.deser(v, self.N) for k, v in self.R.items()}
        return IssuerKey(self.uid,
                         self.N, r,
                         self.deser(self.S, self.N),
                         self.deser(self.Z, self.N))

    def get(self, serFmt: SerFmt=SerFmt.default):
        R = copy(self.R)
        data = {
            MASTER_SEC_RAND: R["0"],
            PK_N: self.N,
            PK_S: self.S,
            PK_Z: self.Z,
            PK_R: R  # TODO Master secret rand number, R[0] is still passed,
            #  remove that
        }
        return serialize(data, serFmt)
