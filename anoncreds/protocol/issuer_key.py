from charm.core.math.integer import integer

from anoncreds.protocol.utils import strToCharmInteger, base58decode


class IssuerKey:
    """
    Public key an Issuer creates and publishes for a particular credential
    definition.
    """
    def __init__(self, uid, N, R, S, Z):
        self.uid = uid
        self.N = N
        self.R = R
        self.S = S
        self.Z = Z

    @classmethod
    def fromKeys(cls, keys):
        N = strToCharmInteger(base58decode(keys["N"]))
        S = strToCharmInteger(base58decode(keys["S"]))
        Z = strToCharmInteger(base58decode(keys["Z"]))
        R = {}
        for k, v in keys["R"].items():
            R[k] = strToCharmInteger(base58decode(v))
        return cls(N, R, S, Z)

    @staticmethod
    def deser(v, n):
        if isinstance(v, integer):
            return v % n
        elif isinstance(v, int):
            return integer(v) % n
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