from collections import namedtuple


IssuerPublicKey = namedtuple("IssuerPublicKey", ["N", "R", "S", "Z"])


Credential = namedtuple("Credential", ["A", "e", "v"])

