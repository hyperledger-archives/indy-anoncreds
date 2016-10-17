from typing import Any
from typing import Dict
from typing import List
from typing import Sequence
from typing import Tuple

from anoncreds.protocol.attribute_repo import AttrRepo
from anoncreds.protocol.cred_def_secret_key import CredDefSecretKey
from anoncreds.protocol.cred_def_store import CredDefStore
from anoncreds.protocol.globals import LARGE_VPRIME_PRIME, LARGE_E_START, LARGE_E_END_RANGE
from anoncreds.protocol.issuer_key import IssuerKey
from anoncreds.protocol.issuer_secret_key import IssuerSecretKey
from anoncreds.protocol.utils import get_prime_in_range, strToCryptoInteger
from config.config import cmod


class Issuer:
    def __init__(self, id,
                 attributeRepo: AttrRepo,
                 credDefStore: CredDefStore,
                 issuerSecretKeyStore):
        self.id = id
        self.issuerSecretKeyStore = issuerSecretKeyStore
        self.attributeRepo = attributeRepo
        self.credDefStore = credDefStore

    def createCred(self, proverId, cduid, name, version, U):
        attributes = self.attributeRepo.getAttributes(proverId)
        encAttrs = attributes.encoded()
        isk = self.issuerSecretKeyStore.get(cduid)  # type: IssuerSecretKey
        return Issuer.generateCredential(
            U,
            next(iter(encAttrs.values())),
            isk.PK,
            isk.sk)

    @classmethod
    def generateCredential(cls,
                           uValue, attributes, pk,
                           sk: CredDefSecretKey):
        """
        Issue the credential for the defined attributes

        :param u: The `u` value provided by the prover
        :param attrs: The attributes for which the credential needs to be generated
        :return: The presentation token as a combination of (A, e, vprimeprime)
        """
        u = strToCryptoInteger(uValue) if isinstance(uValue, str) else uValue

        if not u:
            raise ValueError("u must be provided to issue a credential")
        # Generate a random prime and
        # Set the Most-significant-bit to 1
        vprimeprime = cmod.integer(cmod.randomBits(LARGE_VPRIME_PRIME) |
                              (2 ** (LARGE_VPRIME_PRIME - 1)))
        # Generate prime number in the range (2^596, 2^596 + 2^119)
        estart = 2 ** LARGE_E_START
        eend = (estart + 2 ** LARGE_E_END_RANGE)
        e = get_prime_in_range(estart, eend)
        A = cls._sign(pk, attributes, vprimeprime, u, e, sk.p_prime, sk.q_prime)
        return A, e, vprimeprime

    @staticmethod
    def _sign(pk: IssuerKey, attrs, v, u, e, p_prime, q_prime):
        Rx = 1 % pk.N
        # Get the product sequence for the (R[i] and attrs[i]) combination
        for k, val in attrs.items():
            Rx = Rx * (pk.R[str(k)] ** val)
        if u != 0:
            u = u % pk.N
            Rx *= u
        nprime = p_prime * q_prime
        einverse = e % nprime
        Q = pk.Z / (Rx * (pk.S ** v)) % pk.N
        A = Q ** (einverse ** -1) % pk.N
        return A

