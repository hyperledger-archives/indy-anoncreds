from anoncreds.protocol.globals import LARGE_VPRIME_PRIME, LARGE_E_START, \
    LARGE_E_END_RANGE, LARGE_PRIME
from anoncreds.protocol.types import PublicKey, SecretKey, PrimaryClaim, ID, \
    Attribs, ClaimAttributeValues
from anoncreds.protocol.utils import get_prime_in_range, strToCryptoInteger, \
    randomQR
from anoncreds.protocol.wallet.issuer_wallet import IssuerWallet
from config.config import cmod
from typing import Dict


class PrimaryClaimIssuer:
    def __init__(self, wallet: IssuerWallet):
        self._wallet = wallet

    async def genKeys(self, schemaId: ID, p_prime=None, q_prime=None) -> (
            PublicKey, SecretKey):
        schema = await self._wallet.getSchema(schemaId)
        if not schema.attrNames and isinstance(schema.attrNames, list):
            raise ValueError("List of attribute names is required to "
                             "setup credential definition")

        p_prime = p_prime if p_prime else PrimaryClaimIssuer._genPrime()
        p = 2 * p_prime + 1

        q_prime = q_prime if q_prime else PrimaryClaimIssuer._genPrime()
        q = 2 * q_prime + 1

        n = p * q

        # Generate a random quadratic number
        S = randomQR(n)

        # Generate random numbers corresponding to every attributes
        Xz = PrimaryClaimIssuer._genX(p_prime, q_prime)
        Xr = {}

        for name in schema.attrNames:
            Xr[str(name)] = PrimaryClaimIssuer._genX(p_prime, q_prime)

        # Generate `Z` as the exponentiation of the quadratic random 'S' .
        # over the random `Xz` in the group defined by modulus `n`
        Z = (S ** Xz) % n

        # Generate random numbers corresponding to every attributes
        R = {}
        for name in schema.attrNames:
            R[str(name)] = (S ** Xr[str(name)]) % n

        # Rms is a random number needed corresponding to master secret m1
        Rms = (S ** PrimaryClaimIssuer._genX(p_prime, q_prime)) % n

        # Rctxt is a random number needed corresponding to context attribute m2
        Rctxt = (S ** PrimaryClaimIssuer._genX(p_prime, q_prime)) % n

        return PublicKey(n, Rms, Rctxt, R, S, Z), SecretKey(p_prime, q_prime)

    @classmethod
    def _genX(cls, p_prime, q_prime):
        maxValue = p_prime * q_prime - 1
        minValue = 2
        return cmod.integer(cmod.random(maxValue - minValue)) + minValue

    @classmethod
    def _genPrime(cls):
        # Generate 2 large primes `p_prime` and `q_prime` and use them
        # to generate another 2 primes `p` and `q` of 1024 bits
        prime = cmod.randomPrime(LARGE_PRIME)
        i = 0
        while not cmod.isPrime(2 * prime + 1):
            prime = cmod.randomPrime(LARGE_PRIME)
            i += 1
        print("In {} iterations, found prime {}".format(i, prime))
        return prime

    async def issuePrimaryClaim(self, schemaId: ID, attributes: Attribs,
                                U) -> (PrimaryClaim, Dict[str, ClaimAttributeValues]):
        u = strToCryptoInteger(U) if isinstance(U, str) else U

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
        encodedAttrs = attributes.encoded()
        A = await self._sign(schemaId, encodedAttrs, vprimeprime, u, e)

        m2 = await self._wallet.getContextAttr(schemaId)
        claimAttributes = \
            {attr: ClaimAttributeValues(attributes._vals[attr], encodedAttrs[attr]) for attr in attributes.keys()}

        return (PrimaryClaim(m2, A, e, vprimeprime), claimAttributes)

    async def _sign(self, schemaId: ID, attrs, v, u, e):
        pk = await self._wallet.getPublicKey(schemaId)
        sk = await self._wallet.getSecretKey(schemaId)
        m2 = await self._wallet.getContextAttr(schemaId)

        Rx = 1 % pk.N
        # Get the product sequence for the (R[i] and attrs[i]) combination
        for k, val in attrs.items():
            Rx = Rx * (pk.R[str(k)] ** val)
        Rx = Rx * (pk.Rctxt ** m2)
        if u != 0:
            u = u % pk.N
            Rx *= u
        nprime = sk.pPrime * sk.qPrime
        einverse = e % nprime
        Q = pk.Z / (Rx * (pk.S ** v)) % pk.N
        A = Q ** (einverse ** -1) % pk.N
        return A

    def __repr__(self):
        return str(self.__dict__)
