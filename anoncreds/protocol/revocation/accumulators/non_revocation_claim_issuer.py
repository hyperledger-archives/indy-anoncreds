from anoncreds.protocol.globals import PAIRING_GROUP
from anoncreds.protocol.types import NonRevocationClaim, RevocationPublicKey, \
    RevocationSecretKey, \
    Accumulator, AccumulatorPublicKey, AccumulatorSecretKey, Witness, \
    ID, TimestampType, Tails
from anoncreds.protocol.utils import currentTimestampMillisec, groupIdentityG1, groupIdentityG2
from anoncreds.protocol.wallet.issuer_wallet import IssuerWallet
from config.config import cmod


class NonRevocationClaimIssuer:
    def __init__(self, wallet: IssuerWallet):
        self._wallet = wallet

    async def genRevocationKeys(self) -> (
            RevocationPublicKey, RevocationSecretKey):
        group = cmod.PairingGroup(
            PAIRING_GROUP)  # super singular curve, 1024 bits

        g = group.random(cmod.G1)
        gprime = group.random(cmod.G2)

        h = group.random(cmod.G1)  # random element of the group G
        h0 = group.random(cmod.G1)
        h1 = group.random(cmod.G1)
        h2 = group.random(cmod.G1)
        htilde = group.random(cmod.G1)

        u = group.random(cmod.G2)
        hhat = group.random(cmod.G2)

        qr = group.order()  # order q_R of the group

        x = group.random(cmod.ZR)  # random(qr)
        sk = group.random(cmod.ZR)  # random(qr)

        pk = g ** sk
        y = hhat ** x

        return (RevocationPublicKey(qr, g, gprime, h, h0, h1, h2, htilde, hhat, u, pk, y),
                RevocationSecretKey(x, sk))

    async def issueAccumulator(self, schemaId, iA, L) \
            -> (Accumulator, Tails, AccumulatorPublicKey,
                    AccumulatorSecretKey):
        pkR = await self._wallet.getPublicKeyRevocation(schemaId)
        group = cmod.PairingGroup(PAIRING_GROUP)
        gamma = group.random(cmod.ZR)

        tails = Tails()
        gCount = 2 * L
        for i in range(gCount):
            if i != L + 1:
                gVal = pkR.g ** (gamma ** i)
                gPrimeVal = pkR.gprime ** (gamma ** i)
                tails.addValue(i, gVal, gPrimeVal)
        z = cmod.pair(pkR.g, pkR.gprime) ** (gamma ** (L + 1))

        acc = 1
        V = set()

        accPK = AccumulatorPublicKey(z)
        accSK = AccumulatorSecretKey(gamma)
        accum = Accumulator(iA, acc, V, L)
        return accum, tails, accPK, accSK

    async def issueNonRevocationClaim(self, schemaId: ID, Ur, iA, i) -> (
            NonRevocationClaim, Accumulator, TimestampType):
        accum = await self._wallet.getAccumulator(schemaId)
        pkR = await self._wallet.getPublicKeyRevocation(schemaId)
        skR = await self._wallet.getSecretKeyRevocation(schemaId)
        tails = await self._wallet.getTails(schemaId)
        skAccum = await self._wallet.getSecretKeyAccumulator(schemaId)
        m2 = await self._wallet.getContextAttr(schemaId)

        if accum.isFull():
            raise ValueError("Accumulator is full. New one must be issued.")

        # TODO: currently all revo creds are issued sequentially
        group = cmod.PairingGroup(
            PAIRING_GROUP)  # super singular curve, 1024 bits

        i = i if i else accum.currentI
        accum.currentI += 1
        vrPrimeprime = group.random(cmod.ZR)
        c = group.random(cmod.ZR)

        m2 = group.init(cmod.ZR, int(m2))
        sigma = (pkR.h0 * (pkR.h1 ** m2) * Ur * tails.g[i] * (
            pkR.h2 ** vrPrimeprime)) ** (1 / (skR.x + c))
        omega = groupIdentityG2()
        for j in accum.V:
            omega *= tails.gprime[accum.L + 1 - j + i]

        sigmai = pkR.gprime ** (1 / (skR.sk + (skAccum.gamma ** i)))
        ui = pkR.u ** (skAccum.gamma ** i)

        accum.acc *= tails.gprime[accum.L + 1 - i]
        accum.V.add(i)

        witness = Witness(sigmai, ui, tails.g[i], omega, accum.V.copy())

        ts = currentTimestampMillisec()
        return (
            NonRevocationClaim(accum.iA, sigma, c, vrPrimeprime, witness,
                               i,
                               m2), accum, ts)

    async def revoke(self, schemaId: ID, i) -> (Accumulator, TimestampType):
        accum = await self._wallet.getAccumulator(schemaId)
        tails = await self._wallet.getTails(schemaId)

        accum.V.discard(i)
        accum.acc /= tails.gprime[accum.L + 1 - i]

        ts = currentTimestampMillisec()

        return accum, ts
