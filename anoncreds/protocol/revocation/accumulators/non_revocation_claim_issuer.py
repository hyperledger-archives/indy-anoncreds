from anoncreds.protocol.globals import PAIRING_GROUP
from anoncreds.protocol.types import NonRevocationClaim, RevocationPublicKey, \
    RevocationSecretKey, \
    Accumulator, TailsType, AccumulatorPublicKey, AccumulatorSecretKey, Witness, \
    ID, TimestampType
from anoncreds.protocol.utils import currentTimestampMillisec, groupIdentityG1
from anoncreds.protocol.wallet.issuer_wallet import IssuerWallet
from config.config import cmod


class NonRevocationClaimIssuer:
    def __init__(self, wallet: IssuerWallet):
        self._wallet = wallet

    async def genRevocationKeys(self) -> (
            RevocationPublicKey, RevocationSecretKey):
        group = cmod.PairingGroup(
            PAIRING_GROUP)  # super singular curve, 1024 bits

        h = group.random(cmod.G1)  # random element of the group G
        h0 = group.random(cmod.G1)
        h1 = group.random(cmod.G1)
        h2 = group.random(cmod.G1)
        g = group.random(cmod.G1)
        htilde = group.random(cmod.G1)
        u = group.random(cmod.G1)

        qr = group.order()  # order q_R of the group

        x = group.random(cmod.ZR)  # random(qr)
        sk = group.random(cmod.ZR)  # random(qr)

        pk = g ** sk
        y = h ** x

        return (RevocationPublicKey(qr, g, h, h0, h1, h2, htilde, u, pk, y, x),
                RevocationSecretKey(x, sk))

    async def issueAccumulator(self, schemaId, iA, L) \
            -> (
                    Accumulator, TailsType, AccumulatorPublicKey,
                    AccumulatorSecretKey):
        pkR = await self._wallet.getPublicKeyRevocation(schemaId)
        group = cmod.PairingGroup(PAIRING_GROUP)
        gamma = group.random(cmod.ZR)

        g = {}
        gCount = 2 * L
        for i in range(gCount):
            if i != L + 1:
                g[i] = pkR.g ** (gamma ** i)
        z = cmod.pair(pkR.g, pkR.g) ** (gamma ** (L + 1))

        acc = 1
        V = set()

        accPK = AccumulatorPublicKey(z)
        accSK = AccumulatorSecretKey(gamma)
        accum = Accumulator(iA, acc, V, L)
        return accum, g, accPK, accSK

    async def issueNonRevocationClaim(self, schemaId: ID, Ur, iA, i) -> (
            NonRevocationClaim, Accumulator, TimestampType):
        accum = await self._wallet.getAccumulator(schemaId)
        pkR = await self._wallet.getPublicKeyRevocation(schemaId)
        skR = await self._wallet.getSecretKeyRevocation(schemaId)
        g = await self._wallet.getTails(schemaId)
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
        sigma = (pkR.h0 * (pkR.h1 ** m2) * Ur * g[i] * (
            pkR.h2 ** vrPrimeprime)) ** (1 / (skR.x + c))
        omega = groupIdentityG1()
        for j in accum.V:
            omega *= g[accum.L + 1 - j + i]

        sigmai = pkR.g ** (1 / (skR.sk + (skAccum.gamma ** i)))
        ui = pkR.u ** (skAccum.gamma ** i)

        accum.acc *= g[accum.L + 1 - i]
        accum.V.add(i)

        witness = Witness(sigmai, ui, g[i], omega, accum.V.copy())

        ts = currentTimestampMillisec()
        return (
            NonRevocationClaim(accum.iA, sigma, c, vrPrimeprime, witness, g[i],
                               i,
                               m2), accum, ts)

    async def revoke(self, schemaId: ID, i) -> (Accumulator, TimestampType):
        accum = await self._wallet.getAccumulator(schemaId)
        tails = await self._wallet.getTails(schemaId)

        accum.V.discard(i)
        accum.acc /= tails[accum.L + 1 - i]

        ts = currentTimestampMillisec()

        return accum, ts
