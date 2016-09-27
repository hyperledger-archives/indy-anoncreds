from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair

from anoncreds.protocol.types import SecretData, NonRevocationClaim, RevocationPublicKey, RevocationSecretKey, \
    Accumulator, GType, AccumulatorPublicKey, AccumulatorSecretKey, Witness


class NonRevocationClaimIssuer:
    def __init__(self, secretData: SecretData):
        self._data = secretData
        self._group = PairingGroup(secretData.pkR.groupType)

    @classmethod
    def genRevocationKeys(cls) -> (RevocationPublicKey, RevocationSecretKey):
        groupType = 'SS1024'  # super singular curve, 1024 bits
        group = PairingGroup(groupType)

        h = group.random(G1)  # random element of the group G
        h0 = group.random(G1)
        h1 = group.random(G1)
        h2 = group.random(G1)
        g = group.random(G1)
        htilde = group.random(G1)
        u = group.random(G1)

        qr = group.order()  # order q_R of the group

        x = group.random(ZR)  # random(qr)
        sk = group.random(ZR)  # random(qr)

        pk = g ** sk
        y = h ** x

        return (RevocationPublicKey(qr, g, h, h0, h1, h2, htilde, u, pk, y, x, groupType),
                RevocationSecretKey(x, sk))

    @classmethod
    def issueAccumulator(cls, iA, pk: RevocationPublicKey, L) \
            -> (Accumulator, GType, AccumulatorPublicKey, AccumulatorSecretKey):
        group = PairingGroup(pk.groupType)
        gamma = group.random(ZR)

        g = {}
        gCount = 2 * L
        for i in range(gCount):
            if i != L + 1:
                g[i] = pk.g ** (gamma ** i)
        z = pair(pk.g, pk.g) ** (gamma ** (L + 1))

        acc = 1
        V = set()

        accPK = AccumulatorPublicKey(z)
        accSK = AccumulatorSecretKey(gamma)
        accum = Accumulator(iA, acc, V, L)
        return (accum, g, accPK, accSK)

    def issueNonRevocationClaim(self, m2, Ur, i=None) -> NonRevocationClaim:
        accum = self._data.accum
        pkR = self._data.pkR
        skR = self._data.skR
        g = self._data.g
        skAccum = self._data.skAccum

        if accum.isFull():
            raise ValueError("Accumulator is full. New one must be issued.")

        # TODO: currently all revo creds are issued sequentially
        i = i if i else accum.currentI
        accum.currentI += 1
        vrPrimeprime = self._group.random(ZR)
        c = self._group.random(ZR)

        m2 = self._group.init(ZR, int(m2))
        sigma = (pkR.h0 * (pkR.h1 ** m2) * Ur * g[i] * (pkR.h2 ** vrPrimeprime)) ** (1 / (skR.x + c))
        omega = g[0] / g[0]
        for j in accum.V:
            omega *= g[accum.L + 1 - j + i]

        sigmai = pkR.g ** (1 / (skR.sk + (skAccum.gamma ** i)))
        ui = pkR.u ** (skAccum.gamma ** i)

        accum.acc *= g[accum.L + 1 - i]
        accum.V.add(i)

        witness = Witness(sigmai, ui, g[i], omega, accum.V.copy())

        return NonRevocationClaim(accum.iA, sigma, c, vrPrimeprime, witness, g[i], i, m2)

    def revoke(self, i):
        accum = self._data.accum
        g = self._data.g

        accum.V.discard(i)
        accum.acc /= g[accum.L + 1 - i]
