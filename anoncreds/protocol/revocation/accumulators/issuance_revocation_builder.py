from charm.toolbox.pairinggroup import PairingGroup, ZR

from anoncreds.protocol.revocation.accumulators.types import RevocationPublicKey, RevocationSecretKey, \
    Accumulator, AccumulatorSecretKey, \
    Witness, WitnessCredential


class IssuanceRevocationBuilder:
    def __init__(self, revocPK: RevocationPublicKey, revocSK: RevocationSecretKey):
        self._group = PairingGroup(revocPK.groupType)
        self._pk = revocPK
        self._sk = revocSK

    def issueRevocationCredential(self, accum: Accumulator, accSk: AccumulatorSecretKey,
                                  g, Ur, i=None):
        if accum.isFull():
            raise ValueError("Accumulator is full. New one must be issued.")

        # TODO: currently all revo creds are issued sequentially
        i = i if i else accum.currentI
        accum.currentI += 1
        vrPrimeprime = self._group.random(ZR)
        c = self._group.random(ZR)

        sigma = (self._pk.h0 * Ur * g[i] * (self._pk.h2 ** vrPrimeprime)) ** (1 / (self._sk.x + c))
        omega = g[0] / g[0]
        for j in accum.V:
            omega *= g[accum.L + 1 - j + i]

        sigmai = self._pk.g ** (1 / (self._sk.sk + (accSk.gamma ** i)))
        ui = self._pk.u ** (accSk.gamma ** i)

        accum.acc *= g[accum.L + 1 - i]
        accum.V.add(i)

        witi = Witness(sigmai, ui, g[i], omega, accum.V.copy())

        return WitnessCredential(accum.iA, sigma, c, vrPrimeprime, witi, g[i], i)

    def revoke(self, accum: Accumulator, g, i):
        accum.V.discard(i)
        accum.acc = accum.acc / g[accum.L + 1 - i]
