from charm.toolbox.pairinggroup import PairingGroup, ZR

from anoncreds.protocol.revocation.accumulators.types import RevocationPublicKey, RevocationSecretKey, \
    Accumulator, AccumulatorSecretKey, \
    Witness, WitnessCredential


class IssuanceRevocationBuilder:
    def __init__(self, group: PairingGroup, revocPK: RevocationPublicKey, revocSK: RevocationSecretKey):
        self._group = group
        self._pk = revocPK
        self._sk = revocSK

    def issueRevocationCredential(self, iA, accum: Accumulator, accSk: AccumulatorSecretKey,
                                  g, Ur, i):
        vrPrimeprime = self._group.random(ZR)
        c = self._group.random(ZR)

        sigma = (self._pk.h0 * Ur * g[i] * (self._pk.h2 ** vrPrimeprime)) ** (1 / (self._sk.x + c))
        omega = g[0] / g[0]
        for j in accum.V:
            omega *= g[self._pk.L + 1 - j + i]

        sigmai = self._pk.g ** (1 / (self._sk.sk + (accSk.gamma ** i)))
        ui = self._pk.u ** (accSk.gamma ** i)

        accum.acc *= g[self._pk.L + 1 - i]
        accum.V.add(i)

        witi = Witness(sigmai, ui, g[i], omega, accum.V.copy())

        return WitnessCredential(iA, sigma, c, vrPrimeprime, witi, g[i], i)

    def revoke(self, accum: Accumulator, g, i):
        accum.V.discard(i)
        accum.acc = accum.acc / g[self._pk.L + 1 - i]
