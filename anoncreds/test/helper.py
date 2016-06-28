from anoncreds.protocol.prover import Prover
from anoncreds.protocol.types import Credential

def getPresentationToken(issuers, prover, encodedAttrs):
    presentationToken = {}
    for key, val in prover.U.items():
        issuer = issuers[key]
        A, e, vprimeprime = issuer.generateCredential(prover.U[key], encodedAttrs[key])
        v = prover.vprime[key] + vprimeprime
        presentationToken[key] = Credential(A, e, v)
    return presentationToken


def getProver(attrs, pki):
    prover = Prover(pki)
    prover.setAttrs(attrs)
    return prover, attrs