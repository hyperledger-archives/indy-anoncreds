from anoncreds.protocol.prover import Prover
from anoncreds.protocol.types import Credential

def getPresentationToken(credDefs, prover, encodedAttrs):
    presentationToken = {}
    for key, val in prover.U.items():
        credDef = credDefs[key]
        A, e, vprimeprime = credDef.generateCredential(prover.U[key], encodedAttrs[key])
        v = prover.vprime[key] + vprimeprime
        presentationToken[key] = Credential(A, e, v)
    return presentationToken


def getProver(attrs, pki):
    prover = Prover(pki)
    prover.setAttrs(attrs)
    return prover, attrs