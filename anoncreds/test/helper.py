from anoncreds.protocol.proof import Proof


def getPresentationToken(issuers, prover, encodedAttrs):
    presentationToken = {}
    for key, val in prover.U.items():
        issuer = issuers[key]
        A, e, vprimeprime = issuer.generateCredential(prover.U[key], encodedAttrs[key])
        v = prover.vprime[key] + vprimeprime
        presentationToken[key] = {"A": A, "e": e, "v": v}
    return presentationToken


def getProver(attrs, pki):
    prover = Proof(pki)
    prover.setAttrs(attrs)
    return prover, attrs