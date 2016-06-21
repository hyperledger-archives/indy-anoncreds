from anoncreds.protocol.proof import Proof


def getPresentationToken(issuers, prover, encodedAttrs):
    presentationToken = {}
    for key, val in prover.U.items():
        issuer = issuers[key]
        A, e, vprimeprime = issuer.issue(prover.U[key], encodedAttrs[key])
        v = prover.vprime[key] + vprimeprime
        presentationToken[key] = {"A": A, "e": e, "v": v}
    return presentationToken


def getProver(attrs, pki):
    prover = Proof(pki)
    prover.set_attrs(attrs)
    return prover, attrs