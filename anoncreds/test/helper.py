from anoncreds.protocol.prover import Proof
from anoncreds.protocol.types import Credential


def getPresentationToken(credDefs, proof, encodedAttrs):
    presentationToken = {}
    for key, val in proof.U.items():
        credDef = credDefs[key]
        A, e, vprimeprime = credDef.generateCredential(proof.U[key],
                                                       encodedAttrs[key])
        v = proof.vprime[key] + vprimeprime
        presentationToken[key] = Credential(A, e, v)
    return presentationToken


def getProof(attrs, pki):
    proof = Proof(pki)
    proof.setAttrs(attrs)
    return proof, attrs
