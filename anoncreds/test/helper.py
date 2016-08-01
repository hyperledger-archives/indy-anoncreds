from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.prover import Proof
from anoncreds.protocol.types import Credential, AttribsDef, AttribType


# FIXME Document why a dictionary of credentials is known as a presentationToken.
def getPresentationToken(credDefs, proof, encodedAttrs):
    presentationToken = {}
    for key, val in proof.U.items():
        credDef = credDefs[key]
        A, e, vprimeprime = CredentialDefinition.generateCredential(proof.U[key],
                                                            encodedAttrs[key],
                                                            credDef.PK,
                                                            credDef.p_prime,
                                                            credDef.q_prime
                                                            )
        v = proof.vprime[key] + vprimeprime
        presentationToken[key] = Credential(A, e, v)
    return presentationToken


# FIXME misleading method name. Returns proof and attrs.
def getProof(attrs, pki):
    proof = Proof(pki)
    proof.setAttrs(attrs)
    return proof, attrs


GVT = AttribsDef('gvt',
                 [AttribType('name', encode=True),
                  AttribType('age', encode=False),
                  AttribType('sex', encode=True)])
XYZCorp = AttribsDef('xyz',
                     [AttribType('status', encode=True)])
NASEMP = GVT + XYZCorp
