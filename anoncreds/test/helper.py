from anoncreds.protocol.credential_definition import generateCredential
from anoncreds.protocol.prover import ProofBuilder
from anoncreds.protocol.types import Credential


# Why a dictionary of credentials is known as a presentationToken?
# Source: https://cups.cs.cmu.edu/soups/2013/posters/soups13_posters-final24.pdf
# In general, Privacy-ABCs (Privacy Attribute-Based Credentials) are issued just like ordinary
# cryptographic credentials (e.g., X.509 credentials) using a digital (secret) signature key.
# However, Privacy-ABCs allow their holder to transform them into a new token, called
# presentation token, in such a way that the privacy of the user is protected

def getPresentationToken(credDefs, proof, encodedAttrs):
    presentationToken = {}
    for key, val in proof.U.items():
        credDef = credDefs[key]
        A, e, vprimeprime = generateCredential(proof.U[key],
                                                            encodedAttrs[key],
                                                            credDef.PK,
                                                            credDef.p_prime,
                                                            credDef.q_prime
                                                            )
        v = proof.vprime[key] + vprimeprime
        presentationToken[key] = Credential(A, e, v)
    return presentationToken


def getProofBuilder(attrs, pki):
    proofBuilder = ProofBuilder(pki)
    proofBuilder.setAttrs(attrs)
    return proofBuilder, attrs


