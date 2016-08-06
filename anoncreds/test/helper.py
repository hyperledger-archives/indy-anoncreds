from anoncreds.protocol.credential_definition import generateCredential
from anoncreds.protocol.prover import ProofBuilder
from anoncreds.protocol.types import Credential


# Why a dictionary of credentials is known as a presentationToken?
# Source: https://cups.cs.cmu.edu/soups/2013/posters/soups13_posters-final24.pdf
# In general, Privacy-ABCs (Privacy Attribute-Based Credentials) are issued just like ordinary
# cryptographic credentials (e.g., X.509 credentials) using a digital (secret) signature key.
# However, Privacy-ABCs allow their holder to transform them into a new token, called
# presentation token, in such a way that the privacy of the user is protected
from anoncreds.protocol.verifier import verify_proof


def getPresentationToken(credDefs, proofBuilder, encodedAttrs):
    presentationToken = {}
    for key, val in proofBuilder.U.items():
        credDef = credDefs[key]
        A, e, vprimeprime = generateCredential(proofBuilder.U[key],
                                               encodedAttrs[key],
                                               credDef.PK,
                                               credDef.p_prime,
                                               credDef.q_prime
                                               )
        v = proofBuilder.vprime[key] + vprimeprime
        presentationToken[key] = Credential(A, e, v)
    return presentationToken


def getProofBuilder(attrs, credDefPks):
    proofBuilder = ProofBuilder(credDefPks)
    proofBuilder.setAttrs(attrs)
    return proofBuilder, attrs


def verifyPredicateProof(credDefs, credDefPks, proofBuilderWithAttribs,
                             revealedAttrs, predicate, verifier):

    proofBuilder, attrs = proofBuilderWithAttribs
    presentationToken = getPresentationToken(credDefs, proofBuilder, attrs.encoded())
    nonce = verifier.generateNonce(interactionId=1)
    proof = proofBuilder.preparePredicateProof(credential=presentationToken,
                                               attrs=attrs.encoded(),
                                               revealedAttrs=revealedAttrs,
                                               nonce=nonce,
                                               predicate=predicate)
    return verifier.verifyPredicateProof(proof=proof,
                                         credDefPks=credDefPks,
                                         nonce=nonce,
                                         attrs=attrs.encoded(),
                                         revealedAttrs=revealedAttrs,
                                         predicate=predicate)


def prepareProofAndVerify(credDefs, credDefPks, proofBuilder,
                          attrs, revealedAttrs,
                          proofNonce=None, verifyNonce=None):

    presentationToken = getPresentationToken(
        credDefs, proofBuilder,
        attrs.encoded())

    proof = ProofBuilder.prepareProof(credDefPks=proofBuilder.credDefPks,
                                      masterSecret=proofBuilder.masterSecret,
                                      credential=presentationToken,
                                      attrs=attrs.encoded(),
                                      revealedAttrs=revealedAttrs,
                                      nonce=proofNonce)

    vNonce = proofNonce if not verifyNonce else verifyNonce
    return verify_proof(proof=proof,
                               nonce=vNonce,
                               credDefPks=credDefPks,
                               attrs=attrs.encoded(),
                               revealedAttrs=revealedAttrs)


def verifyProof(credDefs, credDefPks, attrNames,
                proofBuilderWithAttribs, revealedAttrs, *verifiers):

    proofBuilder, attrs = proofBuilderWithAttribs

    if attrNames:
        totalEncoded = 0
        for key, value in credDefs.items():
            totalEncoded += len(attrs.encoded()[key])

        assert totalEncoded == len(attrNames)

    verified = True
    for verifier in verifiers:
        nonce = verifier.generateNonce(interactionId=1)
        verifStatus = prepareProofAndVerify(credDefs,
                                            credDefPks,
                                            proofBuilder,
                                            attrs,
                                            revealedAttrs,
                                            nonce)

        if not verifStatus:
            verified = False

    return verified
