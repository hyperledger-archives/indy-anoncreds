import uuid

from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import ProofBuilder, Prover
from anoncreds.protocol.types import Credential


# Why a dictionary of credentials is known as a presentationToken?
# Source: https://cups.cs.cmu.edu/soups/2013/posters/soups13_posters-final24.pdf
# In general, Privacy-ABCs (Privacy Attribute-Based Credentials) are issued just like ordinary
# cryptographic credentials (e.g., X.509 credentials) using a digital (secret) signature key.
# However, Privacy-ABCs allow their holder to transform them into a new token, called
# presentation token, in such a way that the privacy of the user is protected
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.cred_def_test_store import MemoryCredDefStore
from anoncreds.test.issuer_key_test_store import MemoryIssuerKeyStore


def getPresentationToken(credDefs,
                         pks,
                         issuerSecretKeys,
                         proofBuilder,
                         encodedAttrs):
    presentationToken = {}
    for key, val in proofBuilder.U.items():
        credDef = credDefs[key]
        pk = pks[key]
        sk = issuerSecretKeys[key].sk
        A, e, vprimeprime = Issuer.generateCredential(proofBuilder.U[key],
                                                      encodedAttrs[key],
                                                      pk,
                                                      sk)
        v = proofBuilder.vprime[key] + vprimeprime
        presentationToken[key] = Credential(A, e, v)
    return presentationToken


def getProofBuilderAndAttribs(attribs, credDefs, issuerPks):
    uid = str(uuid.uuid4())
    mcds = MemoryCredDefStore()
    for cd in credDefs.values():
        mcds.publishCredDef(cd)
    miks = MemoryIssuerKeyStore()
    for ipk in issuerPks.values():
        miks.publishIssuerKey(ipk)
    prover = Prover(id=uid, cds=mcds, iks=miks)
    vprime = prover.getVPrimes(*tuple(issuerPks.keys()))
    proofBuilder = ProofBuilder(issuerPks, masterSecret=prover.masterSecret,
                                vprime=vprime)
    return proofBuilder, attribs


def verifyPredicateProof(credDefs,
                         credDefPks,
                         issuerSecretKeys,
                         proofBuilderWithAttribs,
                         revealedAttrs,
                         predicate,
                         verifier: Verifier):

    proofBuilder, attrs = proofBuilderWithAttribs
    presentationToken = getPresentationToken(credDefs,
                                             credDefPks,
                                             issuerSecretKeys,
                                             proofBuilder, attrs.encoded())
    nonce = verifier.generateNonce(interactionId=1)
    proof = proofBuilder.preparePredicateProof(creds=presentationToken,
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


def prepareProofAndVerify(credDefs,
                          credDefPks,
                          issuerSecretKeys,
                          proofBuilder,
                          attrs,
                          revealedAttrs,
                          proofNonce=None,
                          verifyNonce=None):

    presentationToken = getPresentationToken(
        credDefs, credDefPks, issuerSecretKeys,
        proofBuilder, attrs.encoded())

    proof = ProofBuilder.prepareProof(issuerPks=proofBuilder.issuerPks,
                                      masterSecret=proofBuilder.masterSecret,
                                      creds=presentationToken,
                                      encodedAttrs=attrs.encoded(),
                                      revealedAttrs=revealedAttrs,
                                      nonce=proofNonce)

    vNonce = proofNonce if not verifyNonce else verifyNonce
    return Verifier.verifyProof(proof=proof,
                               nonce=vNonce,
                               credDefPks=credDefPks,
                               attrs=attrs.encoded(),
                               revealedAttrs=revealedAttrs)


def verifyProof(credDefs, credDefPks, issuerSecretKeys,
                attrNames, proofBuilderWithAttribs, revealedAttrs, *verifiers):

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
                                            issuerSecretKeys,
                                            proofBuilder,
                                            attrs,
                                            revealedAttrs,
                                            nonce)

        if not verifStatus:
            verified = False

    return verified
