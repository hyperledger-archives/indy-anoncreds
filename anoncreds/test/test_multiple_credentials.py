from anoncreds.test.helper import getPresentationToken
from anoncreds.protocol.verifier import verify_proof


def testMultipleCredentialSingleProof(credDefs,
                                      credDefsPk,
                                      proverAndAttrsForMultiple1,
                                      proverAndAttrsForMultiple2,
                                      verifierMulti1):
    prover, attrs1 = proverAndAttrsForMultiple1
    prover, attrs2 = proverAndAttrsForMultiple2

    attrs = attrs1 + attrs2

    presentationToken = getPresentationToken(credDefs, prover, attrs.encoded())

    nonce = verifierMulti1.generateNonce(interactionId=1)

    revealedAttrs = ['name']
    proof = prover.prepareProof(credential=presentationToken,
                                attrs=attrs.encoded(),
                                revealedAttrs=revealedAttrs,
                                nonce=nonce)

    verify_status = verify_proof(proof=proof,
                                 pk_i=credDefsPk,
                                 nonce=nonce,
                                 attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs)

    assert verify_status


def testMultipleCredentialMultipleVerifier(credDefs,
                                           credDefsPk,
                                           proverAndAttrsForMultiple1,
                                           proverAndAttrsForMultiple2,
                                           verifierMulti1, verifierMulti2):
    prover, attrs1 = proverAndAttrsForMultiple1
    prover, attrs2 = proverAndAttrsForMultiple2

    attrs = attrs1 + attrs2

    presentationToken = getPresentationToken(credDefs, prover, attrs.encoded())

    nonce1 = verifierMulti1.generateNonce(interactionId=2)
    nonce2 = verifierMulti2.generateNonce(interactionId=2)

    revealedAttrs = ['name']
    proof1 = prover.prepareProof(credential=presentationToken,
                                 attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs,
                                 nonce=nonce1)

    verify_status1 = verify_proof(proof=proof1,
                                  pk_i=credDefsPk,
                                  nonce=nonce1,
                                  attrs=attrs.encoded(),
                                  revealedAttrs=revealedAttrs)

    proof2 = prover.prepareProof(credential=presentationToken,
                                 attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs,
                                 nonce=nonce2)

    verify_status2 = verify_proof(proof=proof2,
                                  pk_i=credDefsPk,
                                  nonce=nonce2,
                                  attrs=attrs.encoded(),
                                  revealedAttrs=revealedAttrs)

    assert verify_status1 and verify_status2
