from anoncreds.test.helper import getPresentationToken


def testMultipleCredentialSingleProof(credDefs, proverAndAttrsForMultiple1, proverAndAttrsForMultiple2, verifierMulti1):
    prover, attrs1 = proverAndAttrsForMultiple1
    prover, attrs2 = proverAndAttrsForMultiple2

    attrs = attrs1 + attrs2

    presentationToken = getPresentationToken(credDefs, prover, attrs.encoded())

    nonce = verifierMulti1.generateNonce

    revealedAttrs = ['name']
    proof = prover.prepareProof(credential=presentationToken, attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs, nonce=nonce)

    verify_status = verifierMulti1.verifyProof(proof=proof, nonce=nonce,
                                           attrs=attrs.encoded(),
                                           revealedAttrs=revealedAttrs)

    assert verify_status


def testMultipleCredentialMultipleVerifier(credDefs,
                                           proverAndAttrsForMultiple1,
                                           proverAndAttrsForMultiple2,
                                           verifierMulti1, verifierMulti2):
    prover, attrs1 = proverAndAttrsForMultiple1
    prover, attrs2 = proverAndAttrsForMultiple2

    attrs = attrs1 + attrs2

    presentationToken = getPresentationToken(credDefs, prover, attrs.encoded())

    nonce1 = verifierMulti1.generateNonce
    nonce2 = verifierMulti2.generateNonce

    revealedAttrs = ['name']
    proof1 = prover.prepareProof(credential=presentationToken,
                                  attrs=attrs.encoded(),
                                  revealedAttrs=revealedAttrs,
                                  nonce=nonce1)

    verify_status1 = verifierMulti1.verifyProof(proof=proof1,
                                                 nonce=nonce1,
                                                 attrs=attrs.encoded(),
                                                 revealedAttrs=revealedAttrs)

    proof2 = prover.prepareProof(credential=presentationToken,
                                  attrs=attrs.encoded(),
                                  revealedAttrs=revealedAttrs,
                                  nonce=nonce2)

    verify_status2 = verifierMulti1.verifyProof(proof=proof2,
                                                 nonce=nonce2,
                                                 attrs=attrs.encoded(),
                                                 revealedAttrs=revealedAttrs)

    assert verify_status1 and verify_status2


