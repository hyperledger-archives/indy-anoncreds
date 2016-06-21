from anoncreds.test.helper import getPresentationToken


def testMultipleCredentialSingleProof(credDefs, proverAndAttrsForMultiple1, proverAndAttrsForMultiple2, verifierMulti1):
    prover, attrs1 = proverAndAttrsForMultiple1
    prover, attrs2 = proverAndAttrsForMultiple2

    attrs = attrs1 + attrs2

    presentationToken = getPresentationToken(credDefs, prover, attrs.encoded())

    nonce = verifierMulti1.Nonce

    revealedAttrs = ['name']
    proof = prover.prepare_proof(credential=presentationToken, attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs, nonce=nonce)

    verify_status = verifierMulti1.verify_proof(proof=proof, nonce=nonce,
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

    nonce1 = verifierMulti1.Nonce
    nonce2 = verifierMulti2.Nonce

    revealedAttrs = ['name']
    proof1 = prover.prepare_proof(credential=presentationToken,
                                  attrs=attrs.encoded(),
                                  revealedAttrs=revealedAttrs,
                                  nonce=nonce1)

    verify_status1 = verifierMulti1.verify_proof(proof=proof1,
                                                 nonce=nonce1,
                                                 attrs=attrs.encoded(),
                                                 revealedAttrs=revealedAttrs)

    proof2 = prover.prepare_proof(credential=presentationToken,
                                  attrs=attrs.encoded(),
                                  revealedAttrs=revealedAttrs,
                                  nonce=nonce2)

    verify_status2 = verifierMulti1.verify_proof(proof=proof2,
                                                 nonce=nonce2,
                                                 attrs=attrs.encoded(),
                                                 revealedAttrs=revealedAttrs)

    assert verify_status1 and verify_status2


