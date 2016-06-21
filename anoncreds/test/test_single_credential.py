from anoncreds.protocol.types import GVT
from anoncreds.test.helper import getPresentationToken


def testSingleProver(issuer1, attrNames1, proverAndAttrs1, verifier1):

    prover, attrs = proverAndAttrs1
    assert len(attrs.encoded()[GVT.name]) == len(attrNames1)

    presentationToken = getPresentationToken({GVT.name: issuer1},
                                             prover,
                                             attrs.encoded())

    nonce = verifier1.generateNonce

    # Prepare proof
    revealedAttrs = ['name']
    proof = prover.prepare_proof(credential=presentationToken,
                                 attrs=attrs.encoded(),
                                 revealedAttrs=revealedAttrs,
                                 nonce=nonce)

    # Verify the proof
    verify_status = verifier1.verify_proof(proof=proof,
                                           nonce=nonce,
                                           attrs=attrs.encoded(),
                                           revealedAttrs=revealedAttrs)

    assert verify_status


def testMultipleProvers(issuer1, attrNames1, proverAndAttrs1,
                        proverAndAttrs2, verifier1):

    prover1, attrs1 = proverAndAttrs1
    prover2, attrs2 = proverAndAttrs2
    assert len(attrs1.encoded()[GVT.name]) == len(attrNames1)
    assert len(attrs2.encoded()[GVT.name]) == len(attrNames1)

    presentationToken1 = getPresentationToken({GVT.name: issuer1}, prover1, attrs1.encoded())
    presentationToken2 = getPresentationToken({GVT.name: issuer1}, prover2, attrs2.encoded())

    nonce1 = verifier1.generateNonce
    nonce2 = verifier1.generateNonce

    # Prepare proofs
    revealedAttrs = ['name']
    proof1 = prover1.prepare_proof(credential=presentationToken1,
                                   attrs=attrs1.encoded(),
                                   revealedAttrs=revealedAttrs,
                                   nonce=nonce1)
    proof2 = prover2.prepare_proof(credential=presentationToken2,
                                   attrs=attrs2.encoded(),
                                   revealedAttrs=revealedAttrs,
                                   nonce=nonce2)

    assert verifier1.verify_proof(proof=proof1, nonce=nonce1,
                                  attrs=attrs1.encoded(),
                                  revealedAttrs=revealedAttrs)
    assert verifier1.verify_proof(proof=proof2, nonce=nonce2,
                                  attrs=attrs2.encoded(),
                                  revealedAttrs=revealedAttrs)

