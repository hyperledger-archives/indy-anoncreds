from anoncreds.test.helper import verifyProof


def testMultiCredSingleProof(gvtAndXyzCredDefs,
                             gvtAndXyzCredDefPks,
                             proofBuilderWithGvtAndXyzAttribs,
                             verifierMulti1):
    assert verifyProof(gvtAndXyzCredDefs, gvtAndXyzCredDefPks, None,
                 proofBuilderWithGvtAndXyzAttribs, ['name'],
                verifierMulti1)


def testMultiCredMultiVerifier(gvtAndXyzCredDefs,
                              gvtAndXyzCredDefPks,
                              proofBuilderWithGvtAndXyzAttribs,
                              verifierMulti1, verifierMulti2):
    assert verifyProof(gvtAndXyzCredDefs, gvtAndXyzCredDefPks, None,
                proofBuilderWithGvtAndXyzAttribs, ['name'],
                verifierMulti1, verifierMulti2)

