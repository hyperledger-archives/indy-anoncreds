from anoncreds.protocol.credential_definition import CredentialDefinition, getDeserializedSK, getPPrime, getQPrime


def testSerialization(gvtCredDef):
    sk = gvtCredDef.SK
    serializedSk = gvtCredDef.serializedSK
    deserializedSk = getDeserializedSK(serializedSk)
    assert sk == deserializedSk
    p_prime = getPPrime(deserializedSk)
    q_prime = getQPrime(deserializedSk)
    assert gvtCredDef.p_prime == p_prime
    assert gvtCredDef.q_prime == q_prime
