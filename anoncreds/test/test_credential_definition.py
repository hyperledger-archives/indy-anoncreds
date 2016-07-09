from anoncreds.protocol.credential_definition import CredentialDefinition


def testSerialization(credDef1):
    sk = credDef1.SK
    serializedSk = credDef1.serializedSK
    deserializedSk = CredentialDefinition.getDeserializedSK(serializedSk)
    assert sk == deserializedSk
    p_prime = CredentialDefinition.getPPrime(deserializedSk)
    q_prime = CredentialDefinition.getQPrime(deserializedSk)
    assert credDef1.p_prime == p_prime
    assert credDef1.q_prime == q_prime
