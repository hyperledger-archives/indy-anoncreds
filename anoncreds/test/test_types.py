from anoncreds.protocol.types import PublicKey, ClaimDefinition, Claims
from config.config import cmod


def testClaimDefFromToDict():
    claimDef = ClaimDefinition(name='claimDefName', version='1.0', type='CL',
                               attrNames=['attr1', 'attr2', 'attr3'],
                               issuerId='issuer1')
    assert claimDef == ClaimDefinition.fromStrDict(claimDef.toStrDict())


def testPKFromToDict():
    pk = PublicKey(N=cmod.integer(11),
                   Rms=cmod.integer(12),
                   Rctxt=cmod.integer(13),
                   R={'a': cmod.integer(1), 'b': cmod.integer(2)},
                   S=cmod.integer(14),
                   Z=cmod.integer(15))
    assert pk == PublicKey.fromStrDict(pk.toStrDict())


def testClaimsFromToDict(claimsGvtProver1):
    assert claimsGvtProver1 == Claims.fromStrDict(claimsGvtProver1.toStrDict())
