from anoncreds.protocol.issuer import Issuer
from anoncreds.protocol.prover import Prover, ProverInitializer
from anoncreds.protocol.types import SecretData, PublicData, Claims, ProofInput, PredicateGE, PublicDataPrimary, \
    PublicDataRevocation, SecretDataPrimary, SecretDataRevocation
from anoncreds.protocol.verifier import Verifier
from anoncreds.test.conftest import GVT, XYZCorp


def testSingleIssuerSingleProver(primes1):
    #### 1. Issuer setup

    # generate a credential definition
    credDef = Issuer.genCredDef('GVT', '1.0', GVT.attribNames())

    # generate Issuer's public and secret keys
    pk, sk = Issuer.genKeys(credDef, **primes1)

    # ---> store pk in a public torage
    # ---> store sk in an issuer-private storage

    # generate Issuer's public and secret revocation keys
    pkR, skR = Issuer.genRevocationKeys()
    # ---> store pkR in a public torage
    # ---> store skR in an issuer-private storage

    # issue empty accumulators with public/secret keys and corresponding Gi
    L = 5
    iA = 110
    accum1, g1, pkAccum1, skAccum1 = Issuer.issueAccumulator(iA, pkR, L)
    # ---> store accum1, g1, pkAccum1 in a public storage
    # ---> store skAccum1 in an issuer-private storage



    # ........................................

    publicDataPrimary = PublicDataPrimary(credDef, pk)
    publicDataRevoc = PublicDataRevocation(credDef, pkR, accum1, pkAccum1, g1)
    publicData = PublicData(publicDataPrimary, publicDataRevoc)

    secretDataPrimary = SecretDataPrimary(publicDataPrimary, sk)
    secretDataRevoc = SecretDataRevocation(publicDataRevoc, skR, skAccum1)
    secretData = SecretData(secretDataPrimary, secretDataRevoc)

    #### 2. New User added:
    userId = 111

    ### Issuer:
    # <--- load pk, sk, pkR, skR, accum1, g1, pkAccum1, skAccum1
    issuer = Issuer(secretData)

    # Issuer computes context attr
    # <--- load iA
    m2 = Issuer.genContxt(iA, userId)
    # ---> store m2 to issuer-prover-private storage

    # set attributes
    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')

    # encode attrs to 256-bit ints
    encodedAttrs = attrs.encoded()
    # ---> store other attrs to semi-public storage

    ### Prover:

    # prover generate a master secret m1 (common for all)
    m1 = ProverInitializer.genMasterSecret()
    # ---> store m1 to prover-private storage

    # <--- load pk, pkR, acc
    proverInitializer = ProverInitializer(userId,
                                          {credDef: m2},
                                          {credDef: publicData},
                                          m1)

    #### 3. Issuance of claims

    ### Prover:

    # Prover gens v' and U
    U = proverInitializer.getU(credDef)
    Ur = proverInitializer.getUr(credDef)
    # ~~~~> send U, Ur to Issuer

    ### Issuer:

    # Issuer issues primary claim
    primaryClaim = issuer.issuePrimaryClaim(encodedAttrs, m2, U)

    # Issuer issues non-revocation claim
    nonRevocationClaim = issuer.issueNonRevocationClaim(m2, Ur)

    # ---> publish updated acc
    # ~~~~> send primaryClaim, nonRevocationClaim to prover

    ### Prover:

    # update primary claim with private value and store
    c1 = proverInitializer.initPrimaryClaim(credDef, primaryClaim)
    # ---> store primaryClaim in prover-private storage

    # update non-revocation claim with private value and store
    c2 = proverInitializer.initNonRevocationClaim(credDef, nonRevocationClaim)
    # ---> store primaryClaim in prover-private storage





    # ...........................................................






    #### Presentation

    ### Verifier:

    # attributes to be validated
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18)])
    # gen nonce
    nonce = Verifier.generateNonce()

    # ~~~> send attrs to be validated and Nonce to Prover


    ### Prover:

    # find claims needed to validate the attributes
    # probably it can be defined outside anoncred protocol
    # ---> load all claims (c1, c2)
    allClaims = {credDef: Claims(c1, c2)}
    proofClaims = Prover.findClaims(allClaims, proofInput)

    # <--- load pk, pkR, accum1, g1, pkAccum1 for required issuers
    prover = Prover(userId, {credDef: publicData}, m1)

    # Prover updates witness
    proofClaims = prover.updateNonRevocationClaims(proofClaims)
    # ---> store c2s

    # prepare proof
    proof = prover.prepareProof(proofClaims, nonce)
    # ~~~> send proof to verifier

    ### Verifier:

    # <--- load pk, pkR, accum1, g1, pkAccum1 for issuers participating in proof
    verifId = 5555
    verifier = Verifier(verifId, {credDef: publicData})

    # verify proof
    allRevealedAttrs = {'name': encodedAttrs['name']}
    assert verifier.verify(proof, allRevealedAttrs, nonce)


def testMultiplIssuersSingleProver(primes1, primes2):
    #### 1. Issuer setup

    # generate credential definitions
    credDef1 = Issuer.genCredDef("GVT", "1.0", GVT.attribNames())
    credDef2 = Issuer.genCredDef("XYZCorp", "1.0", XYZCorp.attribNames())

    # generate Issuer's public and secret keys
    pk1, sk1 = Issuer.genKeys(credDef1, **primes1)
    pk2, sk2 = Issuer.genKeys(credDef2, **primes2)

    # ---> store pk in a public torage
    # ---> store sk in an issuer-private storage

    # generate Issuer's public and secret revocation keys
    pkR1, skR1 = Issuer.genRevocationKeys()
    pkR2, skR2 = Issuer.genRevocationKeys()
    # ---> store pkR in a public torage
    # ---> store skR in an issuer-private storage

    # issue empty accumulators with public/secret keys and corresponding Gi
    L = 5
    iA1 = 110
    accum1, g1, pkAccum1, skAccum1 = Issuer.issueAccumulator(iA1, pkR1, L)
    iA2 = 111
    accum2, g2, pkAccum2, skAccum2 = Issuer.issueAccumulator(iA2, pkR2, L)
    # ---> store accum1, g1, pkAccum1 in a public storage
    # ---> store skAccum1 in an issuer-private storage



    # ........................................

    publicDataPrimary1 = PublicDataPrimary(credDef1, pk1)
    publicDataRevoc1 = PublicDataRevocation(credDef1, pkR1, accum1, pkAccum1, g1)
    publicData1 = PublicData(publicDataPrimary1, publicDataRevoc1)

    publicDataPrimary2 = PublicDataPrimary(credDef2, pk2)
    publicDataRevoc2 = PublicDataRevocation(credDef2, pkR2, accum2, pkAccum2, g2)
    publicData2 = PublicData(publicDataPrimary2, publicDataRevoc2)

    secretDataPrimary1 = SecretDataPrimary(publicDataPrimary1, sk1)
    secretDataRevoc1 = SecretDataRevocation(publicDataRevoc1, skR1, skAccum1)
    secretData1 = SecretData(secretDataPrimary1, secretDataRevoc1)

    secretDataPrimary2 = SecretDataPrimary(publicDataPrimary2, sk2)
    secretDataRevoc2 = SecretDataRevocation(publicDataRevoc2, skR2, skAccum2)
    secretData2 = SecretData(secretDataPrimary2, secretDataRevoc2)

    #### 2. New User added:
    userId = 111

    ### Issuer:
    # <--- load pk, sk, pkR, skR, accum1, g1, pkAccum1, skAccum1
    issuer1 = Issuer(secretData1)
    issuer2 = Issuer(secretData2)

    # Issuer computes context attr
    # <--- load iA
    m21 = Issuer.genContxt(iA1, userId)
    m22 = Issuer.genContxt(iA2, userId)
    # ---> store m2 to issuer-prover-private storage

    # set attributes
    attrs1 = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    attrs2 = XYZCorp.attribs(status='FULL', period=8)

    # encode attrs to 256-bit ints
    encodedAttrs1 = attrs1.encoded()
    encodedAttrs2 = attrs2.encoded()
    # ---> store other attrs to semi-public storage

    ### Prover:

    # prover generate a master secret m1 (common for all)
    m1 = ProverInitializer.genMasterSecret()
    # ---> store m1 to prover-private storage

    # <--- load pk, pkR, acc
    proverInitializer = ProverInitializer(userId,
                                          {credDef1: m21, credDef2: m22},
                                          {credDef1: publicData1, credDef2: publicData2},
                                          m1)

    #### 3. Issuance of claims

    ### Prover:

    # Prover gens v' and U
    U1 = proverInitializer.getU(credDef1)
    Ur1 = proverInitializer.getUr(credDef1)
    U2 = proverInitializer.getU(credDef2)
    Ur2 = proverInitializer.getUr(credDef2)
    # ~~~~> send U, Ur to Issuer

    ### Issuer:

    # Issuer issues primary claim
    primaryClaim1 = issuer1.issuePrimaryClaim(encodedAttrs1, m21, U1)
    primaryClaim2 = issuer2.issuePrimaryClaim(encodedAttrs2, m22, U2)

    # Issuer issues non-revocation claim
    nonRevocationClaim1 = issuer1.issueNonRevocationClaim(m21, Ur1)
    nonRevocationClaim2 = issuer2.issueNonRevocationClaim(m22, Ur2)

    # ---> publish updated acc
    # ~~~~> send primaryClaim, nonRevocationClaim to prover

    ### Prover:

    # update primary claim with private value and store
    c11 = proverInitializer.initPrimaryClaim(credDef1, primaryClaim1)
    c12 = proverInitializer.initPrimaryClaim(credDef2, primaryClaim2)
    # ---> store primaryClaim in prover-private storage

    # update non-revocation claim with private value and store
    c21 = proverInitializer.initNonRevocationClaim(credDef1, nonRevocationClaim1)
    c22 = proverInitializer.initNonRevocationClaim(credDef2, nonRevocationClaim2)
    # ---> store primaryClaim in prover-private storage





    # ...........................................................






    #### Presentation

    ### Verifier:

    # attributes to be validated
    proofInput = ProofInput(['status'],
                            [PredicateGE('age', 18)])
    # gen nonce
    nonce = Verifier.generateNonce()

    # ~~~> send attrs to be validated and Nonce to Prover


    ### Prover:

    # find claims needed to validate the attributes
    # probably it can be defined outside anoncred protocol
    # ---> load all claims (c1, c2)
    allClaims = {credDef1: Claims(c11, c21),
                 credDef2: Claims(c12, c22),}
    proofClaims = Prover.findClaims(allClaims, proofInput)

    # <--- load pk, pkR, accum1, g1, pkAccum1 for required issuers
    prover = Prover(userId, {credDef1: publicData1, credDef2: publicData2}, m1)

    # Prover updates witness
    proofClaims = prover.updateNonRevocationClaims(proofClaims)
    # ---> store c2s

    # prepare proof
    proof = prover.prepareProof(proofClaims, nonce)
    # ~~~> send proof to verifier

    ### Verifier:

    # <--- load pk, pkR, accum1, g1, pkAccum1 for issuers participating in proof
    verifId = 5555
    verifier = Verifier(verifId, {credDef1: publicData1, credDef2: publicData2})

    # verify proof
    allRevealedAttrs = {'status': encodedAttrs2['status']}
    assert verifier.verify(proof, allRevealedAttrs, nonce)


def testSingleIssuerSingleProverPrimaryOnly(primes1):
    # 1. cred def
    credDef = Issuer.genCredDef('GVT', '1.0', GVT.attribNames())

    # 2. keys
    pk, sk = Issuer.genKeys(credDef, **primes1)

    publicDataPrimary = PublicDataPrimary(credDef, pk)
    publicData = PublicData(publicDataPrimary)

    secretDataPrimary = SecretDataPrimary(publicDataPrimary, sk)
    secretData = SecretData(secretDataPrimary)

    # 3. set attrs
    userId = 111
    iA = 100
    issuer = Issuer(secretData)

    attrs = GVT.attribs(name='Alex', age=28, height=175, sex='male')
    encodedAttrs = attrs.encoded()

    m1 = ProverInitializer.genMasterSecret()
    m2 = Issuer.genContxt(iA, userId)

    # 4. issie claim
    proverInitializer = ProverInitializer(userId,
                                          {credDef: m2},
                                          {credDef: publicData},
                                          m1)
    U = proverInitializer.getU(credDef)
    primaryClaim = issuer.issuePrimaryClaim(encodedAttrs, m2, U)
    c1 = proverInitializer.initPrimaryClaim(credDef, primaryClaim)

    # 5. to be proved
    proofInput = ProofInput(['name'],
                            [PredicateGE('age', 18)])
    allClaims = {credDef: Claims(c1)}
    proofClaims = Prover.findClaims(allClaims, proofInput)

    # 6. create proof
    prover = Prover(userId, {credDef: publicData}, m1)
    nonce = Verifier.generateNonce()
    proof = prover.prepareProof(proofClaims, nonce)

    # 7. verify
    verifId = 5555
    verifier = Verifier(verifId, {credDef: publicData})
    allRevealedAttrs = {'name': encodedAttrs['name']}
    assert verifier.verify(proof, allRevealedAttrs, nonce)
