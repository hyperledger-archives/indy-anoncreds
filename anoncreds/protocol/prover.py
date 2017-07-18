from functools import reduce
from typing import Dict, Sequence, Any

from anoncreds.protocol.globals import LARGE_MASTER_SECRET, LARGE_M2_TILDE
from anoncreds.protocol.primary.primary_proof_builder import \
    PrimaryClaimInitializer, PrimaryProofBuilder
from anoncreds.protocol.revocation.accumulators.non_revocation_proof_builder import \
    NonRevocationClaimInitializer, \
    NonRevocationProofBuilder
from anoncreds.protocol.types import PrimaryClaim, NonRevocationClaim, Proof, \
    InitProof, ProofRequest, ProofClaims, \
    FullProof, \
    Schema, ID, SchemaKey, ClaimRequest, Claims, RequestedProof, AggregatedProof, ProofInfo, ClaimAttributeValues
from anoncreds.protocol.utils import get_hash_as_int, isCryptoInteger
from anoncreds.protocol.wallet.prover_wallet import ProverWallet
from config.config import cmod


class Prover:
    def __init__(self, wallet: ProverWallet):
        self.wallet = wallet

        self._primaryClaimInitializer = PrimaryClaimInitializer(wallet)
        self._nonRevocClaimInitializer = NonRevocationClaimInitializer(wallet)

        self._primaryProofBuilder = PrimaryProofBuilder(wallet)
        self._nonRevocProofBuilder = NonRevocationProofBuilder(wallet)

    #
    # PUBLIC
    #

    @property
    def proverId(self):
        return self.wallet.walletId

    async def createClaimRequest(self, schemaId: ID, proverId=None,
                                 reqNonRevoc=True) -> ClaimRequest:
        """
        Creates a claim request to the issuer.

        :param schemaId: The schema ID (reference to claim
        definition schema)
        :param proverId: a prover ID request a claim for (if None then
        the current prover default ID is used)
        :param reqNonRevoc: whether to request non-revocation claim
        :return: Claim Request
        """
        await self._genMasterSecret(schemaId)
        U = await self._genU(schemaId)
        Ur = None if not reqNonRevoc else await self._genUr(schemaId)
        proverId = proverId if proverId else self.proverId
        return ClaimRequest(userId=proverId, U=U, Ur=Ur)

    async def createClaimRequests(self, schemaIds: Sequence[ID],
                                  proverId=None,
                                  reqNonRevoc=True) -> Dict[ID, ClaimRequest]:
        """
        Creates a claim request to the issuer.

        :param schemaIds: The schema IDs (references to claim
        definition schema)
        :param proverId: a prover ID request a claim for (if None then
        the current prover default ID is used)
        :param reqNonRevoc: whether to request non-revocation claim
        :return: a dictionary of Claim Requests for each Schema.
        """
        res = {}
        for schemaId in schemaIds:
            res[schemaId] = await self.createClaimRequest(schemaId,
                                                          proverId,
                                                          reqNonRevoc)
        return res

    async def processClaim(self, schemaId: ID, claimAttributes: Dict[str, ClaimAttributeValues], signature: Claims):
        """
        Processes and saves a received Claim for the given Schema.

        :param schemaId: The schema ID (reference to claim
        definition schema)
        :param claims: claims to be processed and saved
        """
        await self.wallet.submitContextAttr(schemaId, signature.primaryClaim.m2)
        await self.wallet.submitClaimAttributes(schemaId, claimAttributes)

        await self._initPrimaryClaim(schemaId, signature.primaryClaim)
        if signature.nonRevocClaim:
            await self._initNonRevocationClaim(schemaId, signature.nonRevocClaim)

    async def processClaims(self, allClaims: Dict[ID, Claims]):
        """
        Processes and saves received Claims.

        :param claims: claims to be processed and saved for each claim
        definition.
        """
        res = []
        for schemaId, (claim_signature, claim_attributes) in allClaims.items():
            res.append(await self.processClaim(schemaId, claim_attributes, claim_signature))
        return res

    async def presentProof(self, proofRequest: ProofRequest) -> FullProof:
        """
        Presents a proof to the verifier.

        :param proofRequest: description of a proof to be presented (revealed
        attributes, predicates, timestamps for non-revocation)
        :return: a proof (both primary and non-revocation) and revealed attributes (initial non-encoded values)
        """
        claims, requestedProof = await self._findClaims(proofRequest)
        proof = await self._prepareProof(claims, proofRequest.nonce, requestedProof)
        return proof

    #
    # REQUEST CLAIMS
    #

    async def _genMasterSecret(self, schemaId: ID):
        ms = cmod.integer(cmod.randomBits(LARGE_MASTER_SECRET))
        await self.wallet.submitMasterSecret(schemaId=schemaId, ms=ms)

    async def _genU(self, schemaId: ID):
        claimInitData = await self._primaryClaimInitializer.genClaimInitData(
            schemaId)
        await self.wallet.submitPrimaryClaimInitData(schemaId=schemaId,
                                                     claimInitData=claimInitData)
        return claimInitData.U

    async def _genUr(self, schemaId: ID):
        claimInitData = await self._nonRevocClaimInitializer.genClaimInitData(
            schemaId)
        await self.wallet.submitNonRevocClaimInitData(schemaId=schemaId,
                                                      claimInitData=claimInitData)
        return claimInitData.U

    async def _initPrimaryClaim(self, schemaId: ID, claim: PrimaryClaim):
        claim = await self._primaryClaimInitializer.preparePrimaryClaim(
            schemaId,
            claim)
        await self.wallet.submitPrimaryClaim(schemaId=schemaId, claim=claim)

    async def _initNonRevocationClaim(self, schemaId: ID,
                                      claim: NonRevocationClaim):
        claim = await self._nonRevocClaimInitializer.initNonRevocationClaim(
            schemaId,
            claim)
        await self.wallet.submitNonRevocClaim(schemaId=schemaId,
                                              claim=claim)

    #
    # PRESENT PROOF
    #

    async def _findClaims(self, proofRequest: ProofRequest) -> (
            Dict[SchemaKey, ProofClaims], Dict[str, Any]):
        revealedAttrs, predicates = proofRequest.verifiableAttributes, proofRequest.predicates

        foundRevealedAttrs = {}
        foundPredicates = {}
        proofClaims = {}
        schemas = {}
        allClaimsAttributes = await self.wallet.getAllClaimsAttributes()

        async def addProof():
            revealedAttrsForClaim = [a for a in revealedAttrs.values() if a.name in claim.keys()]
            revealedPredicatesForClaim = [p for p in predicates.values() if p.attrName in claim.keys()]

            claims = await self.wallet.getClaimSignature(ID(schemaId=schemaId))
            proofClaim = ProofClaims(claims=claims, revealedAttrs=revealedAttrsForClaim,
                                     predicates=revealedPredicatesForClaim)

            proofClaims[schemaId] = proofClaim

        for schemaKey, c in allClaimsAttributes.items():
            schemas[schemaKey] = (await self.wallet.getSchema(ID(schemaKey)))

        for uuid, revealedAttr in revealedAttrs.items():
            matches = [(schemas[key].seqId, c) for key, c in allClaimsAttributes.items() if revealedAttr.name in c
                       and (schemas[key].seqId == revealedAttr.schema_seq_no if revealedAttr.schema_seq_no else True)
                       and (schemas[key].issuerId == revealedAttr.issuer_did if revealedAttr.issuer_did else True)]

            if len(matches) == 0:
                raise ValueError("A claim isn't found for the following attributes: {}", revealedAttr.name)

            schemaId, claim = matches[0]
            foundRevealedAttrs[uuid] = [str(schemaId), str(claim[revealedAttr.name].raw),
                                        str(claim[revealedAttr.name].encoded)]

            if schemaId not in proofClaims:
                await addProof()

        for uuid, predicate in predicates.items():
            matches = [(schemas[key].seqId, c) for key, c in allClaimsAttributes.items() if predicate.attrName in c
                       and (schemas[key].seqId == predicate.schema_seq_no if predicate.schema_seq_no else True)
                       and (schemas[key].issuerId == predicate.issuer_did if predicate.issuer_did else True)]

            if len(matches) == 0:
                raise ValueError("A claim isn't found for the following predicate: {}", predicate)

            schemaId, claim = matches[0]
            foundPredicates[uuid] = str(schemaId)

            if schemaId not in proofClaims:
                await addProof()

        requestedProof = RequestedProof(revealed_attrs=foundRevealedAttrs, predicates=foundPredicates)

        return proofClaims, requestedProof

    async def _prepareProof(self, claims: Dict[SchemaKey, ProofClaims],
                            nonce, requestedProof) -> FullProof:
        m1Tilde = cmod.integer(cmod.randomBits(LARGE_M2_TILDE))
        initProofs = {}
        CList = []
        TauList = []

        # 1. init proofs
        for schemaId, val in claims.items():
            c1, c2, revealedAttrs, predicates = val.claims.primaryClaim, val.claims.nonRevocClaim, val.revealedAttrs, val.predicates

            claim = await self.wallet.getClaimAttributes(ID(schemaId=schemaId))

            nonRevocInitProof = None
            if c2:
                nonRevocInitProof = await self._nonRevocProofBuilder.initProof(
                    schemaId, c2)
                CList += nonRevocInitProof.asCList()
                TauList += nonRevocInitProof.asTauList()

            primaryInitProof = None
            if c1:
                m2Tilde = cmod.integer(int(
                    nonRevocInitProof.TauListParams.m2)) if nonRevocInitProof else None
                primaryInitProof = await self._primaryProofBuilder.initProof(
                    schemaId, c1, revealedAttrs, predicates,
                    m1Tilde, m2Tilde, claim)
                CList += primaryInitProof.asCList()
                TauList += primaryInitProof.asTauList()

            initProof = InitProof(nonRevocInitProof, primaryInitProof)
            initProofs[schemaId] = initProof

        # 2. hash
        cH = self._get_hash(self._prepare_collection(CList), self._prepare_collection(TauList), nonce)

        # 3. finalize proofs
        proofs = {}
        for schemaId, initProof in initProofs.items():
            nonRevocProof = None
            if initProof.nonRevocInitProof:
                nonRevocProof = await self._nonRevocProofBuilder.finalizeProof(
                    schemaId, cH, initProof.nonRevocInitProof)
            primaryProof = await self._primaryProofBuilder.finalizeProof(
                schemaId, cH, initProof.primaryInitProof)

            schema = await self.wallet.getSchema(ID(schemaId=schemaId))

            proof = Proof(primaryProof, nonRevocProof)
            proofInfo = ProofInfo(proof=proof, schema_seq_no=schemaId, issuer_did=schema.issuerId)

            proofs[str(schemaId)] = proofInfo

        aggregatedProof = AggregatedProof(cH, self._prepare_collection(CList))

        return FullProof(proofs, aggregatedProof, requestedProof)

    async def _getCList(self, initProofs: Dict[Schema, InitProof]):
        CList = []
        for initProof in initProofs.values():
            CList += await initProof.nonRevocInitProof.asCList()
            CList += await initProof.primaryInitProof.asCList()
            return CList

    async def _getTauList(self, initProofs: Dict[Schema, InitProof]):
        TauList = []
        for initProof in initProofs.values():
            TauList += await initProof.nonRevocInitProof.asTauList()
            TauList += await initProof.primaryInitProof.asTauList()
        return TauList

    def _prepare_collection(self, values):
        return [cmod.toInt(el) if isCryptoInteger(el) else el for el in values]

    def _get_hash(self, CList, TauList, nonce):
        return get_hash_as_int(nonce,
                               *reduce(lambda x, y: x + y, [TauList, CList]))
