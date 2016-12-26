from abc import abstractmethod

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import ClaimDefinition, PublicKey, SecretKey, ID, \
    RevocationPublicKey, AccumulatorPublicKey, Accumulator, TailsType, \
    RevocationSecretKey, AccumulatorSecretKey, \
    TimestampType
from anoncreds.protocol.wallet.wallet import Wallet, WalletInMemory


class IssuerWallet(Wallet):
    def __init__(self, claimDefId, repo: PublicRepo):
        Wallet.__init__(self, claimDefId, repo)

    # SUBMIT

    @abstractmethod
    async def submitClaimDef(self,
                             claimDef: ClaimDefinition) -> ClaimDefinition:
        raise NotImplementedError

    @abstractmethod
    async def submitPublicKeys(self, claimDefId: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        raise NotImplementedError

    @abstractmethod
    async def submitSecretKeys(self, claimDefId: ID, sk: SecretKey,
                               skR: RevocationSecretKey = None):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumPublic(self, claimDefId: ID,
                                accumPK: AccumulatorPublicKey,
                                accum: Accumulator, tails: TailsType):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumSecret(self, claimDefId: ID,
                                accumSK: AccumulatorSecretKey):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumUpdate(self, claimDefId: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        raise NotImplementedError

    @abstractmethod
    async def submitContextAttr(self, claimDefId: ID, m2):
        raise NotImplementedError

    # GET

    @abstractmethod
    async def getSecretKey(self, claimDefId: ID) -> SecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getSecretKeyRevocation(self,
                                     claimDefId: ID) -> RevocationSecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getSecretKeyAccumulator(self,
                                      claimDefId: ID) -> AccumulatorSecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getContextAttr(self, claimDefId: ID):
        raise NotImplementedError


class IssuerWalletInMemory(IssuerWallet, WalletInMemory):
    def __init__(self, claimDefId, repo: PublicRepo):
        WalletInMemory.__init__(self, claimDefId, repo)

        # other dicts with key=claimDefKey
        self._sks = {}
        self._skRs = {}
        self._accumSks = {}
        self._m2s = {}
        self._attributes = {}

    # SUBMIT

    async def submitClaimDef(self,
                             claimDef: ClaimDefinition) -> ClaimDefinition:
        claimDef = await self._repo.submitClaimDef(claimDef)
        self._cacheClaimDef(claimDef)
        return claimDef

    async def submitPublicKeys(self, claimDefId: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        pk, pkR = await self._repo.submitPublicKeys(claimDefId, pk, pkR)
        await self._cacheValueForId(self._pks, claimDefId, pk)
        if pkR:
            await  self._cacheValueForId(self._pkRs, claimDefId, pkR)
        return pk, pkR

    async def submitSecretKeys(self, claimDefId: ID, sk: SecretKey,
                               skR: RevocationSecretKey = None):
        await  self._cacheValueForId(self._sks, claimDefId, sk)
        if skR:
            await  self._cacheValueForId(self._skRs, claimDefId, skR)

    async def submitAccumPublic(self, claimDefId: ID,
                                accumPK: AccumulatorPublicKey,
                                accum: Accumulator,
                                tails: TailsType) -> AccumulatorPublicKey:
        accumPK = await self._repo.submitAccumulator(claimDefId, accumPK, accum,
                                                     tails)
        await self._cacheValueForId(self._accums, claimDefId, accum)
        await self._cacheValueForId(self._accumPks, claimDefId, accumPK)
        await self._cacheValueForId(self._tails, claimDefId, tails)
        return accumPK

    async def submitAccumSecret(self, claimDefId: ID,
                                accumSK: AccumulatorSecretKey):
        await self._cacheValueForId(self._accumSks, claimDefId, accumSK)

    async def submitAccumUpdate(self, claimDefId: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        await self._repo.submitAccumUpdate(claimDefId, accum, timestampMs)
        await self._cacheValueForId(self._accums, claimDefId, accum)

    async def submitContextAttr(self, claimDefId: ID, m2):
        await self._cacheValueForId(self._m2s, claimDefId, m2)

    # GET

    async def getSecretKey(self, claimDefId: ID) -> SecretKey:
        return await self._getValueForId(self._sks, claimDefId)

    async def getSecretKeyRevocation(self,
                                     claimDefId: ID) -> RevocationSecretKey:
        return await self._getValueForId(self._skRs, claimDefId)

    async def getSecretKeyAccumulator(self,
                                      claimDefId: ID) -> AccumulatorSecretKey:
        return await self._getValueForId(self._accumSks, claimDefId)

    async def getContextAttr(self, claimDefId: ID):
        return await self._getValueForId(self._m2s, claimDefId)
