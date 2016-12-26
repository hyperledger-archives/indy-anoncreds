from abc import abstractmethod

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import ClaimDefinition, PublicKey, SecretKey, ID, \
    RevocationPublicKey, AccumulatorPublicKey, Accumulator, TailsType, \
    RevocationSecretKey, AccumulatorSecretKey, \
    TimestampType
from anoncreds.protocol.wallet.wallet import Wallet, WalletInMemory


class IssuerWallet(Wallet):
    def __init__(self, id, repo: PublicRepo):
        Wallet.__init__(self, id, repo)

    # SUBMIT

    @abstractmethod
    async def submitClaimDef(self,
                             claimDef: ClaimDefinition) -> ClaimDefinition:
        raise NotImplementedError

    @abstractmethod
    async def submitPublicKeys(self, id: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        raise NotImplementedError

    @abstractmethod
    async def submitSecretKeys(self, id: ID, sk: SecretKey,
                               skR: RevocationSecretKey = None):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumPublic(self, id: ID, accumPK: AccumulatorPublicKey,
                                accum: Accumulator, tails: TailsType):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumSecret(self, id: ID, accumSK: AccumulatorSecretKey):
        raise NotImplementedError

    @abstractmethod
    async def submitAccumUpdate(self, id: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        raise NotImplementedError

    @abstractmethod
    async def submitContextAttr(self, id: ID, m2):
        raise NotImplementedError

    # GET

    @abstractmethod
    async def getSecretKey(self, id: ID) -> SecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getSecretKeyRevocation(self, id: ID) -> RevocationSecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getSecretKeyAccumulator(self, id: ID) -> AccumulatorSecretKey:
        raise NotImplementedError

    @abstractmethod
    async def getContextAttr(self, id: ID):
        raise NotImplementedError


class IssuerWalletInMemory(IssuerWallet, WalletInMemory):
    def __init__(self, id, repo: PublicRepo):
        WalletInMemory.__init__(self, id, repo)

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

    async def submitPublicKeys(self, id: ID, pk: PublicKey,
                               pkR: RevocationPublicKey = None) -> (
            PublicKey, RevocationPublicKey):
        pk, pkR = await self._repo.submitPublicKeys(id, pk, pkR)
        await self._cacheValueForId(self._pks, id, pk)
        if pkR:
            await  self._cacheValueForId(self._pkRs, id, pkR)
        return (pk, pkR)

    async def submitSecretKeys(self, id: ID, sk: SecretKey,
                               skR: RevocationSecretKey = None):
        await  self._cacheValueForId(self._sks, id, sk)
        if skR:
            await  self._cacheValueForId(self._skRs, id, skR)

    async def submitAccumPublic(self, id: ID, accumPK: AccumulatorPublicKey,
                                accum: Accumulator,
                                tails: TailsType) -> AccumulatorPublicKey:
        accumPK = await self._repo.submitAccumulator(id, accumPK, accum, tails)
        await self._cacheValueForId(self._accums, id, accum)
        await self._cacheValueForId(self._accumPks, id, accumPK)
        await self._cacheValueForId(self._tails, id, tails)
        return accumPK

    async def submitAccumSecret(self, id: ID, accumSK: AccumulatorSecretKey):
        await self._cacheValueForId(self._accumSks, id, accumSK)

    async def submitAccumUpdate(self, id: ID, accum: Accumulator,
                                timestampMs: TimestampType):
        await self._repo.submitAccumUpdate(id, accum, timestampMs)
        await self._cacheValueForId(self._accums, id, accum)

    async def submitContextAttr(self, id: ID, m2):
        await self._cacheValueForId(self._m2s, id, m2)

    # GET

    async def getSecretKey(self, id: ID) -> SecretKey:
        return await self._getValueForId(self._sks, id)

    async def getSecretKeyRevocation(self, id: ID) -> RevocationSecretKey:
        return await self._getValueForId(self._skRs, id)

    async def getSecretKeyAccumulator(self, id: ID) -> AccumulatorSecretKey:
        return await self._getValueForId(self._accumSks, id)

    async def getContextAttr(self, id: ID):
        return await self._getValueForId(self._m2s, id)
