from abc import abstractmethod

from anoncreds.protocol.repo.public_repo import PublicRepo
from anoncreds.protocol.types import ClaimDefinition, PublicKey, SecretKey, ID, \
    RevocationPublicKey, AccumulatorPublicKey, Accumulator, TailsType, RevocationSecretKey, AccumulatorSecretKey, \
    TimestampType
from anoncreds.protocol.wallet.wallet import Wallet, WalletInMemory


class IssuerWallet(Wallet):
    def __init__(self, id, repo: PublicRepo):
        Wallet.__init__(self, id, repo)

    # SUBMIT

    @abstractmethod
    def submitClaimDef(self, claimDef: ClaimDefinition) -> ClaimDefinition:
        raise NotImplementedError

    @abstractmethod
    def submitPublicKeys(self, id: ID, pk: PublicKey, pkR: RevocationPublicKey = None):
        raise NotImplementedError

    @abstractmethod
    def submitSecretKeys(self, id: ID, sk: SecretKey, skR: RevocationSecretKey = None):
        raise NotImplementedError

    @abstractmethod
    def submitAccumPublic(self, id: ID, accumPK: AccumulatorPublicKey, accum: Accumulator, tails: TailsType):
        raise NotImplementedError

    @abstractmethod
    def submitAccumSecret(self, id: ID, accumSK: AccumulatorSecretKey):
        raise NotImplementedError

    @abstractmethod
    def submitAccumUpdate(self, id: ID, accum: Accumulator, timestampMs: TimestampType):
        raise NotImplementedError

    @abstractmethod
    def submitContextAttr(self, id: ID, m2):
        raise NotImplementedError

    # GET

    @abstractmethod
    def getSecretKey(self, id: ID) -> SecretKey:
        raise NotImplementedError

    @abstractmethod
    def getSecretKeyRevocation(self, id: ID) -> RevocationSecretKey:
        raise NotImplementedError

    @abstractmethod
    def getSecretKeyAccumulator(self, id: ID) -> AccumulatorSecretKey:
        raise NotImplementedError

    @abstractmethod
    def getContextAttr(self, id: ID):
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

    def submitClaimDef(self, claimDef: ClaimDefinition) -> ClaimDefinition:
        claimDef = self._repo.submitClaimDef(claimDef)
        self._cacheClaimDef(claimDef)
        return claimDef

    def submitPublicKeys(self, id: ID, pk: PublicKey, pkR: RevocationPublicKey = None):
        self._repo.submitPublicKeys(id, pk, pkR)
        self._cacheValueForId(self._pks, id, pk)
        if pkR:
            self._cacheValueForId(self._pkRs, id, pkR)

    def submitSecretKeys(self, id: ID, sk: SecretKey, skR: RevocationSecretKey = None):
        self._cacheValueForId(self._sks, id, sk)
        if skR:
            self._cacheValueForId(self._skRs, id, skR)

    def submitAccumPublic(self, id: ID, accumPK: AccumulatorPublicKey, accum: Accumulator, tails: TailsType):
        self._repo.submitAccumulator(id, accumPK, accum, tails)
        self._cacheValueForId(self._accums, id, accum)
        self._cacheValueForId(self._accumPks, id, accumPK)
        self._cacheValueForId(self._tails, id, tails)

    def submitAccumSecret(self, id: ID, accumSK: AccumulatorSecretKey):
        self._cacheValueForId(self._accumSks, id, accumSK)

    def submitAccumUpdate(self, id: ID, accum: Accumulator, timestampMs: TimestampType):
        self._repo.submitAccumUpdate(id, accum, timestampMs)
        self._cacheValueForId(self._accums, id, accum)

    def submitContextAttr(self, id: ID, m2):
        self._cacheValueForId(self._m2s, id, m2)

    # GET

    def getSecretKey(self, id: ID) -> SecretKey:
        return self._getValueForId(self._sks, id)

    def getSecretKeyRevocation(self, id: ID) -> RevocationSecretKey:
        return self._getValueForId(self._skRs, id)

    def getSecretKeyAccumulator(self, id: ID) -> AccumulatorSecretKey:
        return self._getValueForId(self._accumSks, id)

    def getContextAttr(self, id: ID):
        return self._getValueForId(self._m2s, id)
