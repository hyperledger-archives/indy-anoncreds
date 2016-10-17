from anoncreds.protocol.cred_def_secret_key import CredDefSecretKey
from anoncreds.protocol.credential_definition import CredentialDefinition
from anoncreds.protocol.issuer_key import IssuerKey
from anoncreds.protocol.utils import randomQR
from anoncreds.protocol.utils import strToCryptoInteger


class IssuerSecretKey:
    """
    Private key an issuer creates and protects.
    """
    def __init__(self,
                 cd: CredentialDefinition,
                 sk: CredDefSecretKey=None,
                 uid=None,
                 pubkey: IssuerKey=None):
        self.cd = cd
        self.sk = sk if sk else CredDefSecretKey()
        if pubkey:
            self.pubkey = pubkey
        else:
            self._genPubkey(uid)

    def _genPubkey(self, uid):
        # Generate a random quadratic number
        S = randomQR(self.sk.n)

        # Generate `Z` as the exponentiation of the quadratic random 'S' .
        # over the random `Xz` in the group defined by modulus `n`
        Z = S ** self.sk.genX()

        # Generate random numbers corresponding to every attributes
        R = {}
        for name in self.cd.attrNames:
            R[str(name)] = S ** self.sk.genX()
        # R["0"] is a random number needed corresponding to master secret
        R["0"] = S ** self.sk.genX()
        self.pubkey = IssuerKey(uid, N=self.sk.n, R=R, S=S, Z=Z)

    @property
    def PK(self) -> IssuerKey:
        return self.pubkey

    @classmethod
    def getCryptoInteger(cls, val):
        return strToCryptoInteger(val)
