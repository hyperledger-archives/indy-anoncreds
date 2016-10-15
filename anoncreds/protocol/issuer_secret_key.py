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
                 uid=None):
        self.cd = cd
        self.sk = sk if sk else CredDefSecretKey()
        self.uid = uid

        # Generate a random quadratic number
        self.S = randomQR(self.sk.n)

        # Generate random numbers corresponding to every attributes
        Xz = self.sk.genX()
        Xr = {}

        for name in cd.attrNames:
            Xr[str(name)] = self.sk.genX()

        # Generate `Z` as the exponentiation of the quadratic random 'S' .
        # over the random `Xz` in the group defined by modulus `n`
        self.Z = (self.S ** Xz) % self.sk.n

        # Generate random numbers corresponding to every attributes
        self.R = {}
        for name in cd.attrNames:
            self.R[str(name)] = (self.S ** Xr[str(name)]) % self.sk.n
        # R["0"] is a random number needed corresponding to master secret
        self.R["0"] = (self.S ** self.sk.genX()) % self.sk.n

    @property
    def PK(self) -> IssuerKey:
        return IssuerKey(self.uid, N=self.sk.n, R=self.R, S=self.S, Z=self.Z)

    @classmethod
    def getCryptoInteger(cls, val):
        return strToCryptoInteger(val)
