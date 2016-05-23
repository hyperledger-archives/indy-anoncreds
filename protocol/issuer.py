from charm.core.math.integer import randomPrime, random, integer, randomBits, \
    isPrime
from protocol.globals import lprime, lvprimeprime, lestart, leendrange
from protocol.utils import randomQR, get_prime_in_range


class Issuer:
    def __init__(self, l):
        """
        Setup an issuer
        :param l: Number of attributes
        """
        self.p_prime = randomPrime(lprime)
        i = 0
        self.p_prime = integer(159761332860793652411271405738308323756309713571403964461727715088033341338954731575356408309672708510757243427026208884771840662897596091036761172657600918605317337919395271708095954898038033824239974330904445666409061983023701006244359488882052232525171291402032732043484991159690394490671353749090075503499)
        # TODO: Uncomment later after issue is fixed
        # while not isPrime(2 * self.p_prime + 1):
        #     self.p_prime = randomPrime(lprime)
        #     i += 1
        # print("Found prime in {} iteration".format(i))
        self.p = 2 * self.p_prime + 1

        self.q_prime = randomPrime(lprime)
        i = 0
        self.q_prime = integer(147941103885244984950922922580175537666860848468148610466834447282510085234067042630955504787368386886952154418980749829011289975605537475630591764256906718678887431749854811959005260218523276788687932977927794009742733812725985244889425877026238637746152871531210399229194025997481521534648478308545514605813)
        # TODO: Uncomment later after issue is fixed
        # while not isPrime(2 * self.q_prime + 1):
        #     self.q_prime = randomPrime(lprime)
        #     i += 1
        # print("Found prime in {} iteration".format(i))
        self.q = 2 * self.q_prime + 1

        n = self.p * self.q

        S = randomQR(n)

        Xz = integer(random(n))
        Xr = {}

        for i in range(1, l+1):
            Xr[str(i)] = integer(random(n))

        Z = (S ** Xz) % n

        R = {}
        for i in range(1, l+1):
            R[str(i)] = S ** Xr[str(i)]
        R["0"] = S ** integer(random(n))

        self._pk = {'N': n, 'S': S, 'Z': Z, 'R': R}
        self.sk = {'p': self.p, 'q': self.q}

    @property
    def PK(self):
        """
        Generate key pair for the issuer
        :return: Tuple of public-secret key for the issuer
        """
        return self._pk

    def issue(self, u, attrs):
        # Set the Most-significant-bit to 1
        vprimeprime = integer(randomBits(lvprimeprime) |
                              (2 ** (lvprimeprime - 1)))

        estart = 2 ** lestart
        eend = (estart + 2 ** leendrange)

        e = get_prime_in_range(estart, eend)

        sig = self._sign(self._pk, attrs, vprimeprime, u, e)
        return sig["A"], e, vprimeprime

    def _sign(self, pk, attr, v=0, u=0, e=0):
        R = pk["R"]
        Z = pk["Z"]
        S = pk["S"]
        N = pk["N"]
        Rx = 1 % N

        i = 1
        for k, v in attr.items():
            Rx = Rx * (R[str(i)] ** attr[str(k)])
            i += 1

        if u != 0:
            u = u % N
            Rx *= u

        nprime = self.p_prime * self.q_prime
        e1 = e % nprime

        Q = Z / (Rx * (S ** v)) % N
        A = Q ** (e1 ** -1) % N  # This part is unclear. Revisit it

        return {'A': A, 'Q': Q, 'e': e, 'v': v}
