from anoncreds.protocol.globals import ITERATIONS, DELTA


def calcTeq(pk, Aprime, e, v, mtilde, m1Tilde, m2Tilde, unrevealedAttrNames):
    Rur = 1 % pk.N
    for k in unrevealedAttrNames:
        Rur = Rur * (pk.R[k] ** mtilde[k])
    Rur *= pk.Rms ** m1Tilde
    Rur *= pk.Rctxt ** m2Tilde
    return ((Aprime ** e) * Rur * (pk.S ** v)) % pk.N


def calcTge(pk, u, r, mj, alpha, T):
    TauList = []
    for i in range(0, ITERATIONS):
        Ttau = (pk.Z ** u[str(i)]) * (pk.S ** r[str(i)]) % pk.N
        TauList.append(Ttau)
    Ttau = (pk.Z ** mj) * (pk.S ** r[DELTA]) % pk.N
    TauList.append(Ttau)

    # gen Q
    Q = 1 % pk.N
    for i in range(0, ITERATIONS):
        Q *= T[str(i)] ** u[str(i)]
    Q = Q * (pk.S ** alpha) % pk.N
    TauList.append(Q)

    return TauList
