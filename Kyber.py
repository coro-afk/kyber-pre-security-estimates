from math import log
from Kyber_failure import p2_cyclotomic_error_probability
from MLWE_security import MLWE_summarize_attacks, MLWEParameterSet
from proba_util import build_mod_switching_error_law

class KyberParameterSet:
    def __init__(self, n, q, k, eta1, eta2, du, dv):
        self.n = n
        self.q = q
        self.k = k
        self.eta1 = eta1     # binary distribution for the secret key (s, e, r and e1)
        self.eta2 = eta2    # binary distribution for the ciphertext errors (e2)
        self.du = du    # 2^(bits in the first ciphertext)
        self.dv = dv    # 2^(bits in the second ciphertext)


def Kyber_to_MLWE(kps):
    # if kps.eta1 != kps.eta2:
    #     raise "The security script does not handle different error parameter in secrets and errors (eta1 != eta2) "

    # Check whether ciphertext error variance after rounding is larger than secret key error variance
    Rc = build_mod_switching_error_law(kps.q, 2**kps.du)
    var_rounding = sum([i*i*Rc[i] for i in Rc.keys()])

    # if kps.eta2/2. + var_rounding < kps.eta2/2.:
    #     raise "The security of the ciphertext MLWE may not be stronger than the one of the public key MLWE"    

    return MLWEParameterSet(kps.n, kps.k, kps.k + 1, kps.eta1, kps.q)


def communication_costs(ps):
    """ Compute the communication cost of a parameter set
    :param ps: Parameter set (ParameterSet)
    :returns: (cost_Alice, cost_Bob) (in Bytes)
    """
    A_space = 256 + ps.n * ps.k * ps.du
    B_space = ps.n * ps.k * ps.du + ps.n * ps.dv
    return (int(round(A_space))/8., int(round(B_space))/8.)


def summarize(ps):
    print ("params: ", ps.__dict__)
    print ("com costs: ", communication_costs(ps))
    F, f = p2_cyclotomic_error_probability(ps)
    print ("failure: %.1f = 2^%.1f"%(f, log(f + 2.**(-300))/log(2)))


if __name__ == "__main__":
    # Parameter sets
    ps_light = KyberParameterSet(256, 3329, 2, 3, 2, 10, 4)
    ps_recommended = KyberParameterSet(256, 3329, 3, 2, 2, 10, 4)
    ps_paranoid = KyberParameterSet(256, 3329, 4, 2, 2, 11, 5)

    # Analyses
    print ("Kyber512 (light):")
    print ("--------------------")
    print ("security:")
    MLWE_summarize_attacks(Kyber_to_MLWE(ps_light))
    summarize(ps_light)
    print ()

    print ("Kyber768 (recommended):")
    print ("--------------------")
    print ("security:")
    MLWE_summarize_attacks(Kyber_to_MLWE(ps_recommended))
    summarize(ps_recommended)
    print ()

    print ("Kyber1024 (paranoid):")
    print ("--------------------")
    print ("security:")
    MLWE_summarize_attacks(Kyber_to_MLWE(ps_paranoid))
    summarize(ps_paranoid)
    print ()
