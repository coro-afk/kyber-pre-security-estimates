from math import log
from PRE_failure import p2_cyclotomic_error_probability
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

def communication_costs(ps):
    """ Compute the communication cost of a parameter set
    :param ps: Parameter set (ParameterSet)
    :returns: costs in bytes (dict)
    """
    result = {}
    com_sk = 12 * ps.k * ps.n / 8  # 12 bytes per element (Encode_12)
    result["com_pk"] = 12 * ps.k * ps.n / 8 + 32
    result["com_ct"] = ps.du * ps.k * ps.n / 8 + ps.dv * ps.n / 8
    result["com_rk"] = 12 * ps.k * ps.n / 8 + 12 * ps.n / 8
    return result

def summarize(ps):
    print("params: ", ps.__dict__)
    print("com costs: ", communication_costs(ps))
    F, f = p2_cyclotomic_error_probability(ps)
    print("failure: %.1f = 2^%.1f" % (f, log(f + 2.**(-300)) / log(2)))

if __name__ == "__main__":
    # Parameter sets
    ps_light = KyberParameterSet(256, 3329, 2, 3, 2, 10, 4)
    ps_recommended = KyberParameterSet(256, 3329, 3, 2, 2, 10, 4)
    ps_paranoid = KyberParameterSet(256, 3329, 4, 2, 2, 11, 5)

    # Analyses
    print("PRE512 (light):")
    print("--------------------")
    print("security:")
    summarize(ps_light)
    print()

    print("PRE768 (recommended):")
    print("--------------------")
    print("security:")
    summarize(ps_recommended)
    print()

    print("PRE1024 (paranoid):")
    print("--------------------")
    print("security:")
    summarize(ps_paranoid)
    print()
