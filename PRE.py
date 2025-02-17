from math import log
import matplotlib.pyplot as plt
from PRE_failure import p2_cyclotomic_error_probability
from MLWE_security import MLWE_summarize_attacks, MLWEParameterSet
from proba_util import build_mod_switching_error_law

class KyberParameterSet:
    def __init__(self, n, q, k, eta1, eta2, du, dv, drv=12):
        self.n = n
        self.q = q
        self.k = k
        self.eta1 = eta1     # binary distribution for the secret key (s, e, r and e1)
        self.eta2 = eta2    # binary distribution for the ciphertext errors (e2)
        self.du = du    # 2^(bits in the first ciphertext)
        self.dv = dv    # 2^(bits in the second ciphertext)
        self.drv = drv  # compression factor for the second re-key

def communication_costs(ps):
    """ Compute the communication cost of a parameter set
    :param ps: Parameter set (ParameterSet)
    :returns: costs in bytes (dict)
    """
    result = {}
    com_sk = 12 * ps.k * ps.n / 8  # 12 bytes per element (Encode_12)
    result["com_pk"] = 12 * ps.k * ps.n / 8 + 32
    result["com_ct"] = ps.du * ps.k * ps.n / 8 + ps.dv * ps.n / 8
    result["com_rk"] = ps.du * ps.k * ps.n / 8 + ps.drv * ps.n / 8
    return result

def summarize(ps):
    print(f"params: {ps.__dict__}")
    com_costs = communication_costs(ps)
    print(f"com costs: {com_costs}")
    F, f = p2_cyclotomic_error_probability(ps)
    failure_log2 = log(f + 2.**(-300)) / log(2)
    print(f"failure: {f:.1f} = 2^{failure_log2:.1f}")

def plot_failure_rates(drv_values, failure_rates_dict, filename):
    plt.figure()
    for label, failure_rates in failure_rates_dict.items():
        plt.plot(drv_values, failure_rates, marker='o', label=label)
    plt.xlabel('drv')
    plt.ylabel('Failure Rate (log2)')
    plt.title('Failure Rate vs drv for Different Parameter Sets')
    plt.legend()
    plt.grid(True)
    plt.savefig(filename, format='pdf')  # 保存为PDF格式
    plt.show()

def plot_rk_lengths(drv_values, rk_lengths_dict, filename):
    plt.figure()
    for label, rk_lengths in rk_lengths_dict.items():
        plt.plot(drv_values, rk_lengths, marker='o', label=label)
    plt.xlabel('drv')
    plt.ylabel('Re-key Length (bytes)')
    plt.title('Re-key Length vs drv for Different Parameter Sets')
    plt.legend()
    plt.grid(True)
    plt.savefig(filename, format='pdf')  # 保存为PDF格式
    plt.show()

if __name__ == "__main__":    
    drv_values = list(range(4, 13))
    failure_rates_dict = {}
    rk_lengths_dict = {}

    # For PRE512 and PRE768
    for i in range(2, 4):
        level = 'light' if i == 2 else 'recommended'
        s = 512 if i == 2 else 768
        failure_rates = []
        rk_lengths = []
        print(f"Testing {level} ({s} bits) with varying drv:")
        print(f"{'drv':<5} {'failure':<20} {'rk length (bytes)':<20}")
        print("-" * 50)
        for j in drv_values:
            k = 3 if i == 2 else 2
            ps = KyberParameterSet(256, 3329, i, k, 2, 10, 4, j)
            F, f = p2_cyclotomic_error_probability(ps)
            failure_log2 = log(f + 2.**(-300)) / log(2)
            com_costs = communication_costs(ps)
            rk_length = com_costs["com_rk"]
            failure_rates.append(failure_log2)
            rk_lengths.append(rk_length)
            print(f"{j:<5} {f:.1f} = 2^{failure_log2:.1f} {rk_length:<20}")
        print()
        failure_rates_dict[f"cdPRE{s}"] = failure_rates
        rk_lengths_dict[f"cdPRE{s}"] = rk_lengths

    # For PRE1024
    failure_rates = []
    rk_lengths = []
    print("Testing paranoid (1024 bits) with varying drv:")
    print(f"{'drv':<5} {'failure':<20} {'rk length (bytes)':<20}")
    print("-" * 50)
    for j in drv_values:
        ps = KyberParameterSet(256, 3329, 4, 2, 2, 11, 5, j)
        F, f = p2_cyclotomic_error_probability(ps)
        failure_log2 = log(f + 2.**(-300)) / log(2)
        com_costs = communication_costs(ps)
        rk_length = com_costs["com_rk"]
        failure_rates.append(failure_log2)
        rk_lengths.append(rk_length)
        print(f"{j:<5} {f:.1f} = 2^{failure_log2:.1f} {rk_length:<20}")
    print()
    failure_rates_dict["cdPRE1024"] = failure_rates
    rk_lengths_dict["cdPRE1024"] = rk_lengths

    # Plot all failure rates on the same graph
    plot_failure_rates(drv_values, failure_rates_dict, 'failure_rates.pdf')

    # Plot all rk lengths on the same graph
    plot_rk_lengths(drv_values, rk_lengths_dict, 'rk_lengths.pdf')