import operator as op
from math import factorial as fac
from math import sqrt, log
import sys
from proba_util import *

def p2_cyclotomic_final_error_distribution(ps):
    """ construct the final error distribution in our encryption scheme
    :param ps: parameter set (ParameterSet)
    """
    # LWE error law for the key (s, e, r)
    chi_eta1 = build_centered_binomial_law(ps.eta1)
    
    # LWE error law for the first ciphertext (e1, e2)
    chi_eta2 = build_centered_binomial_law(ps.eta2)
    
    # Rounding error of first ciphertext u (e'')
    rerror_u = build_mod_switching_error_law(ps.q, 2**ps.du)
    
    # Rounding error of second ciphertext v (e')
    rerror_v = build_mod_switching_error_law(ps.q, 2**ps.dv)
    
    # LWE + Rounding error key (e_1 + e'')
    chi_eta2_rerror_u = law_convolution(chi_eta2, rerror_u)
    
    # LWE + rounding error ciphertext (e_2 + e')
    chi_eta2_rerror_v = law_convolution(chi_eta2, rerror_v)
    
    # (LWE+Rounding error) * LWE ((e_1 + e'')^t * s and r^t * e)
    B1 = law_product(chi_eta2_rerror_u, chi_eta1)
    B2 = law_product(chi_eta1, chi_eta1)
    
    # Iterative convolution for B1 and B2
    C1 = iter_law_convolution(B1, ps.k * ps.n)
    C2 = iter_law_convolution(B2, ps.k * ps.n)
    
    # Convolute them together 
    # (C1 + C2 + chi_eta2_rerror_v): 
    # ((e_1 + e'')^t * s + (r^t * e) + (e_2 + e'))
    C = law_convolution(C1, C2)
    D = law_convolution(C, chi_eta2_rerror_v)  # Final error
    return D

def p2_cyclotomic_error_probability(ps):
    F = p2_cyclotomic_final_error_distribution(ps)
    proba = tail_probability(F, ps.q/4)
    return F, ps.n * proba