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
    
    # Rounding error of first ciphertext u (cu)
    rerror_u = build_mod_switching_error_law(ps.q, 2**ps.du)
    
    # Rounding error of second ciphertext v (cv)
    rerror_v = build_mod_switching_error_law(ps.q, 2**ps.dv)
    
    # LWE + Rounding error key (e1 + cu)
    chi_eta2_rerror_u = law_convolution(chi_eta2, rerror_u)
    
    # (LWE+Rounding error) * LWE ((e1 + cu)^t * s and r^t * e)
    B1 = law_product(chi_eta2_rerror_u, chi_eta1)
    B2 = law_product(chi_eta1, chi_eta1)
    
    # Iterative convolution for B1 and B2
    C1 = iter_law_convolution(B1, ps.k * ps.n)
    C2 = iter_law_convolution(B2, ps.k * ps.n)
    
    # Convolute them together 
    # C1 + C2 + cv: 
    # (e1 + cu)^t * s + (r^t * e) + cv
    # This is Kyber's total noise minus e2
    C = law_convolution(C1, C2)
    D = law_convolution(C, rerror_v) 
    
    # Double it
    E = law_convolution(D, D)
    
    # Add the noise e2
    F = law_convolution(E, chi_eta2)
    
    # Additional error due to mod switching of re-key
    if ps.drv != 12:
        rerror_rv = build_mod_switching_error_law(ps.q, 2**ps.drv)
        F = law_convolution(F, rerror_rv)
    return F

def p2_cyclotomic_error_probability(ps):
    F = p2_cyclotomic_final_error_distribution(ps)
    proba = tail_probability(F, ps.q/4)
    return F, ps.n * proba