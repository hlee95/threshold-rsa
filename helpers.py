import random
import gmpy2
from gmpy2 import mpz
import numpy as np
import cPickle
import math
import copy
import sys

########################
# General Math Helpers
########################

'''
Returns a random prime number in the range [start, end)
'''

primes = cPickle.load(open("picklePrimesSmall.pkl","r"))

def get_random_prime(start,end):
    i = random.randint(start,end) # better random nunber generator
    while not gmpy2.is_prime(i):
        i +=1
    return i

def get_random_safe_prime(start,end):
    i = random.randint(start,end) # better random nunber generator
    while not (gmpy2.is_prime(i) and gmpy2.is_prime(gmpy2.t_div((i-1),2))):
        i +=1
    return i

# returns all primes in (a,b]
# only works up to 1,000,000,000
def get_primes_in_range(a,b):
    start = np.searchsorted(primes, a)+1
    end = np.searchsorted(primes, b)+1
    return primes[start:end].tolist()

# returns a number between 1 and n that is relatively prime to n
def get_relatively_prime_int(n):
    guess = get_random_int(n)
    while GCD(guess,n)!=1:
        guess = get_random_int(n)
    return guess

def get_relatively_prime_int_small(n):
    n_prime = gmpy2.isqrt(n)
    guess = get_random_int(n_prime)
    while GCD(guess, n) != 1:
        guess = get_random_int(n_prime)
    return guess

def GCD(a, b):
    return gmpy2.gcd(gmpy2.mpz(a), gmpy2.mpz(b))


def getShares(p,n,M):
    base = p/n
    shares = [0]*n
    for i in range(n-1):
        shares[i]= random.randint(3,2**1023)
    rest = sum(shares)%M
    shares[-1] = p-rest
    return shares
        

'''
Returns a random integer between 0 and n-1.
'''
def get_random_int(n):
    i = random.randint(0,2**30) # better random nunber generator
    return gmpy2.mpz_random(gmpy2.random_state(i), n)

'''
Returns (x^y) mod m
'''
def powmod(x, y, m):
    return gmpy2.powmod(gmpy2.mpz(x), gmpy2.mpz(y), gmpy2.mpz(m))

'''
Returns (x*y) mod m
'''
def mulmod(x, y, m):
    return mod(multiply(x, y), m)

'''
Multiply x * y
'''
def multiply(x, y):
    return gmpy2.mul(gmpy2.mpz(x), gmpy2.mpz(y))

'''
Add x + y
'''
def add(x, y):
    return gmpy2.add(gmpy2.mpz(x), gmpy2.mpz(y))

'''
Divide x / y
'''
def divide(x, y):
    return gmpy2.t_div(gmpy2.mpz(x), gmpy2.mpz(y))

def floor_divide(x, y):
    return gmpy2.f_div(gmpy2.mpz(x), gmpy2.mpz(y))

'''
Subtract x - y
'''
def subtract(x, y):
    return gmpy2.sub(gmpy2.mpz(x), gmpy2.mpz(y))


'''
Calcaulte x mod m
'''
def mod(x, m):
    remainder = gmpy2.t_mod(gmpy2.mpz(x), gmpy2.mpz(m))
    # gmpy2.t_mod can return negative values, but we want positive ones.
    if remainder < 0:
        remainder = gmpy2.add(remainder, m)
    return remainder

#[d_1, d_2...d_n] such that sum [] = d mod N
def sum_genereator(d, n, N):
    d_i = []
    #choose random values for first n-1
    for i in range(n-1):
        d_i.append(get_random_int(N))

    #last one must make sum to d
    d_i.append(mod(subtract(d,1*reduce(add,d_i)), N))
    assert mod(reduce(add, d_i), N) == mod(d,N)
    return d_i

#########################################
# Subset Presigning Algorithm Helpers
#########################################

'''
Helper class (basically a struct) that stores the data that
a computer needs for the subset presigning algorithm.
'''
class PresigningData:
    def __init__(self):
        # All variables are named as they are in the paper pages 26 - 27.
        self.lamdba_t_i = None
        self.s_t_i = None
        self.h_t_i = None
        self.received_h_t_i = {} # maps id -> h_t_i for all k computers

        self.sigma_I_t_i = None # signature on the dummy message
        self.x_I = None
        self.received_x_I = [] # contains tuples with (id, x_I) computed by other parties, length of array = k-1

        self.D_I = None # will contain tuples of the form (x_I, [(id, h_t_i, c_prime_t_i)])
        self.S_I_t_i = None # will contain simply s_t_i


#########################################
# Helpers for Generating N
#########################################

'''
Helper class for BGW Protocol data.
'''
class BGWData:
    def __init__(self, M, p_i, q_i, l):
        # All variables are as described in Section 4.3, pg 14-15
        self.M = M
        self.l = l
        self.p_i = p_i
        self.q_i = q_i

        self.l = l # l = floor((n-1)/2) where n is the number of computers
        self.a = [] # array of l random coefficients
        self.b = [] # array of l random coefficients
        self.c = [] # array of 2l random coefficients

        self.f_i_j = {} # maps j -> f_i(j) where i is this computer
        self.g_i_j = {}
        self.h_i_j = {}

        self.received_fgh = [] # array that stores the (f_i(j), g_i(j), h_i(j)) from every computer i, where j is this computer
        self.n_j = None # the final share calculated

'''
Helper class (basically a struct) that stores the data that
a computer needs for Distributed Sieving section 5.2.1 in the paper.
'''
class PQData:
    def __init__(self, _round, M, l):
        # All variables are named as they are in the paper pages 17-18
        self.round = _round # the round we are on, should start at 1
        self.M = M # M = product of all prime numbers between n and B1
        self.l = l # l = floor((n-1)/2)
        self.a_i = None # random secret integer relatively prime to self.M
        self.u = [] # 2d array where u[i][j] is u_{i,j} in the notation of the paper
        self.v = [] # 2d array where v[i][j] is v_{i,j} in the notation of the paper
        self.a = None # cummulative product of the a_i as we iterate through the protocol






