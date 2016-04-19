import random
import gmpy2

'''
Returns a random prime number in the range [start, end)
'''
def get_random_prime(start,end):
    i = random.randint(start,end) # better random nunber generator
    while not gmpy2.is_prime(i):
        i +=1
    return i

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
        self.received_h_t_i = [] # contains tuples with the (id, h_t_i) of all k computers

        self.sigma_I_t_i = None # signature on the dummy message
        self.received_sigma_I_t_i = [] # contains tuples with the (id, sigma_I_t_i) of all k computers
        self.x_I = None
        self.received_x_I = [] # contains tuples with (id, x_I) computed by other parties, length of array = k-1

        self.D_I = None # will contain tuples of the form (x_I, [(id, h_t_i, c_prime_t_i)])
        self.S_I_t_i = None # will contain simply s_t_i


