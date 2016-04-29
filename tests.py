#!/usr/bin/python
from thresholdRSA import *

##############################################################
# Testing Area

# Basically I just print stuff out to see that it makes sense.
# To run tests, just do ./tests.py in the working directory.
##############################################################


def brian_dealing_tests():
    network = Network()
    network.setup()
    M = get_random_prime(N+1,2*N)
    print network.dealing_algorithm()


# works with hard coded N must be changed in code
# as in the function should not normally take an N so it has to be changed
# should get in in sync with the rest so it checks the generated N
def brian_parallel_trial_division():
    network = Network()
    #network.setup()
    N = 32771*32779*32868
    print "should be false"
    print network.parallel_trial_division(N)
    N = 1000000007
    print "should be true"
    print network.parallel_trial_division(N)
#brian_parallel_trial_division()

def brian_primality_test():
    network = Network()
    network.setup()
    print "should be false"
    print network.load_balance_primality_test()
    print "should be true"
    print network.load_balance_primality_test()
#brian_primality_test()
    


# Just observe the output and make sure it's right.
# (Expect to fail, then [0, 1, 2, 5], then fail, then [0, 1, 2, 6], then fail.)
def hanna_subset_presigning_test():
    print "---------------------------------------"
    print "SUBSET PRESIGNING TEST"
    print "---------------------------------------"
    network = Network(range(4, 7))
    network.setup()
    print "Try with 3 people."
    network.sign(100)
    print "\nTry with 4 people."
    network.nodes[2].change_choice(True)
    network.sign(200)
    print "\nTry with same 4 people."
    network.nodes[8].change_choice(True)
    network.sign(300)
    print "\nRemove one person."
    network.nodes[5].change_choice(False)
    network.sign(400)
    print "\nAdd back in the removed person."
    network.nodes[5].change_choice(True)
    network.sign(500)

def hanna_bgw_test():
    network = Network([])
    p = [0, 3, 0, 0, 0]
    q = [0, 1, 0, 0, 0]
    real_N = sum(p) * sum(q)
    print "real_N: ", real_N
    M = 521
    print "M: ", M
    for i in xrange(5):
        network.nodes[i].one_round_BGW_phase_0(M, p[i], q[i], 2)
    for computer in network.nodes:
        computer.one_round_BGW_phase_1()
    for computer in network.nodes:
        computer.one_round_BGW_phase_2()

    test_N = 0
    for computer in network.nodes:
        test_N += computer.bgw.n_j
        print "n_j: ", computer.bgw.n_j
    test_N = mod(test_N, M)
    print "test_N: ", test_N
    print test_N == real_N


def hao_signing_test():
    print "---------------------------------------"
    print "SIGNING TEST"
    print "---------------------------------------"
    network = Network(range(4, 7))
    network.setup()
    network.dealing_algorithm()

    print "Try with 3 people."
    network.sign(100)
    print "\nTry with 4 people."
    network.nodes[2].change_choice(True)
    network.sign(200)
    print "\nTry with same 4 people."
    network.nodes[8].change_choice(True)
    network.sign(300)
    print "\nRemove one person."
    network.nodes[5].change_choice(False)
    network.sign(400)
    print "\nAdd back in the removed person."
    network.nodes[5].change_choice(True)
    network.sign(500)

    print "\n signature share generation"
    network.nodes[2].signature_share_generation(13223)
    print "\n signature share generation"
    network.nodes[5].signature_share_generation(523508)


def hao_key_generation_test():
    print "---------------------------------------"
    print "SUBSET PRESIGNING TEST"
    print "---------------------------------------"
    network = Network(range(4, 7))
    network.private_key_generation()


def run_all_tests():
    #hanna_subset_presigning_test()
    hanna_bgw_test()
    #hao_signing_test()
    #brian_dealing_tests()
    #hao_key_generation_test()
    print "---------------------------------------"
    print "DONE WITH TESTS"
    print "---------------------------------------"

# Run everything!
run_all_tests()


