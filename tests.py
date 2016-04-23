#!/usr/bin/python
from thresholdRSA import *

##############################################################
# Testing Area

# Basically I just print stuff out to see that it makes sense.
# To run tests, just do ./tests.py in the working directory.
##############################################################

# Just observe the output and make sure it's right.
# (Expect to fail, then [0, 1, 2, 5], then fail, then [0, 1, 2, 6], then fail.)
def hanna_subset_presigning_test():
    print "---------------------------------------"
    print "SUBSET PRESIGNING TEST"
    print "---------------------------------------"
    network = Network(range(4, 7))
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

def run_all_tests():
    hanna_subset_presigning_test()

    print "---------------------------------------"
    print "DONE WITH TESTS"
    print "---------------------------------------"

# Run everything!
run_all_tests()


