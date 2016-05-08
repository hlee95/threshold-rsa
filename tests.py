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
    product_prime_test = False
    counter = 0
    while not product_prime_test:
        if counter %100==0:
            print counter
        counter+=1
        network.generate_N(fake=True)
        M = network.nodes[0].M
        N = mod(network.nodes[0].N,M)
        p = 0
        q = 0
        for computer in network.nodes:
            p=add(p,computer.p_i)
        if not gmpy2.is_prime(p):
            #print "p not prime"
            continue
        for computer in network.nodes:
            q=add(q,computer.q_i)
        if not gmpy2.is_prime(q):
            print "q not prime"
            continue
        if N!=p*q:
            raise RuntimeError(" N!=p*q,M")
        trial = network.parallel_trial_division()
        if trial:
            product_prime_test = network.load_balance_primality_test()
    print "N",N
    print "M",M
    for computer in network.nodes:
        print "p_i",computer.p_i
        print "q_i",computer.q_i
    print "found a good N"
brian_primality_test()



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
    trues = []
    for i in xrange(10):
        #M = get_random_prime(10*1024,10**1025)
        M = 102277922045560377677425330733025540787828481406916984309906917658679563028615294226321554724723272942310661725952704155095478409778315613883726668677544055422016936511783428122218075870314606203578763039546078374498114291572003824750681852245916170997581540628197467671968077726679505726524448218294989785311398744742887714607819190071055856821147699026221351085249350463784780552304793306340277073393234968722571984036002634583
        #print "M: ", M
        p = [86073950554594054572046690813007382342109102384982873842578803184201536538628877943140512481095441062578889315568924246909030737312145088325059810507040947056485625875756370588738118390330828479680886357865404929186692081823717077462607913020535808188545300482454371354899092671392059817217866027812302221790516334624841426374822243837469451461726437020877123437782393406169448247482389879889853884819427619825160765790492976489, 32407942981932646210757279840036316891438758043868220934656228948956052979972832566362084487255663759463544820767559816372895344932341051117333716341006216731062621272054115066959914959967555447795753363361346887552670700379791925909850634358182903529964036492908336599792343255213780081620709422813254894714838389206701419934353928895006100613053388612471685723250816647677863154446863487298710309194686622766578315607528333288, 69869979063627731466668050892989223896389723363048763375250688709723510048642461659959470237467609182847116905185144338722583064845974562766392952336537838690954315239729313055258160910347050755783009676184731491550704169867384251840277084026600000599780169833155915123694174754507393250392421232709915239086950002080273029470925206534299821366778013511074819719523180017436119580654844867444770866127940458498359849753710793195, 16203971490966323105378639920018158445719379021934110467328114474478026489986416283181042243627831879731772410383779908186447672466170525558666858170503108365531310636027057533479957479983777723897876681680673438403531341735528217788905140017080263110792241598942920239791324630724944501073558534640417040785297940301916186036807028196211307621395707359356496111179987755621529030627030853845617035679719180083861946257654909594, 58125958929142961985379470455811692783553213039763368492478527700312132519171893279156724386108397389440042553494866511419997511373755263218502629572425811580103899779864645366634854026192008177367682487391512337785705736375292043459202394367278105498417587006774360563808988423702992469948070963586940521111511266542697180690240099296432930094856761793415703821834387094034762889056955654435576853888229163973831831390943356931]
        #print "p: ", p[0]
        #print "GCD(p, M): ", GCD(M, p[0])
        q = [0, 0, 5343630452008230568268677488306482298453815715879412953840794595967319063215444843619231295346972070717108079644623774236772022878761102575039871571948183899384015548303438686849107121071377705436214990992135357350, 0, 0]
        real_N = multiply(reduce(add, p), reduce(add, q))
        #print "real_N: ", real_N
        for i in xrange(5):
            network.nodes[i].one_round_BGW_phase_0(M, p[i], q[i], 2)
        for computer in network.nodes:
            computer.one_round_BGW_phase_1()
        for computer in network.nodes:
            computer.one_round_BGW_phase_2()

        test_N = 0
        for computer in network.nodes:
            test_N = add(test_N, computer.bgw.n_j)
            #print "n_j: ", computer.bgw.n_j
        print test_N == real_N    
        test_N = mod(test_N, M)
        #print "test_N: ", test_N
        print test_N == real_N
        real_N = mod(real_N,M)
        print test_N == real_N
        return 
    print trues

def hanna_generate_pq_test():
    network = Network([])
    network.generate_N()
    p = sum([comp.p_i for comp in network.nodes])
    print "p: ", p
    print gmpy2.is_prime(p)

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
    #hanna_bgw_test()
    hanna_generate_pq_test()
    #hao_signing_test()
    #brian_dealing_tests()
    #hao_key_generation_test()
    print "---------------------------------------"
    print "DONE WITH TESTS"
    print "---------------------------------------"

# Run everything!
#run_all_tests()


