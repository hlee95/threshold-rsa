from helpers import *

# global variables
# n = number of computers in the network
n = 10
# k = number of people who have to agree
k = 4
# g is an agreed upon element in Z*_n that has high order
# g = 101 # TODO compute this
# e = the public key
# e = 1 # TODO compute this
# B1 is the bound used in 5.2.1 distributed sieving method, TODO not exactly sure how to compute
B1 = 1 << 15
# B2 is the bound used in 5.2.3
B2 = 2**19 #we need this to be lower than our list of primes

# N = public modulus
# for now lets just make the the product of 2 large random primes
bits_secure = 1024
# N = get_random_prime(2**bits_secure,2**(bits_secure+1)-1)*get_random_prime(2**bits_secure,2**(bits_secure+1)-1)
#print "N=",N

#N = get_random_safe_prime(2**bits_secure,2**(bits_secure+1)-1)*get_random_prime(2**bits_secure,2**(bits_secure+1)-1)
# e = the public key
#e = get_random_int(N)# TODO compute this
#d = powmod(e, -1, N)
#creating n d_is that sum to d mod N
#d_i = sum_genereator(d, n, N)

# M = A prime number where M > N
# M = get_random_prime(N,2*N)
#print "M=",M

class Network:
    def __init__(self, sayingYes = []):
        print "network init"
        self.nodes = []
        for i in range(n):
            if i in sayingYes:
                self.nodes.append(Computer(self, i, True))
            else:
                self.nodes.append(Computer(self, i, False))

    def get_nodes(self):
        return self.nodes

    '''
    Should be run only once to set up global variables
    and do the dealing of shares.
    '''
    def setup(self):
        print "network setup"
        # first, choose N and e, and distribute d_i to everyone
        self.generate_N(fake=True) # generate public RSA modulus N, and large M
        while not self.verify_N():
            self.generate_N()
        self.choose_e_and_g() # choose the public encryption key e and generator g

        # private key generation, TODO Hao
        self.private_key_generation()

        # then, run the dealing algorithm
        deal = self.dealing_algorithm()
        if not deal:
            raise RuntimeError("user found an issue in the deals")
        print "done setup"

    '''
    Generate N, and verify that it is the product of two primes.
    At the end of this function, every computer will know N,
    '''
    def generate_N(self, fake = False, debug=False):
        #print "generate N"
        # Note this is a local M not the global M
        # This M is the product of all primes in the range (n, B1]

        M = reduce(multiply, get_primes_in_range(n + 1, B1))

        #print "M: ", M

        for computer in self.nodes:
            computer.M = M
        if fake:
            # Now, M is a large prime, larger than N
            M = get_random_prime(1 << 2050, 1 << 2051)
            for computer in self.nodes:
                computer.M = M
                assert gmpy2.is_prime(computer.M) == True


            p = get_random_prime(2**1024,2**1025)
            q = get_random_prime(2**1024,2**1025)
            N = p*q
            shares_p_i = getShares(p,n,M)
            shares_q_i = getShares(q,n,M)
            for i in range(len(self.nodes)):
                self.nodes[i].p_i = shares_p_i[i]
                self.nodes[i].q_i = shares_q_i[i]
                self.nodes[i].N = N
            return


        #print "calculating p_i"
        # First generate p_i
        self.generate_pq(M, debug)

        # for hanna_generate_pq_test
        if debug:
            return

        # At this point the last value that we put as n_j should be p_i
        for computer in self.nodes:
            computer.p_i = computer.bgw.n_j

        #print "calculating q_i"
        # Then generate q_i using the same method.
        self.generate_pq(M, debug)
        for computer in self.nodes:
            computer.q_i = computer.bgw.n_j

        # Now, M is a large prime, larger than N
        M = get_random_prime(1 << 1024, 1 << 1025)
        for computer in self.nodes:
            computer.M = M
            assert gmpy2.is_prime(computer.M) == True

        #print "calcalating N"
        # Compute N using BGW since now every computer has its own p_i and q_i
        for computer in self.nodes:
            computer.one_round_BGW_phase_0(M, computer.p_i, computer.q_i, computer.pq.l)
        for computer in self.nodes:
            computer.one_round_BGW_phase_1()
        for computer in self.nodes:
            computer.one_round_BGW_phase_2()
        # At this point, every computer has its share of N as computer.bgw.n_j,
        # so we just sum up every computer's n_j to get N
        N = mod(sum(map(lambda comp: comp.bgw.n_j, self.nodes)), M)
        for computer in self.nodes:
            computer.N = N
        #print "N: ", N

    def verify_N(self):
        if self.parallel_trial_division():
            return self.load_balance_primality_test()
        return False

    # each computer tries and checks if the N they all have is divisible by any small number
    def parallel_trial_division(self):
        for computer in self.nodes:
            if not computer.trial_division():
                print "bad N fails trial division"
                return False
        return True

    # check if N is prime:
    def load_balance_primality_test(self):
        N = self.nodes[0].N
        for computer in self.nodes:
            if N!= computer.N:
                raise RuntimeError("Not all computers had the same N")
        g = get_relatively_prime_int(N)
        for computer in self.nodes:
            computer.load_balance_primality_test_phase_1(g)
        for computer in self.nodes:
            if not computer.load_balance_primality_test_phase_2(g):
                print "N is not the product of two primes"
                return False
        return True


    '''
    Runs the protocol to give each computer their share of p_i or q_i.
    The same protocol is used for both p_i and q_i so we run this twice.
    At the end of this function, self.pq.u[-1] should be the value of the share.
    '''
    def generate_pq(self, M, debug=False):
        for computer in self.nodes:
            computer.generate_pq_setup(M)
        # print "M", M
        # print "l", self.nodes[0].pq.l
        # check to make sure stuff makes sense
        # gcd(a, M) should be 1
        a = mod(reduce(multiply, [comp.pq.a_i for comp in self.nodes]), M)
        # print "a: ", a
        # print "a mod M: ", mod(a, M)
        if GCD(a, M) != 1:
            raise RuntimeError("gcd(a, M) is not 1 in generate_pq")

        while self.nodes[0].pq.round < n: # round is initialized as 0 for every computer, and updated for every computer at the same time
            r = self.nodes[0].pq.round
            for computer in self.nodes:
                if len(computer.pq.u) != r+1 or len(computer.pq.v) != r+1:
                    raise RuntimeError("Wrong length for u or v, computer ", computer.id)
            for computer in self.nodes:
                computer.one_round_BGW_phase_0(M, computer.pq.u[r], computer.pq.v[r], computer.pq.l)
            for computer in self.nodes:
                computer.one_round_BGW_phase_1()
            for computer in self.nodes:
                computer.one_round_BGW_phase_2()
            # for debugging
            product = mod(reduce(multiply, [self.nodes[i].pq.a_i for i in xrange(r+1)]), M)
            current_sum = mod(reduce(add, [comp.bgw.n_j for comp in self.nodes]), M)
            if product != current_sum:
                raise RuntimeError("product of a_i so far not equal to sum of the latest bgw shares")
            for computer in self.nodes:
                computer.generate_pq_update()
        if debug:
            p = mod(reduce(add, [comp.bgw.n_j for comp in self.nodes]), M)
            print "p == a", p == a

    '''
    Choose the public exponent and the generator randomly.
    '''
    def choose_e_and_g(self):
        e = 65537 #get_relatively_prime_int(self.nodes[0].N)
        g = get_random_int(self.nodes[0].N) # TODO: check this
        for computer in self.nodes:
            computer.e = e
            computer.g = g


    """
    the dealing algorithm.
    each user with their share of the private key d_i
    the users agree on a k and global public S
    Each player gets Public Private share pair (P_i,S_i)
    which is needed to implement the signature scheme
    takes paramters
    prime M > N
    threshold k
    element g of high order Z_N
    S the set of all users
    """
    def dealing_algorithm(self):
        for user in self.nodes:
            #calculation phase
            user.dealing_phase_1()
        for user in self.nodes:
            #print "user id = ",user.id+1
            #verfication phase
            if not user.dealing_phase_2():
                print "aborted, user",user.id+1,", found an error"
                return False
        return True

    '''
    Produce a valid signature for the given message if at least k parties agree.
    '''
    def sign(self, message):
        # If fewer than k parties say yes, then abort and don't sign.
        agreed_parties = [computer for computer in self.nodes if computer.agree]
        if len(agreed_parties) < k:
            print "Only %d parties agreed, need %d, aborting signature." %(len(agreed_parties),k)
            return
        # Pick any k (for simplicity, we pick the first k) of the agreeing parties,
        # and let them be the set of interest
        # Note that we use a tuple because a tuple can be used as a dictionary key.
        I = tuple(agreed_parties[:k])
        I_prime = [computer for computer in self.nodes if computer not in I]

        # Prepare the k parties to run the algorithm.
        for computer in I:
            computer.setup(I, I_prime)

        # If this set of parties has not previously run the
        # subset presigning algorithm before, then run it
        if I not in I[0].subsets:
            self.subset_presigning_algorithm(I)
        else:
            print "This subset has already run the presigning algorithm."

        # Have each party generate a signature share and proof
        #     (so basically do 6.2.3 and 6.2.4)
        for computer in I:
            computer.signature_share_generation(message)
        for computer in I:
            computer.signature_share_verification()
        # Then, have each party do the share combining, so do 6.2.5
        for computer in I:
            computer.combine_signatures(message)
        # Print out the final signature
        for computer in I:
            print "signature " + str(computer.id) + " " + str(computer.signature)

        real_d = reduce(add, [computer.d_i for computer in self.nodes])
        expected_signature = powmod(message, real_d, self.nodes[0].N)
        print expected_signature
        assert expected_signature == self.nodes[0].signature

    '''
    Implements the subset presigning algorithm in multiple phases.
    I is the set of k agreeing parties,
    and I_prime is the remaining set of n-k parties.
    '''
    def subset_presigning_algorithm(self, I):
        print "Subset presigning algorithm!"
        # Use many for-loops because all of phase 1 must complete
        # before any party can start phase 2, and likewise with the subsequent phases.
        for t_i in I:
            t_i.subset_presigning_algorithm_phase_0()
        for t_i in I:
            t_i.subset_presigning_algorithm_phase_1()
        for t_i in I:
            t_i.subset_presigning_algorithm_phase_2()
        for t_i in I:
            t_i.subset_presigning_algorithm_phase_3()
        # X_I should be given, check that sum s in I = sum d in I'+x_I*M    
        ssum = 0
        dsum = 0
        xi = 0
        M = 0
        for comp in I:
            ssum = add(ssum,comp.presigning_data[comp.I].s_t_i)
            xi = comp.presigning_data[comp.I].x_I
            M = comp.M
        for comp in [computer for computer in self.nodes if computer not in I]:
            dsum = add(dsum,comp.d_i)
        assert ssum == dsum + xi*M
            
        for t_i in I:
            t_i.subset_presigning_algorithm_phase_4()

    def private_key_generation(self,):
        print 'private key gen nodes'

        for user in self.nodes:
            user.create_phi_i()
            user.distribute_phi_i_j()
        for user in self.nodes:
            user.distribute_sum_phi_j()
        for user in self.nodes:
            user.generate_phi_and_psi()

        #for checks
        phisum = 0
        for user in self.nodes:
            phisum = add(phisum,user.phi_i)
        for user in self.nodes:
            assert 0 == mod(subtract(user.psi,phisum),user.e)

        for user in self.nodes:
            user.generate_d_i()

        # trial decryption 5.2.6
        message = 1234567
        for user in self.nodes:
            user.generate_message_i(message)

        # user 1 computes product
        self.nodes[0].process_messages(message)

class Computer:
    def __init__(self, network, _id, agree):
        self.network = network
        self.id = _id
        self.agree = agree

        # Variables for RSA secret keys and modulus
        self.N = None # the shared public modulus for RSA
        self.M = None # some number larger than N
        self.g = None # the generator, something that has high order in Z*_n
        self.e = None # the RSA public key
        self.p_i = None #12344 # test values, this computer's share of prime p
        self.q_i = None #15125 # test values, this computer's share of prime q
        self.d_i = None # this computer's share of the secret key d
        # Intermediate variables needed to generate RSA modulus and secret key shares
        self.bgw = None # data for running BGW protocol; the data is replaced every time we run the protocol
        self.pq = None # data to store intermediate values

        # to check if N is the product of two primes
        self.v = [0]*n

        # for primality testing, each node has a list of prime
        primes = get_primes_in_range(B1,B2)

        self.primes = [primes[i] for i in xrange(len(primes)) if i%n==self.id]

        # Variables for the dealing algorithm
        self.f_i_j = [1] * n # array that stores f_i_j for each i in range 0...n-1 (j is self)
        self.a_i_j = []
        # the array for the commitments of of the coefficients of the polynomial
        # we get them from all other users, thus the n by n array
        self.b_i_j = [[0]*n for i in xrange(n)]
        # to calculate the phi(n) used to recover d
        self.phi_i = None
        self.phi_i_j = [0]*n #only gets one phi_i_j from each party
        self.sum_phi_i_j = [0]*n #sum of all phi_i_j of party j, set by recieving from party j, every party will eventually have the same list
        self.phi = None #phi(n)
        self.psi = None #phi(n) mod e
        self.psi_inv = None #psi inv mod e
        self.message_i = [0]*n # for trial decryption 5.2.6
        # Variables set at the end of the dealing algorithm
        self.S = {} #{k,M,g}
        self.P_i = [] # {{b_j,l}_j=1,...,n,l=0,...,k-1}
        self.S_i = {} # #{d_i,{a_i,j}_j=1,...,k-1,{f_j,i}_i!=j}

        # Variables for the subset presigning algorithm
        self.dummy_message = None
        self.I = None # the current subset
        self.I_prime = None # the complement of the current subset
        self.subsets = [] # this is a history of all subsets that this computer has been part of
        self.presigning_data = {} # maps subset -> this computer's presigning data for that subset

        # Variables for share generation/verification/combining
        self.sigmas = [] # contains tuples of the form (id, sigma)
                         # where sigma is itself a tuple of the form (signature, proof)
                         # there should be k items in self.sigmas

        self.signature = None # the final signature produced after combining k shares


    '''
    Change this computer's vote to be yes or no (set agree to True or False)
    '''
    def change_choice(self, agree):
        self.agree = agree


    #####################################################
    # Stuff for Deciding N, e, d_i, g
    #####################################################
    '''
    Protocol among the computers for generating the shares of p and q.
    All arithmetic should be done modulo M.

    This function sets up the data structure needed for calculating p_i and q_i,
    and generates a random a_i that is relatively prime to M.
    '''
    def generate_pq_setup(self, M):
        # Initialize PQData with round = 0, M = M, l = floor((n-1)/2)
        self.pq = PQData(0, M, int(math.floor((n-1)/2)))
        # Let a_i be some random integer relatively prime to M
        self.pq.a_i = get_relatively_prime_int_small(M)
        if GCD(self.pq.a_i, M) != 1:
            raise RuntimeError("The impossible has happened.")
        # Set the first (zeroeth) value in u and v.
        # Since this is the first round, the first (zeroeth) computer sets u[round] = a_i
        # but all the other computers set everything to 0
        if self.id == self.pq.round:
            self.pq.u.append(self.pq.a_i)
            self.pq.v.append(1)
        else:
            self.pq.u.append(0)
            self.pq.v.append(0)


    '''
    Receives a (f, g, h) tuple from a computer, and adds it
    to the array self.bgw.received_fgh.
    '''
    def receive_fgh(self, fgh_tuple):
        self.bgw.received_fgh.append(fgh_tuple)
        # print "fgh: ", fgh_tuple

    '''
    Begins to run one round of the BGW protocol (section 4.3).

    When this function is called, self.pq.round is the round where the latest
    u and v values were placed. For example, the first time one_round_BGW is called,
    we expect round = 0 because we just started the algorithm.

    Phase 0 simply sets the self.bgw data structure with the correct values.
    '''
    def one_round_BGW_phase_0(self, M, p_i, q_i, l):
        # Reset to a new BGWData instance with data from the latest round.
        # self.bgw = BGWData(self.pq.M, self.pq.u[self.pq.round], self.pq.v[self.pq.round], self.pq.l)
        self.bgw = BGWData(M, p_i, q_i, l)
    '''
    Phase 1 generates random coefficients for the polynomials,
    and calculates and broadcasts the f_i(j) values to each computer j.
    '''
    def one_round_BGW_phase_1(self):
        # Generate the random coefficients in arrays a, b, and c
        # Note that a and b have length l, while c has length 2l
        # for count in xrange(self.bgw.l):
        #     self.bgw.a.append(get_random_int(self.bgw.M))
        #     self.bgw.b.append(get_random_int(self.bgw.M))
        #     self.bgw.c.append(get_random_int(self.bgw.M))

        # for count_again in xrange(self.bgw.l):
        #     self.bgw.c.append(get_random_int(self.bgw.M))

        self.bgw.a = [1 for i in xrange(self.bgw.l)]
        self.bgw.b = [1 for i in xrange(self.bgw.l)]
        self.bgw.c = [1 for i in xrange(2*self.bgw.l)]


        # Calculate and broadcast fgh tuples as descrribed in section 4.3 steps 1 and 2
        for computer in self.network.nodes:
            x = computer.id + 1 # the x value to evaluate the polynomial at
            x_j = map(lambda ex: powmod(x, ex + 1, self.bgw.M), range(2*self.bgw.l)) # calculate the relevant powers of x
            f = mod(self.bgw.p_i + reduce(add,map(lambda idx: mulmod(self.bgw.a[idx], x_j[idx], self.bgw.M), range(self.bgw.l))), self.bgw.M)
            g = mod(self.bgw.q_i + reduce(add,map(lambda idx: mulmod(self.bgw.b[idx], x_j[idx], self.bgw.M), range(self.bgw.l))), self.bgw.M)
            h = mod(reduce(add,map(lambda idx: mulmod(self.bgw.c[idx], x_j[idx], self.bgw.M), range(2*self.bgw.l))), self.bgw.M)
            computer.receive_fgh((f, g, h))

    '''
    In phase 2, after receiving (f, g, h) tuples, the computer finishes the BGW protocol
    by calculating N_j and then converting it to n_j, the additive share,
    and saving the additive share in self.pq.n_j
    '''
    def one_round_BGW_phase_2(self):
        # Calculate N_j as described in section 4.3 step 3
        sum_f = sum_g = sum_h = 0
        for f, g, h in self.bgw.received_fgh:
            sum_f = mod(add(sum_f, f), self.bgw.M)
            sum_g = mod(add(sum_g, g), self.bgw.M)
            sum_h = mod(add(sum_h, h), self.bgw.M)
        N_j = mod(add(multiply(sum_f, sum_g), sum_h), self.bgw.M)
        # Calculate n_j as described in section 4.3.2
        n_j = N_j
        bottom = 1
        for h in xrange(n):
            if h != self.id:
                # Don't use mpz because mpz doesn't play nice with floats
                n_j = multiply(multiply(n_j,h + 1),powmod(h-self.id,-1, self.bgw.M))
        #        bottom = multiply(bottom,h - self.id)
        #n_j = divide(n_j,bottom)

        self.bgw.n_j = mod(n_j, self.bgw.M)

    '''
    Update u and v arrays in between rounds of BGW.
    '''
    def generate_pq_update(self):
        # Set the next value in self.pq.u as the share calculated in the last round of BGW
        self.pq.u.append(self.bgw.n_j)
        # Update the round.
        self.pq.round += 1
        # Set the next value in self.pq.v depending on if it's our turn or not.
        if self.id == self.pq.round:
            #print "updated!"
            self.pq.v.append(self.pq.a_i)
        else:
            self.pq.v.append(0)

    # check for small factors of N
    def trial_division(self,debug = False):
        N = self.N
        for prime in self.primes:
            if N%prime==0:
                print "N=prime*x"
                print "N",N
                print "prime",prime
                print "x",N/prime
                return False
        return True

    # check if N is prime
    # broadcast phase
    def load_balance_primality_test_phase_1(self,g):
        N = self.N
        if self.id == 0:
            v = powmod(g,N-self.p_i-self.q_i+1,N)
        else:
            v = powmod(g,self.p_i+self.q_i,N)
        for computer in self.network.nodes:
            computer.v[self.id]=v

    # checking phase
    def load_balance_primality_test_phase_2(self,g):
        N = self.N
        v1 = self.v[0]
        rest = 1
        for i in range(1,n):
            rest = mulmod(rest,self.v[i],N)
        if v1 != rest:
            print "bad N"
            return False
        return True


    #####################################################
    # Stuff for the Dealing Algorithm (6.2.1)
    #####################################################

    # dealing algorithm (6.2.1)
    # Parties i=1...n agree on the following paramters
    # # # prime M > N
    # # # threshold k where 1 < k < n
    # # # element g of high order Z_N*
    # each party picks random degree (k-1) polynomial f_i in Z_m
    # # # f_i(x) = a_{i,k-1}x^{k-1}+...+a_{i,1}x+d_i
    # ith party computes f_i(j) and send to party P_j for all j=1..n
    # note this is the Shamir sharing of d_i
    # ith party also computes b_{i,j}=g^{a_{i,j}} mod N for j = 0...(k-1)
    # # # broadcasts these values
    # # # these are the commitments
    # at this point each party j has recieved f_{1,j},...,f_{n,j} and verifies
    # # # g^{f_{i,j}} = g^{f_i(j)} mod N = g^{a_{1,k-1}j^{k-1}+...+a_{i,1}j+d_i}
    # # #             =
    def dealing_phase_1(self):
        M = self.M
        assert gmpy2.is_prime(M) == True
        g = self.g
        S = self.network.nodes
        #print "user",self.id+1
        selfid = self.id+1
        # pick the random polynomial
        self.a_i_j = [0]*k

        self.a_i_j[0] = self.d_i
        for i in xrange(1,k):
            self.a_i_j[i] = get_random_int(M)
        #print "a_i_j",self.a_i_j
        # calculate f_i_j for each other user and set their values
        # f_i_j = f_i(j)
        for user in S: # for user in set
            #if user != self: # those that are not you
            userid = user.id+1
            f_i_j = 0
            for c in xrange(k-1,-1,-1):
                f_i_j+=multiply(self.a_i_j[c],powmod(userid,c,M))
            #print "f_i_j for user",userid,"is",f_i_j#%M
            user.f_i_j[self.id]=f_i_j
        for user in S:
            for j in xrange(0,k):
                user.b_i_j[self.id][j]=powmod(g,self.a_i_j[j],self.N)
            #print "the bs for user",user.id+1,"is",user.b_i_j[self.id]

    def dealing_phase_2(self):
        M = self.M
        g = self.g
        S = self.network.nodes
        # check to ensure people sent out the correct values
        selfid = self.id+1
        for user_i in S:
            #if user_i != self:
            user_iid = user_i.id+1
            g_exp_f_i_j = powmod(g,self.f_i_j[user_i.id], self.N)
            checker = gmpy2.mpz(1)
            for t in xrange(k):
                checker=multiply(checker,powmod(self.b_i_j[user_i.id][t],powmod(selfid,t,self.N),self.N))
            checker = mod(checker,self.N)
            if checker != g_exp_f_i_j:
                return False
        # set the final values
        self.S["k"] = k
        self.S["M"] = M
        self.S["g"] = g
        self.P_i = self.b_i_j # check this again
        self.S_i["d_i"]=self.d_i
        self.S_i["a_i,j"]=self.a_i_j[1:] # we don't want the term a_0
        self.S_i["f_j,i"]=self.f_i_j # there is a 0 where self is for indexing purposes
        return True



    #####################################################
    # Stuff for the Subset Presigning Algorithm (6.2.2)
    #####################################################
    '''
    Sets up this computer as a member of the set I,
    and clears previous signatures and sigmas from the last round of signing.
    '''
    def setup(self, I, I_prime):
        self.I = I
        self.I_prime = I_prime

        self.sigmas = [] # reset this to empty
        self.signature = None
        print "Hi I am computer %d." % self.id # Remove after debugging

    '''
    Receive a broadcast of a different computer's sigma_I_t_i
    for the dummy message during the presigning phase.
    '''
    #def receive_presigning_sigma_I_t_i(self, id_and_sigma):
    #    self.presigning_data[self.I].received_sigma_I_t_i.append(id_and_sigma)

    '''
    Receive a broadcast of a different computer's h_t_i
    and the computer's id, as a tuple.
    '''
    def receive_presigning_h_t_i(self, id_and_h_t_i):
        self.presigning_data[self.I].received_h_t_i[id_and_h_t_i[0]] = id_and_h_t_i[1]

    '''
    Receive a broadcast of a different computer's calculated x_I
    and the computer's id, as a tuple.
    '''
    def receive_presigning_x_I(self, id_and_x_I):
        self.presigning_data[self.I].received_x_I.append(id_and_x_I)


    '''
    Returns a copy of the current subset presigning data.
    '''
    def get_current_subset_presigning_data(self):
        return (copy.deepcopy(self.presigning_data[self.I].S_I_t_i),
            copy.deepcopy(self.presigning_data[self.I].D_I))

    '''
    Runs the subset presigning algorithm, where <computers>
    is an array of the k computers (including this one)
    that agree to sign the message.

    Note that this only needs to be run ONCE for each unique
    subset of k computers that wish to sign a message.

    Phase 0 involves adding I to the array of subsets
    and creating an instance of PresigningData for this set I
    '''
    def subset_presigning_algorithm_phase_0(self):
        # Sanity check to make sure we haven't already run the algorithm for this subset.
        if self.I in self.subsets:
            raise RuntimeError("Should not run subset presigning algorithm (phase 0) on a previously seen subset.")

        # Add this set I to the self.subsets array and create a new PresigningData instance
        self.subsets.append(self.I)
        self.presigning_data[self.I] = PresigningData()
        self.dummy_message = powmod(2, self.e, self.N)

    '''
    Phase 1 involves calculating lambda_t_i, s_t_i, and h_t_i,
    and broadcasting h_t_i.
    '''
    def subset_presigning_algorithm_phase_1(self):
        # Compute lambda_t_i
        lambda_t_i = 1
        bottoms = 1
        for computer in self.I:
            if computer.id == self.id:
                continue
            lambda_t_i = multiply(multiply(lambda_t_i, computer.id + 1),powmod(computer.id - self.id,-1,self.M))
            #bottoms = multiply(bottoms,computer.id - self.id)
        #lambda_t_i = divide(lambda_t_i,bottoms)
        lambda_t_i = mod(lambda_t_i, self.M)
        #print "lambda_t_i",lambda_t_i
        self.presigning_data[self.I].lambda_t_i = lambda_t_i

        # Compute s_t_i = (sum(f_i_j) * lambda_t_i) % M
        I_prime_ids = map(lambda computer: computer.id, self.I_prime)
        s_t_i = mod(multiply(reduce(add, [self.f_i_j[i] for i in I_prime_ids]), lambda_t_i), self.M)
        self.presigning_data[self.I].s_t_i = s_t_i
        self.presigning_data[self.I].S_I_t_i = s_t_i

        # Compute h_t_i
        h_t_i = powmod(self.g, s_t_i, self.N)
        self.presigning_data[self.I].h_t_i = h_t_i

        # Broadcast h_t_i so other computers can use it to verify later,
        # and also broadcast to yourself just so your array is complete with all k elements.
        for computer in self.I:
            computer.receive_presigning_h_t_i((self.id, h_t_i))

    '''
    Phase 2 involves computing the signature share on a dummy message,
    and broadcasting the signature share to every other party in I.
    '''
    def subset_presigning_algorithm_phase_2(self):
        # Compute and broadcast the signature share.
        dsum = 0
        psum = 0
        qsum = 0
        for computer in self.network.nodes:
            dsum = add(dsum,computer.d_i)
            psum = add(psum,computer.p_i)
            qsum = add(qsum,computer.q_i)
        assert mod(multiply(dsum,self.e),multiply(psum-1,qsum-1))==1
        print 'check i'
        ssum = 0

        for computer in self.I:
            ssum = add(ssum, computer.presigning_data[self.I].S_I_t_i)

        intersum = 0
        for computer1 in self.I:
            for computer2 in self.I_prime:
                intersum = add(intersum, multiply(computer1.f_i_j[computer2.id],computer1.presigning_data[self.I].lambda_t_i))
        assert mod(intersum,self.M)== mod(ssum,self.M)

        bsum = 0
        for computer1 in self.I:
            bsum = add(bsum, multiply(computer1.f_i_j[self.id],computer1.presigning_data[self.I].lambda_t_i))

        dsum = 0
        for computer in self.I_prime:
            dsum = add(dsum, computer.d_i)
        dsum = mod(dsum,self.M)

        #print "bsum",mod(bsum,self.M)
        #print "d_i",mod(self.d_i,self.M)
        #print "intersum",mod(intersum,self.M)


        #print "ssum",mod(ssum,self.M)
        #print "dsum",mod(dsum,self.M)




        #for j in [1,3,4]:
        #    fsum = 0
        #    for i in [0,2]:
        #        fsum=mod(add(fsum,multiply(self.network.nodes[i].f_i_j[j],self.network.nodes[i].presigning_data[self.I].lambda_t_i)),self.M)
        #    print "fsum",fsum
        #    print "dsum",self.network.nodes[j].d_i
        #    assert fsum == self.network.nodes[j].d_i
        assert mod(subtract(ssum, dsum),self.M) == 0

        signature_share = self.signature_share_generation(self.dummy_message)

    '''
    Phase 3 involves verifying the signature shares that have been broadcasted,
    finding x_I via exhaustive search, and then broadcasting x_I.
    '''
    def subset_presigning_algorithm_phase_3(self):
        # Check that we received a signature share from all k-1 other computers in the group.
        if len(self.sigmas) != k:
            #
            "Didn't receive signature share on dummy message from k-1 other parties."
            raise RuntimeError("Didn't receive signature share on dummy message from k-1 other parties.")

        # Verify each signature share.
        if not self.signature_share_verification():
            #print "Invalid signature on dummy message in subset presigning."
            raise RuntimeError("Invalid signature on dummy message in subset presigning.")

        # If everything checks out, then continue on with the algorithm.

        # Find x_I by checking all possible values
        possible_x_I = range(k-n, k+1) # x_I can be between k-n and k inclusive.
        # Calculate the product of the received signature shares.
        product_c_prime_t_i = mod(reduce(multiply,
            map(lambda sigma: sigma[0],
                self.sigmas)), self.N)
        #print 'sigmas', map(lambda sigma: sigma[0],self.sigmas)
        #print 'product', product_c_prime_t_i
        # Calculate 2^(e*M) % N
        two_e_M = powmod(2, multiply(self.e, self.M), self.N)
        # Search for the value of x_I that makes the product = 2 * (2^(e*M*x_I))
        x_I = None
        for x in possible_x_I:
            if product_c_prime_t_i == mod(multiply(2, powmod(two_e_M, x, self.N)), self.N) :
                x_I = x
                break
        if x_I is None:
            raise RuntimeError("Couldn't find viable x_I in subset presigning algorithm, computer " + str(self.id))
        self.presigning_data[self.I].x_I = x_I

        # Broadcast x_I so everyone can verify that they found the same x_I
        for computer in self.I:
            if computer.id != self.id:
                computer.receive_presigning_x_I((self.id, x_I))

    '''
    Phase 4 involves verifying the x_I that have been broadcasted,
    and then setting D_I and S_I_t_i for this subset.
    '''
    def subset_presigning_algorithm_phase_4(self):
        print 'PHASE 4'
        # Verify all received x_I (check that they are the same as what we found).
        if len(self.presigning_data[self.I].received_x_I) != k-1:
            raise RuntimeError("Didn't receive enough x_I values in subset presigning.")
        for _id, x in self.presigning_data[self.I].received_x_I:
            if x != self.presigning_data[self.I].x_I:
                print "Computer %d broadcasted x_I value %d, but this computer (%d) has x_I value %d" %(_id, x, self.id, self.presigning_data[self.I].x_I)
                raise RuntimeError("Didn't match x_I.")

        # Set D_I and S_I_t_i
        self.presigning_data[self.I].S_I_t_i = self.presigning_data[self.I].s_t_i # seems stupid but they do it in the paper
        # Aggregate the received sigmas and h_t_i into an array
        h_sigma_array = []
        # Make sure we have k sigmas and k h_t_i values.
        if len(self.sigmas) != k or len(self.presigning_data[self.I].received_h_t_i) != k:
            raise RuntimeError("Didn't receive k sigmas or h_t_i values.")
        # Match them up and aggregate into h_sigma_array
        for sigma, proof in self.sigmas:
            id_s = proof[-1] # the id is the last thing in the proof array
            for id_h, h_t_i in self.presigning_data[self.I].received_h_t_i.items():
                if id_s == id_h:
                    h_sigma_array.append((id_s, h_t_i, sigma))
                    break
        # Make sure that we got k tuples after matching, otherwise there are unmatched values.
        print len(h_sigma_array), k
        if len(h_sigma_array) != k:
            raise RuntimeError("Couldn't match h_t_i and sigma values appropriately.")

        self.presigning_data[self.I].D_I = (self.presigning_data[self.I].x_I, h_sigma_array)

        print 'S_I_t_i', self.presigning_data[self.I].S_I_t_i
        print 'I', self.I

    ###############################################################
    # Stuff for the Signature Share Generation and Verification
    ###############################################################

    '''
    Receives a sigma from another computer
    and saves it in self.sigmas
    '''
    def receive_sigma(self, sigma):
        self.sigmas.append(sigma)

    '''
    Given a message and the relevant set of k parties,
    computes and broadcasts a tuple containing a signature and a proof.

    Also saves the signature share (both the signature and the proof) in self.sigmas.
    Also returns the signature share.
    '''
    def signature_share_generation(self, m):
        #needs to be fixed for unknown order of g mod N
        d_i = self.d_i
        s_i = self.presigning_data[self.I].S_I_t_i
        b_ti0 = self.b_i_j[self.id][0]
        h_ti = self.presigning_data[self.I].h_t_i
        c_i = powmod(m, add(s_i,d_i), self.N)
        s = get_random_int(self.N)
        c = get_random_int(self.N)
        r= add(s,multiply(c,add(s_i,d_i)))
        m_s = powmod(m, s, self.N)
        g_s = powmod(self.g, s, self.N)
        proof = [m, (g_s, m_s), c_i, r, c, self.id] #
        sigma = (c_i, proof) #TODO: actually calculate sigma = (signature, proof)
        print 'Is'
        # TODO broadcast the tuple (self.id, sigma) to other parties
        for computer in self.I:
            print computer
            computer.receive_sigma(sigma)
        # Return sigma
        return sigma

    '''
    For every sigma in self.sigmas, where sigma is a signature and a proof,
    verify that the proof holds, and return True or False.
    '''
    def signature_share_verification(self):
        print 'verifying'
        for sigma in self.sigmas:
            (c_i, proof) = sigma
            [m, (g_s, m_s), c_i, r, c, s_id] = proof
            b_ti0 = self.b_i_j[s_id][0]
            h_ti = self.presigning_data[self.I].received_h_t_i[s_id]
            if powmod(self.g, r, self.N) != mod(g_s*powmod(b_ti0*h_ti, c, self.N), self.N):
                return False
            if powmod(m, r, self.N) != mod(m_s*powmod(c_i, c, self.N), self.N):
                return False
        return True # TODO actually verify each sigma

    ##############################################
    # Stuff for the Share Combining (6.2.5)
    ##############################################

    '''
    Assuming we have already received the sigmas from the
    other k-1 parties, we will now combine the shares and
    return the appropriate signature for the desired message.
    '''
    def combine_signatures(self, m):
        # We assume that the signature shares have been computed,
        # broadcasted and verified already, and that they are
        # stored in self.sigmas

        # Calculate the product of c_{t_i} for t_i in I
        product_c_t_i = mod(reduce(multiply, map(lambda sigma: sigma[1][0], self.sigmas)), self.N)
        # Calculate the final signature = m^(-x_I * M) * the product
        self.signature = mod(multiply(product_c_t_i, powmod(m, -1 * multiply(self.presigning_data[self.I].x_I, self.M), self.N)), self.N)


    ##############################################
    # Stuff for Private Key Generation
    ##############################################

    def receive_phi(self, from_id, phi_i_j):
        self.phi_i_j[from_id] = phi_i_j

    def receive_sum_phi_j(self, from_id, sum_phi_j):
        self.sum_phi_i_j[from_id] = sum_phi_j #sum of all phi_i_j of party j, set by recieving from party j, every party will eventually have the same list

    def receive_message_i(self, from_id, message):
        self.message_i[from_id] = message

    def create_phi_i(self,):
        #step 1
        self.phi_i =-add(self.p_i,self.q_i)
        if self.id == 0:
            self.phi_i = add(add(self.N,self.phi_i), 1)

    def distribute_phi_i_j(self,):
        phi_i_j = sum_genereator(self.phi_i, n, self.e)
        assert mod(reduce(add, phi_i_j), self.e) == mod(self.phi_i,self.e)
        for computer in self.network.nodes:
            computer.receive_phi(self.id, phi_i_j[computer.id])

    def distribute_sum_phi_j(self,):
        #Calculates sum of phi_i_j and distributes it to everyone
        sum_phi_j = reduce(add,self.phi_i_j)
        for computer in self.network.nodes:
            computer.receive_sum_phi_j(self.id, sum_phi_j)

    def generate_phi_and_psi(self,):
        #print self.sum_phi_i_j
        self.sum_phi = reduce(add,self.sum_phi_i_j)
        self.psi = mod(self.sum_phi, self.e)
        self.psi_inv = powmod(self.psi, -1, self.e)

    def generate_d_i(self,):
        self.d_i = floor_divide(-multiply(self.phi_i,self.psi_inv), self.e)
        if self.id == 0:
            self.d_i = floor_divide(1-multiply(self.phi_i,self.psi_inv), self.e)

    def generate_message_i(self,message):
        self.network.nodes[0].receive_message_i(self.id, powmod(message,multiply(self.d_i,self.e),self.N))

    #message is the message to compare to
    def process_messages(self,message):
        m_prime = mod(reduce(multiply,self.message_i), self.N)
        correct = n
        for i in range(n):
            if mod(message, self.N) == mod(multiply(m_prime, powmod(message, multiply(i,self.e), self.N)),self.N):
                correct = i
                break
        assert correct != n
        self.d_i +=correct


    def __str__(self):
        return "Computer "+str(self.id)
