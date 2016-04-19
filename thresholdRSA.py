from helpers import *
# global variables
# n = number of computers in the network
n = 10
# k = number of people who have to agree
k = 4
# g is an agreed upon element in Z*_n that has high order
g = 0 # TODO compute this
# e = the public key
e = 0 # TODO compute this

# N = public modulus
# for now lets just make the the product of 2 large random primes
bits_secure = 1024
N = get_random_prime(2**bits_secure,2**(bits_secure+1)-1)*get_random_prime(2**bits_secure,2**(bits_secure+1)-1)

# M = A prime number where M > N
M = get_random_prime(N,2*N)

class Network:
    def __init__(self, sayingYes = []):
        self.nodes = []
        for i in range(n):
            if i in sayingYes:
                self.nodes.append(Computer(i, True))
            else:
                self.nodes.append(Computer(i, False))
    def get_nodes(self):
        return self.nodes

    '''
    Should be run only once to set up global variables
    and do the dealing of shares.
    '''
    def setup(self):
        # first, choose N and e, and distribute d_i to everyone
        # then, run the dealing algorithm
        pass

    '''
    Produce a valid signature for the given message if at least k parties agree.
    '''
    def sign(self, message):
        global k
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
        # If this set of parties has not previously run the
        # subset presigning algorithm before, then run it
        if I not in I[0].subsets:
            print "Subset presigning algorithm!"
            for t_i in I:
                t_i.subset_presigning_algorithm_phase_1(I, I_prime)
            # Use more for-loops because all of phase 1 (the broadcast phase) must complete
            # before any party can start phase 2, and likewise with phase 2 and phase 3.
            for t_i in I:
                t_i.subset_presigning_algorithm_phase_2()
            for t_i in I:
                t_i.subset_presigning_algorithm_phase_3()

        ''' major TODO: all this stuff '''
        # Have each party generate a signature share and proof
        #     (so basically do 6.2.3 and 6.2.4)
        # Then, have each party do the share combining, so do 6.2.5

class Computer:
    def __init__(self, _id, agree):
        self.id = _id
        self.agree = agree

        # This computer's share of the secret key
        self.d_i = None

        # Variables for the dealing algorithm
        self.f_i_j = [0] * n # array that stores f_i_j for each i in range 0...n-1 (j is self)

        # Variables for the subset presigning algorithm
        global e
        self.dummy_message = 2**e # TODO maybe use gmpy2 for this
        self.I = None # the current subset
        self.I_prime = None # the complement of the current subset
        self.subsets = [] # this is a history of all subsets that this computer has been part of
        self.presigning_data = {} # maps subset -> this computer's presigning data for that subset


    '''
    Change this computer's vote to be yes or no (set agree to True or False)
    '''
    def change_choice(self, agree):
        self.agree = agree

    #####################################################
    # Stuff for the Dealign Algorithm (6.2.1)
    #####################################################

    # dealing algorithm (6.2.1)
    # Parties i=1...n agreeon the following paramters
    # # # prime M > N
    # # # threshold k where 1 < k < n
    # # # element g of high order Z_N*
    # each party picks random degree (k-1) polynomial f_i in Z_m
    # # # f_i(x) = a_{i,k-1}x^{k-1}+...+a_{i,1}x+d_i
    # ith party computes f_i(j) and send to party P_j for all j=1..n
    # note this is the Shamir sharing of d_i
    # ith party also computes b_{i,j}=g^{a_{i,j}} mod N for j = 0...(k-1)
    # # # broadcats these values
    # # # these are the commitments
    # at this point each party j has recieved f_{1,j},...,f_{n,j} and verifies
    # # # g^{f_{i,j}} = g^{f_i(j)} mod N = g^{a_{1,k-1}j^{k-1}+...+a_{i,1}j+d_i}
    # # #             =


    #####################################################
    # Stuff for the Subset Presigning Algorithm (6.2.2)
    #####################################################

    '''
    Receive a broadcast of a different computer's sigma_I_t_i
    for the dummy message during the presigning phase.
    '''
    def receive_presigning_sigma_I_t_i(self, sigma):
        self.presigning_data[self.I].received_sigma_I_t_i.append(sigma)

    '''
    Runs the subset presigning algorithm, where <computers>
    is an array of the k computers (including this one)
    that agree to sign the message.

    Note that this only needs to be run ONCE for each unique
    subset of k computers that wish to sign a message.

    Phase 1 involves calculating lambda_t_i, s_t_i, and h_t_i.
    '''
    def subset_presigning_algorithm_phase_1(self, I, I_prime):
        global N
        # Sanity check to make sure we haven't already run the algorithm for this subset.
        if I in self.subsets:
            raise RuntimeError("Should not run subset presigning algorithm (phase 1) on a previously seen subset.")

        self.I = I
        self.I_prime = I_prime
        self.subsets.append(I)
        self.presigning_data[I] = PresigningData()
        print "Hi I am computer %d." % self.id # Remove after debugging

        # Compute lambda_t_i
        lambda_t_i = 1
        for computer in I:
            if computer.id == self.id:
                continue
            lambda_t_i *= (computer.id + 1)/(computer.id - self.id) # We need the "+1" because otherwise we could get 0
            lambda_t_i %= M
        self.presigning_data[I].lambda_t_i = lambda_t_i

        # Compute s_t_i
        I_prime_ids = map(lambda computer: computer.id, I_prime)
        s_t_i = (sum([self.f_i_j[i] for i in I_prime_ids]) * lambda_t_i) % M
        self.presigning_data[I].s_t_i = s_t_i

        # Compute h_t_i
        h_t_i = (g**(s_t_i)) % N # TODO maybe use gmpy2 for this
        self.presigning_data[I].h_t_i = h_t_i


    '''
    Phase 2 involves computing the signature share on a dummy message,
    and broadcasting the signature share.
    '''
    def subset_presigning_algorithm_phase_2(self):
        # Compute the signature share.
        signature_share = self.signature_share_generation(self.dummy_message)
        # Broadcast this signature share to all k-1 other computers in the group.
        for computer in self.I:
            if computer.id != self.id:
                computer.receive_presigning_sigma_I_t_i(signature_share)

    '''
    Phase 3 involves solving for verifying the signature shares,
    finding x_I via exhaustive search, and then setting D_I and S_I_t_i for this subset.
    '''
    def subset_presigning_algorithm_phase_3(self):
        global k
        # Check that we received a signature share from all k-1 other computers in the group.
        if len(self.presigning_data[self.I].received_sigma_I_t_i) != k-1:
            print "Didn't receive signature share on dummy message from k-1 other parties."
            #raise RuntimeError("Didn't receive signature share on dummy message from k-1 other parties.")

        # Verify each signature share.
        for sigma in self.presigning_data[self.I].received_sigma_I_t_i:
            if not self.signature_share_verification(sigma):
                print "Invalid signature on dummy message in subset presigning."
                #raise RuntimeError("Invalid signature on dummy message in subset presigning.")

        # If everything checks out, then continue on with the algorithm.

        # Find x_I
        # Set D_I and S_I_t_i



    ###############################################################
    # Stuff for the Signature Share Generation and Verification
    ###############################################################

    '''
    Given a message and the relevant set of k parties,
    returns a tuple containing a signature and a proof.
    '''
    def signature_share_generation(self, m):
        pass

    '''
    Given a tuple sigma_I_t_i (using same name as in the paper) that
    contains a signature and a proof,
    verify that the proof holds, and return True or False.
    '''
    def signature_share_verification(self, sigma):
        return True


    ##############################################
    # Stuff for the Share Combining (6.2.5)
    ##############################################

    '''
    Assuming we have already received the sigmas from the
    other k-1 parties, we will now combine the shares and
    return the appropriate signature for the desired message.
    '''
    def combine_signatures(self):
        pass

#############################################
# Testing Area
#############################################

network = Network(range(3))
network.sign("blah")
print
network.nodes[5].change_choice(True)
network.sign("bloop")

