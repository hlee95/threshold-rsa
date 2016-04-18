# global variables
# n = number of computers in the network
n = 10
# k = number of people who have to agree
k = 4
# M = A prime Number where M > N


class Network:
    def __init__(self, sayingYes = []):
        self.nodes = set()
        for i in range(n):
            if i in sayingYes:
                self.nodes.add(Computer(True))
            else:
                self.nodes.add(Computer(False))
    def getNodes(self):
        retuern self.nodes

class Computer:
    def __init__(self, agree):
        self.agree = agree
    def changeChoice(self, agree):
        self.agree = agree


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


# subset Presigning Algorythm


# Signature Share Generation Algorithm


# Signiture Share Verfication Algorithm


# Share Combination Algorithm



        

    
