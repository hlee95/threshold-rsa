import random
import gmpy2
def getRandomPrime(start,end):
    i = random.randint(start,end) #better random nunber generator 
    while not gmpy2.is_prime(i):
        i +=1
    return i

