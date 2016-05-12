import random
from operator import mul
n = 5
k = 2

def do_poly(a,x):
    total = 0
    for c in xrange(0,k):
        total += a[c] * pow(x,c)
    return total

def make_fs():
    ds = [random.randint(0,2**10) for i in range(n)]
    fs = [[0 for i in range(n)] for j in range(n)]
    for i in xrange(n):
        a = [ds[i]]+[random.randint(0,2**10) for it in range(k-1)]
        for j in range(n):
            fs[j][i] = do_poly(a,j+1)
    return (fs, ds)

def check((fs,ds)):
    ls = [reduce(mul,[float(j)/(j-i) for j in range(1,k+1) if j !=i]) for i in range(1,k+1)]
    ss = [sum(fs[i][k:])*ls[i] for i in range(k)]
    print sum(ss)==sum(ds[k:])
    print sum(ss)
    print sum(ds[k:])
    
#check(make_fs())

def check_lambda_int(k,i):
    total = 1
    for j in range(1,k+1):
        if j!=i:
            total *= j
    for j in range(1,k+1):
        if j!=i:
            total /= (j-i)
    if total != int(total):
        print total
#for k in range(1000):
#    for i in range(k):
#        check_lambda_int(k,i)        
