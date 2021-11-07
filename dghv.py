import random
from .scheme import *

class DGHV(HomomorphicEncryptionScheme):
    def keyGen(self, lmbda):
        self.N = lmbda
        self.P = lmbda ** 2
        self.Q = lmbda ** 5
        # Key is random P-bit odd integer
        key = random.randrange(1, 2 ** self.P, 2)
        return key

    def encrypt(self, p, m):
        # m' is random N-bit number such that m' = m mod 2
        m_ = random.randrange(m, 2 ** self.N, 2)
        # c <- m' + pq
        # q is a random Q-bit number
        q = random.randrange(0, 2 ** self.Q, 1)
        c = m_ + p*q
        return c

    def decrypt(self, p, c):
        # c' is (c mod p) in (-p/2, p/2)
        c_ = c % p # c_ in range [0, p)
        if c_ >= p//2:
            # Range from [p/2, p) goes to [-p/2, 0)
            # Union'd with range [0, p/2) gives correct range [-p/2, p/2).
            c_ -= p
        return c_ % 2

    def add(self, c1, c2):
        return c1 + c2

    def sub(self, c1, c2):
        return c1 - c2

    def mult(self, c1, c2):
        return c1 * c2

    def evaluate(self, f, *cs):
        # Assuming f is a Circuit with gates properly set up...
        pass

