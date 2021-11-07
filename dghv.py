import random
from abc import ABC, abstractmethod
from scheme import *

class DGHV(HomomorphicEncryptionScheme):
    def keyGen(self, lmbda):
        self.N = lmbda
        self.P = lmbda ** 2
        self.Q = lmbda ** 5
        # Key is random P-bit odd integer
        self.key = random.randrange(1, 2 ** self.P, 2)
        return self.key

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
        # Call f, pass in the args and the scheme
        return f(self, *cs)

    def recrypt(self, pk, D, sk, c1):
        # pk is the new public key to encrypt into
        # D is the decryption circuit
        # sk is the secret key encrypted under pk (list of ciphertexts, 1 per bit)
        # c1 is the ciphertext
        bitsStr = "{0:b}".format(c1) # Get bits of c1 for encrypt
        c1_ = [self.encrypt(pk, int(b)) for b in bitsStr]
        args = sk + c1_
        c = self.evaluate(pk, D, *args)
        return c

class Gate(ABC):
    @abstractmethod
    def run(self, scheme, b1, b2):
        pass

class XORGate(Gate):
    def run(self, scheme, b1, b2):
        return scheme.add(b1, b2)

class ANDGate(Gate):
    def run(self, scheme, b1, b2):
        return scheme.multiply(b1, b2)

class ORGate(Gate):
    def run(self, scheme, b1, b2):
        andGate = ANDGate()
        xorGate = XORGate()
        andResult = andGate.run(scheme, b1, b2)
        xorResult = xorGate.run(scheme, b1, b2)
        return xorGate.run(xorResult, andResult)

class NANDGate(Gate):
    def run(self, scheme, b1, b2):
        andGate = ANDGate()
        andResult = andGate.run(scheme, b1, b2)
        xorGate = XORGate()
        encrypted1 = scheme.encrypt(scheme.key, 1)
        return xorGate.run(scheme, encrypted1, andResult)

if __name__ == "__main__":
    # Some tests
    scheme = DGHV()
    key = scheme.keyGen(5)
    for bit in range(0, 2):
        expected = bit
        cipher = scheme.encrypt(key, bit)
        actual = scheme.decrypt(key, cipher)
        assert expected == actual

