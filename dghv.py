import random
from abc import ABC, abstractmethod
from scheme import *

def toBitOrder(number, precision=None):
    # Bit order is little endian (LSB first)
    fstring = "{0:b}"
    if precision is not None:
        fstring = "{0:0" + str(precision) + "b}"
    return [int(b) for b in fstring.format(number)[::-1]]

class DGHV(HomomorphicEncryptionScheme):
    def keyGen(self, lmbda):
        self.N = lmbda
        self.P = lmbda ** 2
        self.Q = lmbda ** 5
        # Key is random P-bit odd integer
        self.secretKey = random.randrange(2 ** (self.P - 1) + 1, 2 ** self.P, 2)
        self.publicKey = [self.encryptWithSecret(self.secretKey, 0) for _ in range(lmbda)]
        return self.publicKey, self.secretKey

    def encrypt(self, pubKey, m):
        subset = random.sample(pubKey, random.randint(1, len(pubKey)-1))
        # In theory this is still 0 mod p
        subsetSum = sum(subset)
        return m + subsetSum

    def encryptWithSecret(self, p, m):
        # m' is random N-bit number such that m' = m mod 2
        m_ = random.randrange(2 ** (self.N - 1) + m, 2 ** self.N, 2)
        assert (m_ % 2) == m
        # c <- m' + pq
        # q is a random Q-bit number (noise)
        q = random.randrange(2 ** (self.Q - 1), 2 ** self.Q, 1)
        c = m_ + p*q
        # Verify that the output can be decrypted correctly
        assert (c % p) == m_
        return c

    def encryptNumber(self, p, number, precision=None):
        ms = toBitOrder(number, precision)
        ciphers = []
        for m in ms:
            ciphers.append(self.encrypt(p, m))
        return ciphers

    def decrypt(self, p, c):
        # c' is (c mod p) in (-p/2, p/2)
        c_ = c % p # c_ in range [0, p)
        #if c_ >= p//2:
        #    # Range from [p/2, p) goes to [-p/2, 0)
        #    # Union'd with range [0, p/2) gives correct range [-p/2, p/2).
        #    c_ -= p
        return c_ % 2

    def decryptNumber(self, p, cs):
        # Ciphers are little endian
        i = 0
        result = 0
        length = len(cs)
        for i in range(length):
            bit = self.decrypt(p, cs[i])
            result += bit * (2 ** i)
        return result

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
        bits = toBitOrder(c1) # Get bits of c1 for encrypt
        c1_ = [self.encrypt(pk, b) for b in bits]
        args = sk + c1_
        c = self.evaluate(pk, D, *args)
        return c

class Gate(ABC):
    @abstractmethod
    def run(self, scheme, *inputs):
        pass

class XORGate(Gate):
    def run(self, scheme, *inputs):
        return scheme.add(inputs[0], inputs[1])

class ANDGate(Gate):
    def run(self, scheme, *inputs):
        return scheme.mult(inputs[0], inputs[1])

class ORGate(Gate):
    def run(self, scheme, *inputs):
        andGate = ANDGate()
        xorGate = XORGate()
        andResult = andGate.run(scheme, inputs[0], inputs[1])
        xorResult = xorGate.run(scheme, inputs[0], inputs[1])
        return xorGate.run(scheme, xorResult, andResult)

class NANDGate(Gate):
    def run(self, scheme, *inputs):
        andGate = ANDGate()
        andResult = andGate.run(scheme, inputs[0], inputs[1])
        xorGate = XORGate()
        encrypted1 = scheme.encrypt(scheme.publicKey, 1)
        return xorGate.run(scheme, encrypted1, andResult)

class FullAdder(Gate):
    def run(self, scheme, *inputs):
        andGate = ANDGate()
        orGate = ORGate()
        xorGate = XORGate()
        a = inputs[0]
        b = inputs[1]
        carryIn = inputs[2]
        xorResult = xorGate.run(scheme, a, b)
        sumOutput = xorGate.run(scheme, xorResult, carryIn)
        andResult1 = andGate.run(scheme, a, b)
        andResult2 = andGate.run(scheme, carryIn, xorResult)
        carryOut = orGate.run(scheme, andResult1, andResult2)
        return sumOutput, carryOut

def addernbit(scheme, n, *ciphers):
    # Ciphers must be in order [A1, A2, ..., An, B1, B2, ..., Bn]
    a = []
    b = []
    for i in range(n):
        a.append(ciphers[i])
        b.append(ciphers[i+n])
    adder = FullAdder()
    cIn = scheme.encrypt(scheme.publicKey, 0)
    r = []
    for i in range(n):
        ri, cIn = adder.run(scheme, a[i], b[i], cIn)
        r.append(ri)
    return r

if __name__ == "__main__":
    # Some tests
    scheme = DGHV()
    publicKey, secretKey = scheme.keyGen(2)
    # Check that bit encryption works
    print("Testing bit encryption")
    for bit in range(0, 2):
        expected = bit
        cipher = scheme.encrypt(publicKey, bit)
        actual = scheme.decrypt(secretKey, cipher)
        assert expected == actual
    # Test basic operators
    print("Testing primitive operations (XOR/AND)")
    for bit1 in range(0, 2):
        for bit2 in range(0, 2):
            expected = bit1 ^ bit2
            encrypted1 = scheme.encrypt(publicKey, bit1)
            encrypted2 = scheme.encrypt(publicKey, bit2)
            encryptedActual = scheme.add(encrypted1, encrypted2)
            actual = scheme.decrypt(secretKey, encryptedActual)
            print(f"{bit1} ^ {bit2} = {expected} | {actual}")
            assert expected == actual
            expected = bit1 & bit2
            encrypted1 = scheme.encrypt(publicKey, bit1)
            encrypted2 = scheme.encrypt(publicKey, bit2)
            encryptedActual = scheme.mult(encrypted1, encrypted2)
            actual = scheme.decrypt(secretKey, encryptedActual)
            print(f"{bit1} & {bit2} = {expected} | {actual}")
            assert expected == actual
    # Test some additions
    print("Testing addition circuit evaluation")
    for a in range(0, 2):
        for b in range(0, 2):
            expected = a + b
            encryptedA = scheme.encryptNumber(publicKey, a, precision=2)
            encryptedB = scheme.encryptNumber(publicKey, b, precision=2)
            args = encryptedA + encryptedB
            encryptedSum = scheme.evaluate(addernbit, 2, *args)
            actual = scheme.decryptNumber(secretKey, encryptedSum)
            print(f"{a} + {b} = {expected} | {actual}")
            assert expected == actual

