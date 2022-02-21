import math
import random
from abc import ABC, abstractmethod
from scheme import *
from decimal import *
import numpy as np

def toBitOrder(number, precision=None):
    # Bit order is little endian (LSB first)
    fstring = "{0:b}"
    if precision is not None:
        fstring = "{0:0" + str(precision) + "b}"
    return [int(b) for b in fstring.format(number)[::-1]]

class SymmetricDGHV(HomomorphicEncryptionScheme):
    def __init__(self, l):
        self.lmbda = l
        self.keyGen()

    def keyGen(self):
        self.N = self.lmbda
        self.P = self.lmbda ** 2
        self.Q = self.lmbda ** 5
        # Key is random P-bit odd integer
        lowbound = 2**(self.P - 2)
        highbound = 2**(self.P - 1) - 1
        halfkey = random.randint(lowbound, highbound)
        # Force key in range, odd
        self.key = (halfkey << 1) + 1
    
    def encrypt(self, m):
        return self.encryptLen(m, self.N)

    def encryptLen(self, m, bitlen):
        # N-bit integer even/odd depending on m
        message = (random.randint(2**(bitlen-2), 2**(bitlen-1) - 1) << 1) + m
        # Random Q-bit noise
        q = random.randint(2**(self.Q-1), 2**self.Q) - 1
        return message + self.key*q

    def decrypt(self, c):
        return (c % self.key) % 2
    
    def add(self, c1, c2):
        return c1 + c2

    def sub(self, c1, c2):
        return c1 - c2

    def mult(self, c1, c2):
        return c1 * c2

class AsymmetricDGHV(SymmetricDGHV):
    def keyGen(self):
        super().keyGen()
        self.secretkey = self.key
        # Encryptions of 0, bitlen specified to limit noise
        # 15 is arbitrary number, doesn't matter, needs to be at least 2
        parent = super()
        self.publickey = [parent.encryptLen(0, 3) for i in range(15)]

    def encrypt(self, m):
        # Choose random subset of size 4
        index = np.random.choice(np.arange(len(self.publickey)), 4, replace=False)

        # Sum subset with bit
        return m + sum([self.publickey[i] for i in index])

    # Decrypt is identical to symmetric scheme no need to define here
    # Add, sub, mult are all identical as well

class BootstrappableDGHV(AsymmetricDGHV):
    def generateSSP(self, size, subsetSize, sumto):
        average = sumto/Decimal(size)
        sspSet = [Decimal(random.random()) * 2 * average for i in range(size)]

        # choose subset
        index = np.random.choice(np.arange(size), subsetSize, replace=False)
        total = sum([sspSet[i] for i in index])
        diff = (sumto - total)/Decimal(subsetSize)
        sspSet = [v+diff for v in sspSet]

        # Calculating Hamming weight
        subset = [int(i in index) for i in range(size)]
        return (subset, sspSet)

    def keyGen(self):
        # Compute public key and secret key as before
        super().keyGen()
        # Set appropriate decimal precision
        getcontext().prec = self.Q
        # Generate subset sum that adds to 1/secretkey
        tot = (Decimal(1)/Decimal(self.secretkey))
        # Size of subset parameter
        self.alpha = math.floor(self.lmbda / math.log2(self.lmbda))
        # Generate subset to be half of total set
        self.newsecret, self.newpublic = self.generateSSP(2 * self.alpha, self.alpha, tot)

    def postProcess(self, c):
        # Adjust ciphertext after any computation to simplify decryption
        # Element-wise product of cipher and public key set
        return [Decimal(c) * Decimal(y) for y in self.newpublic]

    def encrypt(self, m):
        # Encrypt with parent
        c = super().encrypt(m)
        # Post process
        cy = self.postProcess(c)
        # Return c and cy
        return (c, cy)

    def decrypt(self, c):
        # Find subset sum
        cipher = c[0]
        cy = c[1]
        x = round(sum([cy[i] if v > 0 else 0 for i, v in enumerate(self.newsecret)]))
        # XOR LSB's
        return (cipher & 1) ^ (x & 1)

    def add(self, c1, c2):
        newc = super().add(c1[0], c2[0])
        sy = self.postProcess(newc)
        return (newc, sy)

    def sub(self, c1, c2):
        newc = super().sub(c1[0], c2[0])
        sy = self.postProcess(newc)
        return (newc, sy)

    def mult(self, c1, c2):
        newc = super().mult(c1[0], c2[0])
        sy = self.postProcess(newc)
        return (newc, sy)

if __name__ == "__main__":
    # Some tests
    schemes = [SymmetricDGHV(4), AsymmetricDGHV(4), BootstrappableDGHV(4)]
    for scheme in schemes:
        print(f"Testing scheme {scheme}")
        # Check that bit encryption works
        print("Testing bit encryption")
        for bit in range(0, 2):
            expected = bit
            cipher = scheme.encrypt(bit)
            actual = scheme.decrypt(cipher)
            assert expected == actual
        # Test basic operators
        print("Testing primitive operations (XOR/AND)")
        for bit1 in range(0, 2):
            for bit2 in range(0, 2):
                expected = bit1 ^ bit2
                encrypted1 = scheme.encrypt(bit1)
                encrypted2 = scheme.encrypt(bit2)
                encryptedActual = scheme.add(encrypted1, encrypted2)
                actual = scheme.decrypt(encryptedActual)
                print(f"{bit1} ^ {bit2} = {expected} | {actual}")
                assert expected == actual
                expected = bit1 & bit2
                encrypted1 = scheme.encrypt(bit1)
                encrypted2 = scheme.encrypt(bit2)
                encryptedActual = scheme.mult(encrypted1, encrypted2)
                actual = scheme.decrypt(encryptedActual)
                print(f"{bit1} & {bit2} = {expected} | {actual}")
                assert expected == actual

