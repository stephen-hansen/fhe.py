import math
import random
from abc import ABC, abstractmethod
from scheme import *
from decimal import *
import numpy as np

def lsb(c):
    return c & 1

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
        # N-bit integer even/odd depending on m
        m = (random.randint(2**(self.N-2), 2**(self.N-1) - 1) << 1) + m
        # Random Q-bit noise
        q = random.randint(2**(self.Q-1), 2**self.Q) - 1
        return m + self.key*q

    def decrypt(self, c):
        return (c % self.key) % 2
    
    def add(self, c1, c2):
        return c1 + c2

    def sub(self, c1, c2):
        return c1 - c2

    def mult(self, c1, c2):
        return c1 * c2

if __name__ == "__main__":
    # Some tests
    scheme = SymmetricDGHV(4)
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

