import math
import random
from abc import ABC, abstractmethod
from scheme import *
from circuit import *
from decimal import *
import numpy as np

def toBitOrder(number, precision=None):
    # Bit order is little endian (LSB first)
    fstring = "{0:b}"
    if precision is not None:
        fstring = "{0:0" + str(precision) + "b}"
    return [int(b) for b in fstring.format(number)][::-1]

def toBitOrderFloat(number, places):
    res = []
    num = 1
    for x in range(1+places):
        if (num <= number):
            number -= Decimal(num)
            res.append(1)
        else:
            res.append(0)
        num /= 2.0
    return res[::-1]

class SymmetricDGHV(HomomorphicEncryptionScheme):
    def __init__(self, l):
        self.lmbda = l
        self.keyGen()

    def keyGen(self):
        self.N = self.lmbda
        self.P = self.lmbda ** 4 # modified
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
        #message = m
        message = (random.randint(2**(bitlen-2), 2**(bitlen-1) - 1) << 1) + m
        # Random Q-bit noise
        q = random.randint(2**(self.Q-1), 2**self.Q - 1)
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
        getcontext().prec = self.Q * 40
        # Generate subset sum that adds to 1/secretkey
        tot = (Decimal(1)/Decimal(self.secretkey))
        # Size of subset parameter
        self.alpha = math.floor(self.lmbda / math.log2(self.lmbda))
        # Generate subset to be half of total set
        self.newsecret, self.newpublic = self.generateSSP(2 * self.alpha, self.alpha, tot)

    def postProcess(self, c):
        # Adjust ciphertext after any computation to simplify decryption
        # Element-wise product of cipher and public key set
        return [((Decimal(c)) * (Decimal(y))) % 2 for y in self.newpublic]

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

class DecryptCircuit():
    def __init__(self, scheme):
        # Step 1, encrypt every bit of secret key
        self.scheme = scheme
        # A vector of bits
        key = scheme.newsecret
        self.encryptedkey = [scheme.encrypt(v) for v in key]

    def run(self, c):
        # Step 2, encrypt cipher again (bits)
        cipher_lsb = self.scheme.encrypt(toBitOrder(c[0])[0])
        # Inputs are doubly encrypted cipher (c) and encrypted bits
        # Step 3, element-wise product of cy and encrypted key with total sum
        cy = c[1]
        Theta = math.ceil(math.log2(self.scheme.alpha))+3
        enc_cy = []
        # First mask each cyi
        for i, v in enumerate(self.encryptedkey):
            cyi_bits = toBitOrderFloat(cy[i], Theta)
            enc_bits = [self.scheme.mult(v, self.scheme.encrypt(b)) for b in cyi_bits]
            enc_cy.append(enc_bits)
        # Ok now to do the sum
        total = enc_cy[0]
        for i in range(1, len(enc_cy)):
            add = enc_cy[i]
            carry = self.scheme.encrypt(0)
            newsum = []
            for j in range(len(add)):
                xor1 = self.scheme.add(total[j], add[j])
                newsum.append(self.scheme.add(xor1, carry))
                and1 = self.scheme.mult(carry, xor1)
                and2 = self.scheme.mult(add[j], total[j])
                # OR here is redundant, can just use XOR
                carry = self.scheme.add(and1, and2)
            total = newsum
        xbits = total[::-1]
        rounded_sum = self.scheme.add(xbits[0], xbits[1])
        # Step 4, lsb of cipher and x, xor
        return self.scheme.add(cipher_lsb, rounded_sum)

class DGHVGate(Gate):
    def __init__(self, scheme):
        super().__init__()
        self.scheme = scheme
        self.dc = DecryptCircuit(scheme)
    # After each run, recrypt
    def run(self):
        output = super().run()
        return output

    def recrypt(self):
        output = super().run()
        return self.dc.run(output)

# Circuit gates
class ToggleSwitch(Gate):
    def __init__(self, scheme):
        super().__init__()
        self.scheme = scheme
        self.on = self.scheme.encrypt(0)

    def toggle(self, val):
        self.on = self.scheme.encrypt(val)

    def runImpl(self, inputs):
        # ignore inputs
        return self.on

class ANDGate(DGHVGate):
    def __init__(self, scheme):
        super().__init__(scheme)

    def runImpl(self, inputs):
        # mult inputs
        val = inputs[0]
        for inp in inputs[1:]:
            val = self.scheme.mult(val, inp)
        return val

class XORGate(DGHVGate):
    def __init__(self, scheme):
        super().__init__(scheme)

    def runImpl(self, inputs):
        # add inputs
        val = inputs[0]
        for inp in inputs[1:]:
            val = self.scheme.add(val, inp)
        return val

class ORGate(DGHVGate):
    def __init__(self, scheme):
        super().__init__(scheme)
        self.and1 = ANDGate(scheme)
        self.xor1 = XORGate(scheme)
        self.xor2 = XORGate(scheme)
        # and1 and xor1 are inputs to xor2
        self.xor2.addInput(self.and1)
        self.xor2.addInput(self.xor1)
        # xor2 will be input to this program
        # so that calling "run" will call xor2
        # in turn, calls and1 and xor1
        self.inputConns.append(self.xor2)

    def addInput(self, gate):
        # Append to AND/XOR rather than gate itself
        self.and1.addInput(gate)
        self.xor1.addInput(gate)

    def runImpl(self, inputs):
        # inputs is result of xor2
        # just return it
        return inputs[0]

class FullAdder():
    def __init__(self, scheme):
        self.scheme = scheme
        self.toggleA = ToggleSwitch(scheme)
        self.toggleB = ToggleSwitch(scheme)
        self.toggleCarryIn = ToggleSwitch(scheme)
        # Build 1 bit adder
        xor1 = XORGate(scheme)
        xor1.addInput(self.toggleA)
        xor1.addInput(self.toggleB)

        and1 = ANDGate(scheme)
        and1.addInput(self.toggleA)
        and1.addInput(self.toggleB)

        xor2 = XORGate(scheme)
        xor2.addInput(xor1)
        xor2.addInput(self.toggleCarryIn)

        self.sum = xor2

        and2 = ANDGate(scheme)
        and2.addInput(xor1)
        and2.addInput(self.toggleCarryIn)

        or1 = XORGate(scheme)
        or1.addInput(and2)
        or1.addInput(and1)

        self.carryOut = or1

    def setValues(self, a, b, carryin):
        self.toggleA.toggle(a)
        self.toggleB.toggle(b)
        self.toggleCarryIn.toggle(carryin)

    def setEncryptedValues(self, a, b, carryin):
        self.toggleA.on = a
        self.toggleB.on = b
        self.toggleCarryIn.on = carryin

    def run(self):
        sumv = self.scheme.decrypt(self.sum.run())
        carryout = self.scheme.decrypt(self.carryOut.run())
        return (sumv, carryout)

    def runEnc(self):
        return self.sum.run(), self.carryOut.run()

class IntegerAdder():
    def __init__(self, scheme):
        self.scheme = scheme
        self.fullAdder = FullAdder(scheme)

    def setValues(self, a, b):
        # a, b are integers (not bit vectors)
        # encrypted handled automatically by full adder
        # n is precision (number of bits)
        n = math.floor(max(math.log2(a), math.log2(b))) + 1
        self.numA = toBitOrder(a, n)
        self.numB = toBitOrder(b, n)

    def run(self):
        # output precision will be n+1
        result = []
        carry = self.scheme.encrypt(0)
        for bitA, bitB in zip(self.numA, self.numB):
            bitAenc = self.scheme.encrypt(bitA)
            bitBenc = self.scheme.encrypt(bitB)
            self.fullAdder.setEncryptedValues(bitAenc, bitBenc, carry)
            s, carry = self.fullAdder.runEnc()
            result.append(s)
        result.append(carry)
        sumv = 0
        for bit in result[::-1]:
            sumv *= 2
            sumv += self.scheme.decrypt(bit)
        return sumv

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

    bootstrap = BootstrappableDGHV(4)
    print("Testing decrypt circuit")
    dc = DecryptCircuit(bootstrap)
    for bit in range(0, 2):
        expected = bit
        cipher1 = bootstrap.encrypt(bit)
        cipher2 = cipher1
        # run mult a bunch of times to generate large enough error
        for _ in range(40):
            cipher2 = bootstrap.mult(cipher2, bootstrap.encrypt(1))
        assert bootstrap.decrypt(cipher2) == expected
        cipher3 = dc.run(cipher2)
        actual = bootstrap.decrypt(cipher3)
        print(f"{bit} -> ... -> {actual}")
        assert expected == actual
        assert cipher2[0] > cipher1[0]
        assert (cipher3[0] % bootstrap.key) <= (cipher2[0] % bootstrap.key)
    print("Testing a 1-bit adder")
    fa = FullAdder(bootstrap)
    for a in range(0, 2):
        for b in range(0, 2):
            for cin in range(0, 2):
                sum_exp = (a ^ b) ^ cin
                cout_exp = ((a ^ b) & cin) | (a & b)
                fa.setValues(a, b, cin)
                sum_act, cout_act = fa.run()
                print(f"sum a={a} b={b} cin={cin}; EXP sum={sum_exp}, cout={cout_exp}; ACT sum={sum_act}, cout={cout_act}")
    print("Testing addition of 3 bit numbers")
    ia = IntegerAdder(bootstrap)
    for a in range(1, 2**3):
        for b in range(1, 2**3):
            sum_exp = a + b
            ia.setValues(a, b)
            sum_act = ia.run()
            if (sum_exp != sum_act):
                print(f"!!! sum a={a} b={b}; EXP sum={sum_exp}; ACT sum={sum_act}")
            else:
                print(f"sum a={a} b={b}; EXP sum={sum_exp}; ACT sum={sum_act}")
    print("Testing addition of LARGE numbers")
    a = 9223372036854775807
    b = 9223372036854775807
    ia.setValues(a,b)
    sum_exp = a+b
    sum_act = ia.run()
    # This test is expected to fail
    if (sum_exp != sum_act):
        print(f"!!! sum a={a} b={b}; EXP sum={sum_exp}; ACT sum={sum_act}")
    else:
        print(f"sum a={a} b={b}; EXP sum={sum_exp}; ACT sum={sum_act}")

