from abc import ABC, abstractmethod

class EncryptionScheme(ABC):
    @abstractmethod
    def keyGen(self, lmbda):
        # lmbda is a security parameter
        pass

    @abstractmethod
    def encrypt(self, p, m):
        # p is the key, m is a plaintext bit
        # returns a ciphertext
        pass

    @abstractmethod
    def decrypt(self, p, c):
        # p is the key, c is a ciphertext
        # returns a plaintext
        pass

class HomomorphicEncryptionScheme(EncryptionScheme):
    @abstractmethod
    def add(self, c1, c2):
        # c1 and c2 are ciphertexts
        # returns the ciphertext c1 + c2
        pass

    @abstractmethod
    def sub(self, c1, c2):
        # c1 and c2 are ciphertexts
        # returns the ciphertext c1 - c2
        pass

    @abstractmethod
    def mult(self, c1, c2):
        # c1 and c2 are ciphertexts
        # returns the ciphertext c1 * c2
        pass

    @abstractmethod
    def evaluate(self, f, *cs):
        # f is a boolean function, cs are ciphertext inputs
        # returns the ciphertext f(c1, ..., ct)
        pass

