from abc import ABC, abstractmethod

class EncryptionScheme(ABC):
    @abstractmethod
    def keyGen(self):
        pass

    @abstractmethod
    def encrypt(self, m):
        # m is a plaintext bit
        # returns a ciphertext
        pass

    @abstractmethod
    def decrypt(self, c):
        # c is a ciphertext
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


