import math
import random

import numpy as np
from gmpy2 import invert

from src.affine_encoder import AffineEncoder


class RandomizedIterativeAffineCipher(object):
    def __init__(self):
        pass

    @staticmethod
    def generate_keypair(key_size=1024, key_round=5, encode_precision=2 ** 100):
        key_size_array = np.linspace(start=int(key_size / 2), stop=key_size, num=key_round)
        key_size_array = np.floor(key_size_array).astype(np.int64)
        n_array = [0 for _ in range(key_round)]
        a_array = [0 for _ in range(key_round)]
        i = 0
        for key_size in key_size_array:
            n = random.SystemRandom().getrandbits(key_size)
            a_ratio = random.SystemRandom().random()
            a = 0
            while True:
                a_size = int(key_size * a_ratio)
                if a_size is 0:
                    continue
                a = random.SystemRandom().getrandbits(a_size)
                if math.gcd(n, a) == 1:
                    break
            n_array[i] = n
            a_array[i] = a
            i = i + 1

        # pick a generator and a scalar
        g = random.SystemRandom().randint(1, n_array[0] - 1)
        x = random.SystemRandom().getrandbits(160)
        return RandomizedIterativeAffineCipherKey(a_array, n_array, g, x, encode_precision=encode_precision)


class RandomizedIterativeAffineCipherKey(object):
    def __init__(self, a_array, n_array, g, x, encode_precision=2 ** 100):
        if len(a_array) != len(n_array):
            raise ValueError("a_array length must be equal to n_array")
        self.a_array = a_array
        self.n_array = n_array
        self.key_round = len(self.a_array)
        self.a_inv_array = self.mod_inverse()
        self.affine_encoder = AffineEncoder(mult=encode_precision)
        self.g = g
        self.x = x
        self.h = g * x % self.n_array[0]

    def encrypt(self, plaintext):
        return self.raw_encrypt(self.affine_encoder.encode(plaintext))

    def decrypt(self, ciphertext):
        if isinstance(ciphertext, int) is True and ciphertext is 0:
            return 0
        return self.affine_encoder.decode(self.raw_decrypt(ciphertext))

    def raw_encrypt(self, plaintext):
        plaintext = self.encode(plaintext)
        ciphertext = RandomizedIterativeAffineCiphertext(plaintext[0], plaintext[1], self.n_array[-1])
        for i in range(self.key_round):
            ciphertext = self.raw_encrypt_round(ciphertext, i)
        return ciphertext

    def raw_decrypt(self, ciphertext):
        plaintext = ciphertext.cipher2
        for i in range(self.key_round):
            plaintext = self.raw_decrypt_round(plaintext, i)
        return self.decode(RandomizedIterativeAffineCiphertext(ciphertext.cipher1, plaintext, ciphertext.n_final))

    def encode(self, plaintext):
        y = random.SystemRandom().getrandbits(160)
        return [y * self.g % self.n_array[0], (plaintext + y * self.h) % self.n_array[0]]

    def decode(self, ciphertext):
        intermediate_result = (ciphertext.cipher2 - self.x * ciphertext.cipher1) % self.n_array[0]
        if intermediate_result > self.n_array[0] * 0.9:
            return intermediate_result - self.n_array[0]
        else:
            return intermediate_result

    def raw_encrypt_round(self, plaintext, round_index):
        return RandomizedIterativeAffineCiphertext(
            plaintext.cipher1,
            (self.a_array[round_index] * plaintext.cipher2) % self.n_array[round_index],
            plaintext.n_final
        )

    def raw_decrypt_round(self, ciphertext, round_index):
        plaintext = (self.a_inv_array[self.key_round - 1 - round_index]
                     * (ciphertext % self.n_array[self.key_round - 1 - round_index])) \
                    % self.n_array[self.key_round - 1 - round_index]
        if plaintext / self.n_array[self.key_round - 1 - round_index] > 0.9:
            return plaintext - self.n_array[self.key_round - 1 - round_index]
        else:
            return plaintext

    def mod_inverse(self):
        a_array_inv = [0 for _ in self.a_array]
        for i in range(self.key_round):
            a_array_inv[i] = int(invert(self.a_array[i], self.n_array[i]))
        return a_array_inv


class RandomizedIterativeAffineCiphertext(object):
    def __init__(self, cipher1, cipher2, n_final):
        self.cipher1 = cipher1
        self.cipher2 = cipher2
        self.n_final = n_final

    def __add__(self, other):
        if isinstance(other, RandomizedIterativeAffineCiphertext):
            return RandomizedIterativeAffineCiphertext(
                (self.cipher1 + other.cipher1) % self.n_final,
                (self.cipher2 + other.cipher2) % self.n_final,
                self.n_final
            )
        elif type(other) is int and other == 0:
            return self
        else:
            raise TypeError("Addition only supports AffineCiphertext and initialization with int zero")

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        return self + (other * -1)

    def __rsub__(self, other):
        return other + (self * -1)

    def __mul__(self, other):
        if type(other) is int and other is -1:
            return RandomizedIterativeAffineCiphertext(
                (self.cipher1 * other) % self.n_final,
                (self.cipher2 * other) % self.n_final,
                self.n_final)
        else:
            raise TypeError("Multiplication only supports int -1.")

    def __rmul__(self, other):
        return self.__mul__(other)
