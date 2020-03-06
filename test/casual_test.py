from src.randomized_iterative_affine_cipher import RandomizedIterativeAffineCipher

key = RandomizedIterativeAffineCipher.generate_keypair(key_round=5)

a = 1123.53125
b = -513241.7312651
A = key.encrypt(a)
print("decrypted a = " + str(key.decrypt(A)))
B = key.encrypt(b)
print("decrypted b = " + str(key.decrypt(B)))
C = A + B
c = key.decrypt(C)
print(A.__dict__)
print(B.__dict__)
print(C.__dict__)
print("real c = " + str(a + b))
print("computed c = " + str(c))
