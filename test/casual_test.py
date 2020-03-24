from src.randomized_iterative_affine_cipher import RandomizedIterativeAffineCipher

key = RandomizedIterativeAffineCipher.generate_keypair(key_round=5)

scale = -3.1
a = 5.33
c = -3.55
scale_c = 2.5
A = key.encrypt(a)
B = A * scale
b = key.decrypt(B)
real_b = a * scale

print("real b = {}".format(real_b))
print("b = {}".format(b))

R = scale * key.encrypt(a) + scale_c * key.encrypt(c)
r = key.decrypt(R)
real_r = scale * a + scale_c * c

pass
