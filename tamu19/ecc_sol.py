from sage.all import *
from Crypto.Cipher import AES

p = 412220184797
A = 10717230661382162362098424417014722231813
B = 22043581253918959176184702399480186312

E = EllipticCurve(GF(p), [A, B])
G = E(56797798272, 349018778637)
Alice_Pub = E(61801292647, 228288385004)

Alice_Priv = G.discrete_log(Alice_Pub)
print("Alice Private key: " + str(Alice_Priv))

Bob_Pub = E(196393473219, 35161195210)
Bob_Priv = G.discrete_log(Bob_Pub)
print("Bob Private key: " + str(Bob_Priv))

share_1 = Alice_Pub * Bob_Priv
share_2 = Bob_Pub * Alice_Priv

print("Shared key (1): " + str(share_1))
print("Shared key (2): " + str(share_2))

x = share_1[0]
y = share_1[1]

data = open("enc_data", "rb").read()
print data

shared_key = str(x) + str(y)
print shared_key
cipher = AES.new(shared_key, AES.MODE_CBC, IV="\x00"*16)
ptxt = cipher.decrypt(data)

print ptxt

