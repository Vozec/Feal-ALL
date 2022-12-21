from FEAL.feal_nx import *
from FEAL.feal_n import *

msg = b'Hello This Is Vozec !'

engine1 = Feal_NX(key = b'ThisIsASecretKey',rounds = 32)
engine2 = Feal_N(key = b'Secpass!',rounds = 4)

print('\n## FEAL NX ##')
ct = engine1.encrypt(msg)
print('Cipher Text: %s'%ct)
pt = engine1.decrypt(ct)
print('Plain  Text: %s'%pt)



print('\n## FEAL N ##')
ct = engine2.encrypt(msg)
print('Cipher Text: %s'%ct)
pt = engine2.decrypt(ct)
print('Plain  Text: %s'%pt)
