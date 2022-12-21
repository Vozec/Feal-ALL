from Feal_NX.cipher import *

engine = Feal_NX(
	key = b'ThisIsASecretKey',
	rounds = 32
)

msg = b'Hello This Is Vozec !'

ct = engine.encrypt(msg)
print('Cipher Text: %s'%ct)

pt = engine.decrypt(ct)
print('Plain  Text: %s'%pt)
