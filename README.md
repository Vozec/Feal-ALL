# Feal-NX
This tool is the implementation of the FEAL NX encryption   
Feal NX is the latest version of FEAL encryption, N is the number of rounds.

*L'outil est basé sur ce papier : [FEAL-NX SPECIFICATIONS 
](https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-3e.pdf)*  
- Toutes les étapes du code sont détaillé pour comprendre le chiffrement avec le papier à coté

## Example :

```python
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

```

## Result :
```bash
$ python3 example.py
Cipher Text: b'\x96\xb1\xfd\x97\xa3>g\x1c\x03\xe1\xb0\xb1\x1e\x0cC\x10\xd2y\xea,\xc5\xde\x12\xb5'
Plain  Text: b'Hello This Is Vozec !'
```

## Test : 
Tous les tests présenté dans le pdf précédent sont effectués dans *test.py*
