# Feal-N(*X*)
This tool is the implementation of the FEAL NX and FEAL N encryption   
Feal NX is the latest version of FEAL encryption,supporting 128 bits key .
Feal N is a similar version , restricte to 64 bits keys.
- *N is the number of rounds.*

*L'outil est basé sur ce papier : [FEAL-NX SPECIFICATIONS 
](https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-3e.pdf)*  
ainsi que l'article de TheAmazingKing : [ici](http://www.theamazingking.com/crypto-feal.php)
*(Toutes les étapes du code Feal NX sont détaillé pour comprendre le chiffrement avec le papier à coté)*

## Example :

```python
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
```

## Result :
```bash
$ python3 example.py
## FEAL NX ##
Cipher Text: b'\x96\xb1\xfd\x97\xa3>g\x1c\x03\xe1\xb0\xb1\x1e\x0cC\x10\xd2y\xea,\xc5\xde\x12\xb5'
Plain  Text: b'Hello This Is Vozec !'

## FEAL N ##
Cipher Text: b'\xad+;7\xa2]\xe3\xf0\xfaZ\xefs=\xc8\xbb-\x07\x1a\xb5\xd91\xf0\x1e\x82'
Plain  Text: b'Hello This Is Vozec !'
```

## Test : 
Tous les tests présenté dans le pdf pour feal_nx sont effectués dans *test.py*
