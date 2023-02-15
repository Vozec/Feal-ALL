# Feal-ALL
This tool is the implementation of the FEAL NX / FEAL N and FEAL-4 encryption    
Feal-NX is the latest version of FEAL encryption,supporting 128 bits key .  
Feal-N is a similar version , restricte to 64 bits keys.  
Feal-4 is similar to Feal-N with a small difference with the F-box & last xor at the end of the encypt function  
- *N is the number of rounds.*  

This tool is based on these papers : 
- [FEAL-NX SPECIFICATIONS](https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-3e.pdf)
- [The FEAL Cipher Family](https://link.springer.com/content/pdf/10.1007/3-540-38424-3_46.pdf)
- [L'article de TheAmazingKing](http://www.theamazingking.com/crypto-feal.php)

*(All the steps of the Feal NX code are detailed to understand the encryption with the paper next to it)*

## Example :

```python
from FEAL.feal_nx import *
from FEAL.feal_n import *
from FEAL.feal_4 import *

msg = b'Hello This Is Vozec !'

engine1 = Feal_NX(key = b'ThisIsASecretKey',rounds = 32)
engine2 = Feal_N(key = b'Secpass!',rounds = 8)
engine3 = Feal_4(key = b'Secpass!')


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



print('\n## FEAL 4 ##')
ct = engine3.encrypt(msg)
print('Cipher Text: %s'%ct)
pt = engine3.decrypt(ct)
print('Plain  Text: %s'%pt)
```

## Result :
```bash
$ python3 example.py
## FEAL NX ##
Cipher Text: b'\x96\xb1\xfd\x97\xa3>g\x1c\x03\xe1\xb0\xb1\x1e\x0cC\x10\xd2y\xea,\xc5\xde\x12\xb5'
Plain  Text: b'Hello This Is Vozec !'

## FEAL N ##
Cipher Text: b'e\x7f\xdaJz\xe8\x1a\x85\xcb\xbb\xfd\xe7=\x84a\xfdf\xeb\xfe[@4\x08\xe5'
Plain  Text: b'Hello This Is Vozec !'

## FEAL 4 ##
Cipher Text: b'\xef\x01\xc5&(r\xb6H4\xed\xe4\xe9u\xf3\xaf\x03\xe0\xd3a\xdf\x14\x81\xe3\x9c'
Plain  Text: b'Hello This Is Vozec !'
```

## Test : 
All tests presented in the pdf for feal_nx & feal_n are performed in *test.py*
