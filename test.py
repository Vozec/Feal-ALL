from Feal_NX.utils import *
from Feal_NX.cipher import *

# Test from https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-3e.pdf

# Function test  'f'
assert [0x10,0x04,0x10,0x44] == F([0x00,0xff,0xff,0x00],[0xff,0xff])

# Function test 'fk'
assert [0x10,0x04,0x10,0x44] == Fk([0x00,0x00,0x00,0x00],[0x00,0x00,0x00,0x00])

# Function test 'S1'
assert S1(0b10011,0b11110010) == 0b00011000

# Function test 'key_generation'
K = bytes([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0XEF,
		   0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0XEF])

assert Feal_NX(key = K,rounds = 32).subkey == [
	0x75,0x19,0x71,0xf9,0x84,0xe9,0x48,0x86,
	0x88,0xe5,0x52,0x3b,0x4e,0xa4,0x7a,0xde,
	0xfe,0x40,0x5e,0x76,0x98,0x19,0xee,0xac,
	0x1b,0xd4,0x24,0x55,0xdc,0xa0,0x65,0x3b,
	0x3e,0x32,0x46,0x52,0x1c,0xc1,0x34,0xdf,
	0x77,0x8b,0x77,0x1d,0xd3,0x24,0x84,0x10,
	0x1c,0xa8,0xbc,0x64,0xa0,0xdb,0xbd,0xd2,
	0x1f,0x5f,0x8f,0x1c,0x6b,0x81,0xb5,0x60,
	0x19,0x6a,0x9a,0xb1,0xe0,0x15,0x81,0x90,
	0x9f,0x72,0x66,0x43,0xad,0x32,0x68,0x3a
]

# Function test 'encrypt'
P = bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])
assert Feal_NX(key = K,rounds = 32).encrypt(P) == bytes([0x9c,0x9b,0x54,0x97,0x3d,0xf6,0x85,0xf8])

# Function test 'decrypt'
C = bytes([0x9c,0x9b,0x54,0x97,0x3d,0xf6,0x85,0xf8])
assert Feal_NX(key = K,rounds = 32).decrypt(C) == bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])