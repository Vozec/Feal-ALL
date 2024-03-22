def F(α: int, β: int) -> bytes:
	α0, α1, α2, α3 = int2bytes(α)
	β0, β1, β2, β3 = int2bytes(β)
	f1 = α1^β0					# f1 = α1 ⊕ β0
	f2 = α2^β1					# f2 = α2 ⊕ β1
	f1 = f1^α0					# f1 = f1 ⊕ α0
	f2 = f2^α3					# f2 = f2 ⊕ α3
	f1 = S1(f1,f2)				# f1 = S1(f1, f2)
	f2 = S0(f2,f1)				# f2 = S0(f2, f1)
	f0 = S0(α0,f1)				# f0 = S0(α0, f1)
	f3 = S1(α3,f2)				# f3 = S1(α3, f2) 
	return bytes2int([f0, f1, f2, f3])

def Fk(α: int, β: int) -> bytes:
	α0, α1, α2, α3 = int2bytes(α)
	β0, β1, β2, β3 = int2bytes(β)
	fk1 = α1^α0					# fK1 = α1 ⊕ α0
	fk2 = α2^α3					# fK2 = α2 ⊕ α3
	fk1 = S1(fk1, fk2^β0)		# fK1 = S1 (fK1, fK2 ⊕ β0)
	fk2 = S0(fk2, fk1^β1)		# fK2 = S0 (fK2, fK1 ⊕ β1)
	fk0 = S0(α0, fk1^β2)		# fK0 = S0 (α0, fK1 ⊕ β2)
	fk3 = S1(α3, fk2^β3)		# fK3 = S1 (α3, fK2 ⊕ β3)
	return [fk0, fk1, fk2, fk3]

def S1(X1:int, X2:int):
	return S0(X1,X2,k=1)

def S0(X1, X2, k:int = 0) -> int:
	def rot2(T,bit_block=8):
		return (T << 2)|(T >> (bit_block - 2))
	return rot2((X1 + X2 + k) % 256) % 256

def split(L_R: int) -> list[int]:
	return (L_R >> 32, L_R & ((1 << 32) - 1))

def join(L: int, R: int, k: int=8) -> int:
	return (L << k) | (R << 0)

def bytes2int(array: list[int]) -> int:
	return (array[0] << 24) | (array[1] << 16) | (array[2] << 8) | (array[3] << 0) 

def int2bytes(x: int, k:int = 4) -> bytes:
	return bytes([(x >> 8*_) & 0xFF for _ in range(k)])[::-1]



class Feal_NX():
	def __init__(self, rounds: int, key: bytes, Fbox = F) -> None:
		assert rounds > 0, 'Number of Round must be > 0'
		assert len(key) == 16, 'Key must be 16 characters.'

		self.N = rounds
		self.key = key
		self.subkey = self.key_schedule(key,rounds)
		self.F = Fbox

	def key_schedule(self, key: bytes, rounds: int) -> list:
		# https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-3e.pdf *(Fig. 2 Key schedule of FEAL-NX)*
		subkeys = []

		A0, B0 = split(int.from_bytes(key[:8], 'big'))
		Kr1, Kr2 = split(int.from_bytes(key[8:], 'big'))
		Qr = Kr1 ^ Kr2

		for i in range((rounds+8)//2):
			if(i % 3 == 1):		xored = B0^Kr1
			elif(i % 3 == 0):	xored = B0^Qr
			else:				xored = B0^Kr2
			xored = xored ^ D0 if i > 0 else xored
			D0, A0 = A0, Fk(A0, xored)

			subkeys.append(join(A0[0], A0[1]))
			subkeys.append(join(A0[2], A0[3]))

			A0, B0 = B0, bytes2int(A0)
		return subkeys

	def encrypt_bloc(self, bloc: int) -> list[bytes]:
		φ = 0 													# φ : zero block, 32-bits long
		L,R = split(bloc)  		 								# P is separated into L0 and R0 both 32-bits long

		L ^= join(*self.subkey[self.N+0:self.N+2], 16)			# (L0, R0) = (L0, R0) ⊕ (K32, K33, K34, K35 )
		R ^= join(*self.subkey[self.N+2:self.N+4], 16)
		L, R = L^φ, R^L 										# # (L0, R0) = (L0, R0) ⊕ ( φ , L0)

		for i in range(self.N):									# Lr-1 = Rr ⊕ f (Lr, Kr-1) & Rr-1 = Lr
			L ^= self.F(R, join(*self.subkey[i:i+2],16))
			L,R = R,L

		R, L = R^φ, L^R 										# (R32, L32 ) = (R32, L32 ) ⊕ ( φ , R32)
		R ^= join(*self.subkey[self.N+4:self.N+6],16)			# (R32, L32 ) = (R32, L32 ) ⊕ (K36, K37, K38, K39 )
		L ^= join(*self.subkey[self.N+6:self.N+8],16)

		return int2bytes((R << 32) | L, 8) 						# Ciphertext is given as (R32, L32)

	def decrypt_bloc(self, bloc: int) -> list[bytes]:
		φ = 0
		R,L = split(bloc)  		 								# P is separated into L0 and R0 both 32-bits long

		R ^= join(*self.subkey[self.N+4:self.N+6],16)			# (R32, L32 ) = (R32, L32 ) ⊕ (K36, K37, K38, K39 )
		L ^= join(*self.subkey[self.N+6:self.N+8],16)
		R, L = R^φ, L^R 										# (R32, L32 ) = (R32, L32 ) ⊕ ( φ , R32)

		for i in reversed(range(self.N)):						# Lr-1 = Rr ⊕ f (Lr, Kr-1) & Rr-1 = Lr
			L,R = R,L
			L ^= self.F(R, join(*self.subkey[i:i+2],16))

		L, R = L^φ, R^L											# (L0, R0) = (L0, R0) ⊕ ( φ , L0)
		R ^= join(*self.subkey[self.N+2:self.N+4], 16)			# (L0, R0) = (L0, R0) ⊕ (K32, K33, K34, K35 )
		L ^= join(*self.subkey[self.N+0:self.N+2], 16)

		return int2bytes((R << 32) | L, 8)


	def encrypt(self,data):
		pad   = lambda data : data + bytes([0x00 for _ in range((8-len(data))%8)])
		data = pad(data)

		result = []
		for k in range(len(data)//8):
			bloc = int.from_bytes(data[k*8:(k+1)*8], "big")	
			result += self.encrypt_bloc(bloc)

		return bytes(result)

	def decrypt(self,data):
		result = []
		for k in range(len(data)//8):
			bloc = int.from_bytes(data[k*8:(k+1)*8], "big")	
			result += self.decrypt_bloc(bloc)

		return bytes(result)



if __name__ == '__main__':
	# Test from https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-3e.pdf
	K = bytes([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0XEF,
			   0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0XEF])

	feal = Feal_NX(key=K, rounds=32)
	
	assert feal.subkey == [
		join(0x75,0x19),join(0x71,0xf9),join(0x84,0xe9),join(0x48,0x86),
		join(0x88,0xe5),join(0x52,0x3b),join(0x4e,0xa4),join(0x7a,0xde),
		join(0xfe,0x40),join(0x5e,0x76),join(0x98,0x19),join(0xee,0xac),
		join(0x1b,0xd4),join(0x24,0x55),join(0xdc,0xa0),join(0x65,0x3b),
		join(0x3e,0x32),join(0x46,0x52),join(0x1c,0xc1),join(0x34,0xdf),
		join(0x77,0x8b),join(0x77,0x1d),join(0xd3,0x24),join(0x84,0x10),
		join(0x1c,0xa8),join(0xbc,0x64),join(0xa0,0xdb),join(0xbd,0xd2),
		join(0x1f,0x5f),join(0x8f,0x1c),join(0x6b,0x81),join(0xb5,0x60),
		join(0x19,0x6a),join(0x9a,0xb1),join(0xe0,0x15),join(0x81,0x90),
		join(0x9f,0x72),join(0x66,0x43),join(0xad,0x32),join(0x68,0x3a)
	]

	P = bytes([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00])
	
	assert feal.encrypt(P) == bytes([0x9c,0x9b,0x54,0x97,0x3d,0xf6,0x85,0xf8])
	assert feal.decrypt(feal.encrypt(P)) == P
