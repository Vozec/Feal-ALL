from FEAL.utils import *

class Feal_N():
	def __init__(self,rounds,key):
		assert rounds > 0, 'Number of Round must be > 0'
		assert len(key) == 8, 'Key must be 8 characters.'

		self.N = rounds
		self.key = key
		self.subkey = self.key_generation(key,rounds)
		assert len(self.subkey) == self.N + 2

	def key_generation(self,key,rounds):
		return 	[[244, 54, 227, 83],
				[66, 137, 49, 218],
				[111, 101, 86, 6],
				[33, 240, 170, 239],
				[114, 172, 23, 194],
				[73, 207, 166, 32]]		
		
	# http://www.theamazingking.com/images/crypto-feal2.JPG
	def encrypt(self,data):
		pad   = lambda data : data + bytes([0x00 for _ in range((8-len(data))%8)])
		split = lambda L_R:(L_R[:4],L_R[4:])
		result = []
		data = pad(data)

		for k in range(len(data)//8):
			bloc = data[k*8:(k+1)*8]
			L,R = split(bloc)

			L = xor(L,self.subkey[-2])
			R = xor(R,self.subkey[-1])
			R = xor(L,R)
			for i in range(self.N):
				L = xor(L,F1(xor(R,self.subkey[i])))
				L,R = R,L
			
			L,R = R,L
			R = xor(R,L)
			result += L+R

		return bytes(result)
					
	def decrypt(self,data):
		split = lambda L_R:(L_R[:4],L_R[4:])
		result = []
		for k in range(len(data)//8):
			bloc = data[k*8:(k+1)*8]
			L,R = split(bloc)

			R = xor(L,R)
			L,R = R,L
			for i in reversed(range(self.N)):
				L,R = R,L
				L = xor(L,F1(xor(self.subkey[i],R)))
			
			R = xor(R,L)
			R = xor(R,self.subkey[-1])
			L = xor(L,self.subkey[-2])

			result += L+R
		return bytes(result).strip(b'\x00')

