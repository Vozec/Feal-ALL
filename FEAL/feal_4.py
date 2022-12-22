from FEAL.utils import *

class Feal_4():
	def __init__(self,key):
		assert len(key) == 8, 'Key must be 8 characters.'
		self.N = 4
		self.key = key
		self.subkey = self.key_generation(key)
		assert len(self.subkey) == (self.N + 2)*4

	def key_generation(self,key,rounds=4):
		# https://link.springer.com/content/pdf/10.1007/3-540-38424-3_46.pdf
		subkeys = [0] * (rounds//2+4)

		Kl,Kr   = key[:8],[0]*8
		Kr1,Kr2 = Kr[:4],Kr[4:]
		Qr 		= xor(Kr1,Kr2)

		A0,B0 	= Kl[:4],Kl[4:]
		D0 = [0]*4
		for i in range(rounds//2+4):
			if(i % 3 == 1):		xored = xor(B0,Kr1)
			elif(i % 3 == 0):	xored = xor(B0,Qr)
			else:				xored = xor(B0,Kr2)
			xored = xor(xored, D0) if i > 0 else xored
			D0 = A0[0:4]
		
			b = A0
			A0 = Fk(A0, xored)
		
			subkeys[4 * i: 4 * i + 2] = A0[0:2]
			subkeys[4 * i + 2: 4 * i + 4] = A0[2:4]
			A0, B0 = B0, A0

		return subkeys

	# # http://www.theamazingking.com/images/crypto-feal2.JPG
	def encrypt(self,data):
		pad   = lambda data : data + bytes([0x00 for _ in range((8-len(data))%8)])
		split = lambda L_R:(L_R[:4],L_R[4:])
		result = []
		data = pad(data)

		for k in range(len(data)//8):
			bloc = data[k*8:(k+1)*8]
			L,R = split(bloc)

			L = xor(L,self.subkey[-2*4:-4])
			R = xor(R,self.subkey[-4:])
			R = xor(L,R)

			for i in range(self.N):
				L = xor(L,F1(xor(R,self.subkey[i*4:(i+1)*4])))
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
				L = xor(L,F1(xor(self.subkey[i*4:(i+1)*4],R)))
			
			R = xor(R,L)
			R = xor(R,self.subkey[-4:])
			L = xor(L,self.subkey[-2*4:-4])

			result += L+R
		return bytes(result).strip(b'\x00')

