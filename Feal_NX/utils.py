def xor(α,β):   
	assert len(α) == len(β), 'Input are not the same size.'
	return [α[_] ^ β[_] for _ in range(len(α))]

def F(α, β):
	'''
	(f0, f1, f2, f3) = f are calculated in sequence.
	f1 =α1 ⊕ β0
	f2 =α2 ⊕ β1
	f1 = f1 ⊕ α0
	f2 = f2 ⊕ α3
	f1 = S1 (f1, f2 )
	f2 = S0 (f2, f1 )
	f0 = S0 (α0, f1)
	f3 = S1 (α3, f2 ) 
	'''
	f1 = α[1]^β[0]
	f2 = α[2]^β[1]
	f1 = f1^α[0]
	f2 = f2^α[3]
	f1 = S1(f1,f2)
	f2 = S0(f2,f1)
	f0 = S0(α[0],f1)
	f3 = S1(α[3],f2)
	return [f0,f1,f2,f3]

def Fk(α, β):
	'''
	(fK0, fK1, fK2, fK3) = fK are calculated in sequence.
	fK1 = α1 ⊕ α0
	fK2 = α2 ⊕ α3
	fK1 = S1 (fK1, ( fK2 ⊕ β0 ) )
	fK2 = S0 (fK2, ( fK1 ⊕ β1 ) )
	fK0 = S0 (α0, ( fK1 ⊕ β2 ) )
	fK3 = S1 (α3, ( fK2 ⊕ β3 ) )
	'''
	fk1 = α[1]^α[0]
	fk2 = α[2]^α[3]
	fk1 = S1(fk1,(fk2^β[0]))
	fk2 = S0(fk2,(fk1^β[1]))
	fk0 = S0(α[0],(fk1^β[2]))
	fk3 = S1(α[3],(fk2^β[3]))
	return [fk0,fk1,fk2,fk3]

def S1(X1,X2):
	return S0(X1,X2,k=1)

def S0(X1,X2,k=0):
	'''	Rot2(T) is the result of a 2-bit left rotation operation on 8-bit block, T. '''
	# https://www.geeksforgeeks.org/rotate-bits-of-an-integer/
	def rot2(T,bit_block=8):
		return (T << 2)|(T >> (bit_block - 2))
	return rot2((X1 + X2 + k) % 256) % 256

