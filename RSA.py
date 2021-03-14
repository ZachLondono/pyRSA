import random

primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 
				31, 37, 41, 43, 47, 53, 59, 61, 67,  
				71, 73, 79, 83, 89, 97, 101, 103,  
				107, 109, 113, 127, 131, 137, 139,  
				149, 151, 157, 163, 167, 173, 179,  
				181, 191, 193, 197, 199, 211, 223, 
				227, 229, 233, 239, 241, 251, 257, 
				263, 269, 271, 277, 281, 283, 293, 
				307, 311, 313, 317, 331, 337, 347, 349] 

def generatePrime(n):
	# pick a number in the range (2^(n-1)+1, 2^n-1)
	candidate = (random.randrange(2**(n-1)+1, 2**n-1))
	
	# test for prime
	if lowlevelprime(candidate) and millerRabin(candidate):
		return candidate
	else: return generatePrime(n)

def lowlevelprime(candidate):
	for divisor in primes_list:
		if candidate % divisor == 0:
			return False
	return True

def millerRabin(candidate):
	maxDivisionsByTwo = 0
	evenComponent = candidate - 1

	while evenComponent % 2 == 0:
		evenComponent >>= 1
		maxDivisionsByTwo += 1
	assert(2**maxDivisionsByTwo * evenComponent == candidate - 1)

	def trialComposite(round_tester):
		if pow(round_tester, evenComponent, candidate) == 1:
			return False
		for i in range(maxDivisionsByTwo):
			if pow(round_tester, 2**i * evenComponent, candidate) == candidate -1:
				return False
		return True
	
	numberOfTrials = 20
	for i in range(numberOfTrials):
		round_tester = random.randrange(2, candidate)
		if trialComposite(round_tester):
			return False
	return True

def generateKeyPair():
	p = generatePrime(16)
	q = generatePrime(16)
	n = p * q
	n_t = (p - 1) * (q - 1)
	e = 65537
	d = pow(e, -1, n_t)
	return (n,e), (p,q,d)

def encryptMessage(message, n, e):
	return [(ord(char) ** e) % n for char in message]

def decryptMessage(message, n, d):
	for char_e in message:
		print(char_e)
		c = char_e ** d
		print(c)
	#return "".join(chr((char_e ** d) % n) for char_e in message)


if __name__ == "__main__":
	(n,e), (p,q,d) = generateKeyPair()

	message = "H"
	c = encryptMessage(message, n, e)
	m = decryptMessage(c, n, d)
