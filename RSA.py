import random
import asn1tools
import base64

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
	p = generatePrime(1024)
	q = generatePrime(1024)
	n = p * q
	n_t = (p - 1) * (q - 1)
	e = 65537
	d = pow(e, -1, n_t)
	return (n,e), (p,q,d)

def encryptMessage(message, n, e):
	return [(ord(char) ** e) % n for char in message]

def decryptMessage(message, n, d):
	return "".join(chr((char_e ** d) % n) for char_e in message)

def writeKeyPairs(n, d, e):
	key_file = asn1tools.compile_files('RSA.asn')
	
	asn1_encoded = key_file.encode('PUBLICKEY', {'n': n, 'e': e})
	
	pk = open('public', 'wb')
	pk.write(b'-----BEGIN RSA PUBLIC KEY-----\n')
	pk.write(base64.b64encode(asn1_encoded))
	pk.write(b'\n-----END RSA PUBLIC KEY-----')
	pk.close()
	
	asn1_encoded = key_file.encode('PRIVATEKEY', {'n': n, 'd': d})

	pk = open('private', 'wb')
	pk.write(b'-----BEGIN RSA PRIVATE KEY-----\n')
	pk.write(base64.b64encode(asn1_encoded))
	pk.write(b'\n-----END RSA PRIVATE KEY-----')
	pk.close()

def loadPublicKey():
	endcoded_key = ""
	start = False
	end = False
	for line in open('public', 'r'):
		if not start and line == '-----BEGIN RSA PUBLIC KEY-----\n':
				start = True
		elif not end and line == '-----END RSA PUBLIC KEY-----':
			end = True
		elif start and not end:
			encoded_key = line
		else: return -1
	
	decoded_key = base64.b64decode(encoded_key)
	
	key_file = asn1tools.compile_files('RSA.asn')
	key = key_file.decode('PUBLICKEY', decoded_key)

	return key['n'], key['e']

def loadPrivateKey():
	endcoded_key = ""
	start = False
	end = False
	for line in open('private', 'r'):
		if not start and line == '-----BEGIN RSA PRIVATE KEY-----\n':
				start = True
		elif not end and line == '-----END RSA PRIVATE KEY-----':
			end = True
		elif start and not end:
			encoded_key = line
		else: return -1
	
	decoded_key = base64.b64decode(encoded_key)
	
	key_file = asn1tools.compile_files('RSA.asn')
	key = key_file.decode('PRIVATEKEY', decoded_key)

	return key['n'], key['d']

if __name__ == "__main__":
	#(n,e), (p,q,d) = generateKeyPair()

	#message = "H"
	#c = encryptMessage(message, n, e)
	#m = decryptMessage(c, n, d)

	#writeKeyPairs(n,d,e)

	(n,e) = loadPublicKey()
	(n,d) = loadPrivateKey()
	

