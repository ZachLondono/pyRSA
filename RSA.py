import random
import asn1tools
import base64
import math

class PublicKey:
	def __init__(self, n, e):
		self.e = e
		self.n = n

class PrivateKey:
	def __init__(self, p, q, d):
		self.p = p
		self.q = q
		self.d = d
		# Dencryption values
		self.d_P = self.d % (self.p - 1)
		self.d_Q = self.d % (self.q - 1)
		self.q_inv = pow(self.q, -1, self.p)

class KeyPair:

	# list of known prime numbers for basic prime test 
	primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 
						31, 37, 41, 43, 47, 53, 59, 61, 67,  
						71, 73, 79, 83, 89, 97, 101, 103,  
						107, 109, 113, 127, 131, 137, 139,  
						149, 151, 157, 163, 167, 173, 179,  
						181, 191, 193, 197, 199, 211, 223, 
						227, 229, 233, 239, 241, 251, 257, 
						263, 269, 271, 277, 281, 283, 293, 
						307, 311, 313, 317, 331, 337, 347, 349] 

	def __init__(self, size):
		# private key variables
		p = self.generatePrime(size)
		q = self.generatePrime(size)
		n = p * q
		n_t = (p - 1) * (q - 1)

		# public key exponent
		e = 65537
		
		# private key exponent
		d = pow(e, -1, n_t)
		
		self.publicKey = PublicKey(n, e)
		self.privateKey = PrivateKey(p, q, d)

	# Continue to try generating random numbers until it can be fairly sure that the number is prime
	def generatePrime(self, n):
		while True:
			candidate = (random.randrange(2**(n-1)+1, 2**n-1))
			if self.basicprimecheck(candidate) and self.millerRabin(candidate):
				return candidate
	
	# Check if the prime candidate is divisible by any of the given primes 
	def basicprimecheck(self, candidate):
		for divisor in self.primes_list:
			if candidate % divisor == 0:
				return False
		return True
	
	# Algorithm for checking if a value is potentially prime
	def millerRabin(self, candidate):
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

def writeKeyToFile(file_path, asn1_encoded, key_type):

	key_type = key_type.upper().encode('utf-8')
	key_data = b'-----BEGIN RSA ' + key_type + b' KEY-----\n' 
	
	b64encoded = base64.b64encode(asn1_encoded)
	length = len(b64encoded)
	line_count = math.ceil(length / 64)
	for i in range(line_count):
		s = i * 64
		e = s + 64
		key_data += b64encoded[s:e]
		if i < line_count - 1:
			key_data += b'\n'

	key_data += b'\n-----END RSA ' + key_type + b' KEY-----' 

	key_file = open(file_path, 'wb')
	key_file.write(key_data)
	key_file.close()
	
def storePublicKey(file_path, publicKey):
	key_file = asn1tools.compile_files('RSA.asn')
	asn1_encoded = key_file.encode('PUBLICKEY', {'n': publicKey.n, 'e': publicKey.e})
	writeKeyToFile('pub.key', asn1_encoded, 'PUBLIC')

def storePrivateKey(file_path, privateKey):
	key_file = asn1tools.compile_files('RSA.asn')
	asn1_encoded = key_file.encode('PRIVATEKEY', {'p': privateKey.p, 'q': privateKey.q, 'd': privateKey.d})
	writeKeyToFile('priv.key', asn1_encoded, 'PRIVATE')
	
def loadPublicKey(file_path):
	encoded_key = ""
	start = False
	end = False
	for line in open(file_path, 'r'):
		if not start and line == '-----BEGIN RSA PUBLIC KEY-----\n':
				start = True
		elif not end and line == '-----END RSA PUBLIC KEY-----':
			end = True
		elif start and not end:
			encoded_key += line
		else: return -1
	
	decoded_key = base64.b64decode(encoded_key)
	
	key_file = asn1tools.compile_files('RSA.asn')
	key = key_file.decode('PUBLICKEY', decoded_key)

	return PublicKey(key['n'], key['e'])

def loadPrivateKey(file_path):
	encoded_key = ""
	start = False
	end = False
	for line in open(file_path, 'r'):
		if not start and line == '-----BEGIN RSA PRIVATE KEY-----\n':
				start = True
		elif not end and line == '-----END RSA PRIVATE KEY-----':
			end = True
		elif start and not end:
			encoded_key += line
		else: return -1
	
	decoded_key = base64.b64decode(encoded_key)
	
	key_file = asn1tools.compile_files('RSA.asn')
	key = key_file.decode('PRIVATEKEY', decoded_key)

	return PrivateKey(key['p'], key['q'], key['d'])


def encryptMessage(pubKey, message):
	return [ pow(ord(char), pubKey.e, pubKey.n)for char in message]
	#return [(ord(char) ** self.e) % self.n for char in message]
	
def decryptMessage(privKey, message):
	
	def decryptCRT(privKey, c):
		m1 = pow(c, privKey.d_P, privKey.p)
		m2 = pow(c, privKey.d_Q, privKey.q)
		h = ((m1 - m2) * privKey.q_inv ) % privKey.p
		m = m2 + h * privKey.q
		return int(m)

	return "".join(chr(decryptCRT(privKey, char_e)) for char_e in message)
	
