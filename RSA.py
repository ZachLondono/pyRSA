import random
import asn1tools
import base64

class RSA:
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


	def __init__(self):
		
		# Values for public/private key
		self.p = 0
		self.q = 0
		self.d = 0
		self.e = 0

		# calculating values for decrypting cipher
		self.d_Q = 0
		self.d_P = 0
		self.q_inv = 0
		
	# Continue to try generating random numbers until it can be fairly sure that the number is prime
	def generatePrime(n):
		while True:
			candidate = (random.randrange(2**(n-1)+1, 2**n-1))
			if RSA.basicprimecheck(candidate) and RSA.millerRabin(candidate):
				return candidate
	
	# Check if the prime candidate is divisible by any of the given primes 
	def basicprimecheck(candidate):
		for divisor in RSA.primes_list:
			if candidate % divisor == 0:
				return False
		return True
	
	# Algorithm for checking if a value is potentially prime
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
	
	def generateKeyPair(self, n):
		
		# private key variables
		self.p = RSA.generatePrime(n)
		self.q = RSA.generatePrime(n)
		self.n = self.p * self.q
		n_t = (self.p - 1) * (self.q - 1)

		# public key exponent
		self.e = 65537
		
		# private key exponent
		self.d = pow(self.e, -1, n_t)
		
		# Dencryption values
		self.d_P = self.d % (self.p - 1)
		self.d_Q = self.d % (self.q - 1)
		self.q_inv = pow(self.q, -1, self.p)
	
	def encryptMessage(self, message):
		return [ pow(ord(char), self.e, self.n)for char in message]
		#return [(ord(char) ** self.e) % self.n for char in message]
	
	def decryptMessage(self, message):
		return "".join(chr(self.decryptCRT(char_e)) for char_e in message)
	
	def decryptCRT(self, c):
		m1 = pow(c, self.d_P, self.p)
		m2 = pow(c, self.d_Q, self.q)
		h = ((m1 - m2) * self.q_inv ) % self.p
		m = m2 + h * self.q
		return int(m)
	
	def writePublicKey(file_path):
		key_file = asn1tools.compile_files('RSA.asn')
		
		asn1_encoded = key_file.encode('PUBLICKEY', {'n': self.n, 'e': self.e})
		pk = open(file_path, 'wb')
		pk.write(b'-----BEGIN RSA PUBLIC KEY-----\n')
		pk.write(base64.b64encode(asn1_encoded))
		pk.write(b'\n-----END RSA PUBLIC KEY-----')
		pk.close()
	
	def writePrivateKey(file_path):
		key_file = asn1tools.compile_files('RSA.asn')
		
		asn1_encoded = key_file.encode('PRIVATEKEY', {'p': self.p, 'q': self.q, 'd': self.d})
		pk = open(file_path, 'wb')
		pk.write(b'-----BEGIN RSA PRIVATE KEY-----\n')
		pk.write(base64.b64encode(asn1_encoded))
		pk.write(b'\n-----END RSA PRIVATE KEY-----')
		pk.close()
	
	def loadPublicKey(file_path):
		endcoded_key = ""
		start = False
		end = False
		for line in open(file_path, 'r'):
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
	
		self.n = key['n']
		self.e = key['e']
	
	def loadPrivateKey(file_path):
		endcoded_key = ""
		start = False
		end = False
		for line in open(file_path, 'r'):
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
	
		self.p = key['p']
		self.q = key['q']
		self.d = key['d']
	
