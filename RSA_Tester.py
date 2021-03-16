import RSA as rsa
import time

def perf_test():
	bits = [16, 32, 64, 1048, 2048]
	
	message = "Hello World"
	print("Encrypting Message: " + message)
	
	for size in bits:
	
		print("===================================")
		print("Key size: %d" % size)
		gen_start = time.perf_counter()
		keyPair = rsa.KeyPair(size)
		print(time.perf_counter() - gen_start)
		
		print("Encrypting")
		enc_start = time.perf_counter()
		cypher = rsa.encryptMessage(keyPair.publicKey, "Hello World")
		print(time.perf_counter() - enc_start)
		
		print("Decrypting")
		dec_start = time.perf_counter()
		message = rsa.decryptMessage(keyPair.privateKey, cypher)
		print(time.perf_counter() - dec_start)
		print("Decrypted message: " + message)
		print("===================================\n\n")

def storage_test():
	
	message = 'Test Message'

	print('Generating Keys')
	keyPair = rsa.KeyPair(1048)
	print('Storing Public Key')
	rsa.storePublicKey('pub.key', keyPair.publicKey)
	print('Storing Private Key')
	rsa.storePrivateKey('priv.key', keyPair.privateKey)

	print("===================================")
	print('Loading Public Key')
	pubKey = rsa.loadPublicKey('pub.key')
	
	print('Testing Loaded Public Key')
	cypher = rsa.encryptMessage(pubKey, message)
	unencrypted = rsa.decryptMessage(keyPair.privateKey, cypher)
	print('Passed: ' + ('True' if message == unencrypted else 'False'))

	print("===================================")
	print('Loading Private Key')
	privKey = rsa.loadPrivateKey('priv.key')

	print('Testing Loaded Private Key')
	cypher = rsa.encryptMessage(keyPair.publicKey, message)
	unencrypted = rsa.decryptMessage(privKey, cypher)
	print('Passed: ' + ('True' if message == unencrypted else 'False'))


	print("===================================")
	print('Testing Loaded Public & Private Key')
	cypher = rsa.encryptMessage(pubKey, message)
	unencrypted = rsa.decryptMessage(privKey, cypher)
	print('Passed: ' + ('True' if message == unencrypted else 'False'))

perf_test()
storage_test()
