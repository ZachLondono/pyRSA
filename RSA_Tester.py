import RSA as rsa
import time

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



