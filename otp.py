import os
import os.path
import sys
import getopt
import logging

#-----------------------------| Logging |------------------------------|
logger = logging.getLogger()
logger.setLevel(logging.INFO)

consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.DEBUG)

logger.addHandler(consoleHandler)

#----------------------------| Constants |-----------------------------|

DEFAULT_BUFFER_SIZE = 2048

#---------------------------| Functions |------------------------------|

def xor(plaintext, key):
	"""Xor a binary plaintext with an equally binary key of the same
	size. Retruns a binary ciphertext of, again, the same size."""
	if len(plaintext) != len(key):
		raise IndexError('Plaintext and key should be the same size')
	
	cipher = bytearray(len(plaintext))
	for i, byte in enumerate(plaintext):
		cipher[i] = byte ^ key[i]
	
	return cipher

if __name__ == '__main__':
	# Parse options |--------------------------------------------------|
	options = 'db:'
	options_large = ('decrypt', 'buffer-size=')
	try:
		opts, args = getopt.gnu_getopt(sys.argv[1:], options, options_large)
	except getopt.GetoptError as err:
		logger.error('Error getting command line options: %s', err.msg)
		sys.exit(2)
	
	BUFFER_SIZE = DEFAULT_BUFFER_SIZE
	decrypting = False
	for opt, arg in opts:
		if opt in ('-d', '--decrypt'):
			decrypting = True
		elif opt in ('-b', '--buffer-size'):
			BUFFER_SIZE = int(arg)
	
	# The actual work |------------------------------------------------|
	
	if not decrypting:
		for filename in args:
			fcipher_name = filename + '.otp'
			fkey_name = filename + '.otpk'
			
			# The plaintext file, ciphertext file and where the key will be written
			with open(filename, 'rb') as fplain, open(fcipher_name, 'wb') as fcipher, open(fkey_name, 'wb') as fkey:
				while True:
					buffer_plain = fplain.read(BUFFER_SIZE)
					if not buffer_plain: # Get out when all plain text is read
						break
					# Can't just pass BUFFER_SIZE, as buffer_plain may be smaller
					buffer_key = os.urandom(len(buffer_plain))
					fcipher.write(xor(buffer_plain, buffer_key))
					fkey.write(buffer_key)
	else: # Decryption
		for filename in args:
			fplain_name = os.path.splitext(filename)[0]
			fkey_name = os.path.splitext(filename)[0] + '.otpk'
			
			# The plaintext file, the ciphertext file (notice writing mode) and key file (again, but reading).
			with open(filename, 'rb') as fcipher, open(fplain_name, 'wb') as fplain, open(fkey_name, 'rb') as fkey:
				while True:
					buffer_cipher = fcipher.read(BUFFER_SIZE)
					if not buffer_cipher: # Get out when all cipher text is read
						break
					fplain.write(xor(buffer_cipher, fkey.read(len(buffer_cipher)) ))
	
				
