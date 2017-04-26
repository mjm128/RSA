import sys
if sys.version[0] == '3':
		print("Warning: Python 3.X currently not supported.")
		print("Try again running Python 2.X")
		exit(66)
import os, random, struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA512
from base64 import b64encode, b64decode
from binascii import unhexlify

##################################################
# Loads the RSA key object from the location
# @param keyPath - the path of the key
# @return - the RSA key object with the loaded key
##################################################
def loadKey(keyPath):
	
	# The RSA key
	key = None
	
	# Open the key file
	with open(keyPath, 'r') as keyFile:
		
		# Read the key file
		keyFileContent = keyFile.read()
		
		# Decode the key
		decodedKey = b64decode(keyFileContent)
		
		# Load the key
		key = RSA.importKey(decodedKey)

	# Return the key
	return key
		

##################################################
# Signs the string using an RSA private key
# @param sigKey - the signature key
# @param string - the string
##################################################
def digSig(sigKey, string):
	
	# TODO: return the signature of the file
	try:
		signature = sigKey.sign(string, '')
	except:
		print("Cannot sign with public key")
		exit(42)
	return signature

##########################################################
# Returns the file signature
# @param fileName - the name of the file
# @param privKey - the private key to sign the file with
# @return fileSig - the file signature
##########################################################
def getFileSig(fileName, privKey):
	
	# TODO:
	# 1. Open the file
	# 2. Read the contents
	# 3. Compute the SHA-512 hash of the contents
	# 4. Sign the hash computed in 4. using the digSig() function
	# you implemented.
	# 5. Return the signed hash; this is your digital signature
	with open(fileName, "r") as file:
		fileContents = file.read()
		dataHash = SHA512.new(fileContents).hexdigest()
		signedHash = digSig(privKey, dataHash)

	return signedHash

###########################################################
# Verifies the signature of the file
# @param fileName - the name of the file
# @param pubKey - the public key to use for verification
# @param signature - the signature of the file to verify
##########################################################
def verifyFileSig(fileName, pubKey, signature):
	
	# TODO:
	# 1. Read the contents of the input file (fileName)
	# 2. Compute the SHA-512 hash of the contents
	# 3. Use the verifySig function you implemented in
	# order to verify the file signature
	# 4. Return the result of the verification i.e.,
	# True if matches and False if it does not match
	with open(fileName, "r") as file:
		fileContents = file.read()
		dataHash = SHA512.new(fileContents).hexdigest()
		sig = loadSig(signature)
		
	return verifySig(dataHash, sig, pubKey)

############################################
# Saves the digital signature to a file
# @param fileName - the name of the file
# @param signature - the signature to save
############################################
def saveSig(fileName, signature):

	# TODO: 
	# Signature is a tuple with a single value.
	# Get the first value of the tuple, convert it
	# to a string, and save it to the file (i.e., indicated
	# by fileName)
	with open(fileName, "w") as file:
		file.write(str(signature[0]))

###########################################
# Loads the signature and converts it into
# a tuple
# @param fileName - the file containing the
# signature
# @return - the signature
###########################################
def loadSig(fileName):
	
	# TODO: Load the signature from the specified file.
	# Open the file, read the signature string, convert it
	# into an integer, and then put the integer into a single
	# element tuple
	with open(fileName, "r") as file:
		sigString = file.read()
		signature = int(sigString)

	return (signature,)

#################################################
# Verifies the signature
# @param theHash - the hash 
# @param sig - the signature to check against
# @param veriKey - the verification key
# @return - True if the signature matched and
# false otherwise
#################################################
def verifySig(theHash, sig, veriKey):
	
	# TODO: Verify the hash against the provided
	# signature using the verify() function of the
	# key and return the result
	if veriKey.verify(theHash, sig) == True:
		print("Match!")
	else:
		print("No match!")

def AES_keyCheck(key):
	if len(key) == 32:
		try:
			aesKey = str(unhexlify(key))
			return aesKey
		except:
			print("Error: Non-hexadecimal digit found")
			exit(16)
	else:
		print("Error: Key length = {}, Key length must be 32 hex characters long" .format(len(key)))
		exit(9001)

def aesEncrypt(inputFileName, signature, key):
	cipherText = ""
	plainText = str(signature[0])
	plainText = str(len(plainText)) + "==" + plainText 
	with open(inputFileName, "r") as file:
		plainText += file.read()
	
	#Padding in format of: '\x03 \x03 \x03
	padNum = 16 - len(plainText) % 16
	while len(plainText) % 16 != 0:
		plainText += chr(padNum) #Add padding character
	
	aes_cipher = AES.new(key, AES.MODE_ECB)
	
	for index in range(0, len(plainText), 16):
			cipherText += aes_cipher.encrypt(plainText[index:index+16])
	
	outputFileName = "encrypted_" + inputFileName[:]
	with open(outputFileName, "w") as file:
		file.write(cipherText)
	
	return outputFileName

def aesDecrypt(inputFileName, key):
	plainText = ""
	cipherText = ""
	with open(inputFileName, "r") as file:
		cipherText += file.read()
	
	aes_cipher = AES.new(key, AES.MODE_ECB)
	
	try:
		for index in range(0, len(cipherText), 16):
				plainText += aes_cipher.decrypt(cipherText[index:index+16])
	except ValueError:
		print("ERROR: File is not a proper multiple of 16 bytes")
		print("Verify that file is the encrypted file")
		exit(666)
	
	sigLen = plainText.split("==")[0]
	signature = plainText[len(sigLen) + len("==") : len(sigLen) + int(sigLen) + len("==")]
	plainText = removePadding(plainText[len(sigLen) + len("==") + len(signature):])

	
	field = "encrypted_"
	start = inputFileName.find(field)
	if start > -1:
		outputFileName = "decrypted_" + inputFileName[start + len(field) : ]
	else:
		outputFileName = "decrypted_" + inputFileName
	with open(outputFileName, "w") as file:
		file.write(plainText)
	
	return (outputFileName, (int(signature),))

def removePadding(plainText):
		padNum = ord(plainText[-1])
		padChar = plainText[-1]
		isPadding = False
		if padNum > 0 and padNum < 16:
			if padNum == 1 and plainText[-2] != padChar:
				#If only one padding character
				return plainText[:len(plainText)-1]
			isPadding = True
			for index in range(2, padNum):
				if plainText[-index] != padChar:
					isPadding = False
		if isPadding:
			return plainText[:len(plainText)-padNum]
		return plainText

# The main function
def main():
	
	# Make sure that all the arguments have been provided
	if len(sys.argv) != 5:
		print("USAGE:  " + sys.argv[0] + " <KEY FILE NAME> <SIGNATURE FILE NAME> <INPUT FILE NAME> <sign/verify>")
		print("OR\t" + sys.argv[0] +" <KEY FILE NAME> <AES KEY> <INPUT FILE NAME> <sign-enc/dec-verify>")
		print("\nModes:\n\t- sign\n\t- sign-enc\n\t- verify\n\t- dec-verify")
		exit(-1)
	
	# The key file
	keyFileName = sys.argv[1]
	
	# Signature file name
	sigFileName = sys.argv[2]
	
	# The input file name
	inputFileName = sys.argv[3]
	
	# The mode i.e., sign or verify
	mode = sys.argv[4]

	# TODO: Load the key using the loadKey() function provided.
	key = loadKey(keyFileName)
	# We are signing
	if mode == "sign":
		# TODO: 1. Get the file signature
		#       2. Save the signature to the file
		sig = getFileSig(inputFileName, key)
		saveSig(sigFileName, sig)
		print("Signature saved to file: {}" .format(sigFileName))
	
	elif mode == "sign-enc":
		aesKey = AES_keyCheck(sys.argv[2].replace(" ", ""))
		sig = getFileSig(inputFileName, key)
		outFile = aesEncrypt(inputFileName, sig, aesKey)
		print("Encrypted file saved to: {}" .format(outFile))
		
	# We are verifying the signature
	elif mode == "verify":
		
		# TODO Use the verifyFileSig() function to check if the
		# signature signature in the signature file matches the
		# signature of the input file
		verifyFileSig(inputFileName, key, sigFileName)
	
	elif mode == "dec-verify":
		aesKey = AES_keyCheck(sys.argv[2].replace(" ", ""))
		(outFile, sig) = aesDecrypt(inputFileName, aesKey)
		with open(outFile, "r") as file:
			fileContents = file.read()
			dataHash = SHA512.new(fileContents).hexdigest()
			verifySig(dataHash, sig, key)
		print("Decrypted file saved to: {}" .format(outFile))
		
	else:
		print("Invalid mode: {}" .format(mode))
	
	exit(0)

### Call the main function ####
if __name__ == "__main__":
	main()
