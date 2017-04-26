           ______  _____    _____ _                       
     /\   |  ____|/ ____|  / ____(_)                      
    /  \  | |__  | (___   | (___  _  __ _ _ __   ___ _ __ 
   / /\ \ |  __|  \___ \   \___ \| |/ _` | '_ \ / _ \ '__|
  / ____ \| |____ ____) |  ____) | | (_| | | | |  __/ |   
 /_/    \_\______|_____/  |_____/|_|\__, |_| |_|\___|_|   
                                     __/ |                
                                    |___/                  
-----------------------------------------------------------------------
RSA version 1.0 4/26/17
-----------------------------------------------------------------------

-----------------------------------------------------------------------
-----------------------------------------------------------------------
PROGRAMMING LANGUAGE

Programmed in Python
	
Tested on Windows 10 and Ubuntu Linux

Fully compatible with python2.x

Python3.x NOT supported

-----------------------------------------------------------------------
-----------------------------------------------------------------------
EXECUTION INSTRUCTIONS:

	- Make sure you have both Python2.x and pycrypto installed
	- The program is ran through commmand line with

-----------------------------------------------------------------------
USING THE SOFTWARE:

	-Running the signer.py file will display command line arguements

	-------------------------------------------------------------------------------

	USAGE:  signer.py <KEY FILE NAME> <SIGNATURE FILE NAME> <INPUT FILE NAME> <sign/verify>
	OR      signer.py <KEY FILE NAME> <AES KEY> <INPUT FILE NAME> <sign-enc/dec-verify>

	Modes:
		- sign
		- sign-enc
		- verify
		- dec-verify

	------------------------------------------------------------------------------

	- The last option is the mode. For "sign" or "verify" the signer
		will behave like normal. (First line after "USAGE")

	- If the mode is "sign-enc" or "dec-verify" the arguements change.
		The <Signature File Name> should be replaced with <AES KEY>
		This is for the EC portion.
		
	- When executing with normal usage, "sign" mode will output the signature
		into the signature file provided. The "verify" mode will take the
		signature from the signature file provided and verify if the signature
		provided match.

-----------------------------------------------------------------------

-----------------------------------------------------------------------
-----------------------------------------------------------------------
EXTRA CREDIT:

- We did implement the extra-credit portion of the assignment

- Takes in 32 hex characters as the key for AES

- The encryption process first takes the length of the signature and e
	and places it in the beginning of the file before encrypting
	the signature + contents

- Encryption automatically names the file with "encrypted_" at the start

- Decryption first decrypts, then takes out the signature and unencodes
	the signature, and then checks if the signature matches the file.

- Decryption automatically names t he file with "decrypted_" at the start
	and removes any "encrypted_" string in the filestring.

-----------------------------------------------------------------------
