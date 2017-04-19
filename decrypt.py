### Dependencies
import os
import subprocess
import array

# Initialization
MAX_FINAL_I = 255

# Print a string of pretty-styling byte array
def printAsByte(label, s):
	print label + " (" + str(len(s)) + ") ==> " + ':'.join(x.encode('hex') for x in str(s)) + "\n"

# Print a formatted message given label and content
def printAsMessage(label, s):
	print label + ": " + str(s) + "\n"

# Produce single or multiple bytes randomly
def generateRandomBytes(num):
	return bytearray(os.urandom(num))

# Convert an integer into byte(hexidecimal)
def intToHex(num):
	return chr(num)

# Check the given r_yN byte array is validated by oracle or not
# Return 0 if not, 1 if yes
def isValidatedByOracle(r_yN_array, toPrint = True):
	# Re-write to r_yN file
	r_yN_fileName = "r_yN"
	with open(r_yN_fileName, 'wb') as output:
		output.write(bytearray(r_yN_array))
	# Check validation
	oracle_validation = subprocess.check_output(["./oracle", r_yN_fileName])
	if (toPrint):
		printAsMessage("Oracle Validation", oracle_validation)
	return int(oracle_validation)

#converts bytes to nums
def b_to_num_single(_byte):
    return int(_byte.encode('hex'), 16)

def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))


def getFinalI(r, k):
	### [Step 1]: Generate random block r = (r1|r2|...|r15|i) ###
	i_of_r = 0	# Init i of r to be 0
	byte_k_th = k - 1
	r = r[:byte_k_th] + intToHex(i_of_r) + r[byte_k_th+1:]

	### [Step 2]: Ask the oracle if r_yN is valid ###
	yN = ciphertext[ciphertext_length - 16:]	# Get (r|yN)
	r_yN = r + yN
	oracle_validation = isValidatedByOracle(r_yN, False)	# Validate (r|yN) by oracle

	### [Step 3]: Increment i and keep on validation ###
	while ((oracle_validation) == 0) and (i_of_r < MAX_FINAL_I):
		i_of_r += 1	     										# Update i
		r = r[:byte_k_th] + intToHex(i_of_r) + r[byte_k_th+1:]	# Re-construct r
		r_yN = r + yN 											# Re-construct r_yN
		oracle_validation = isValidatedByOracle(r_yN, False)	# Validate again

	return (i_of_r, r_yN)



### Load byte from ciphertext
ciphertext_file = open("ciphertext", "rb")
ciphertext = ciphertext_file.read()
ciphertext_file.close()
ciphertext_length = len(ciphertext)
printAsByte("ciphertext", ciphertext)



######################### Decypt Byte #########################
r = generateRandomBytes(15) + intToHex(0)
k = 16
(i_of_r, r_yN) = getFinalI(r, k)
'''

### [Step 1]: Generate random block r = (r1|r2|...|r15|i) ###
# Init i of r to be 0
i_of_r = 0
# Init r
r = generateRandomBytes(15) + intToHex(i_of_r)
printAsByte("r", r)


### [Step 2]: Ask the oracle if r_yN is valid ###
# Get (r|yN)
yN = ciphertext[ciphertext_length - 16:]
r_yN = r + yN
printAsByte("r_yN", r_yN)
# Validate (r|yN) by oracle
oracle_validation = isValidatedByOracle(r_yN, False)


### [Step 3]: Increment i and keep on validation ###
# If validation is false(0), increment i_of_r by 1, and validate again
# Until the validation is True(1), or i_of_r exceeds 255(ERROR)
while ((oracle_validation) == 0) and (i_of_r < 255):
	# Update i
	i_of_r += 1
	# Re-construct r
	r = r[:15] + intToHex(i_of_r)
	# Re-construct r_yN
	r_yN = r + yN
	# Validate again
	oracle_validation = isValidatedByOracle(r_yN, False)
# ==> Validation process finish. Get the correct i_of_r

'''

### [Step 4]: Replace each byte and check validation ###
# Replace r1 with any other byte
# Start from 0-th
byte_to_replace = 0
k = byte_to_replace + 1
# re-construct r_yN
new_r_yN = generateRandomBytes(1) + r_yN[1:]
# validatation
oracle_validation = isValidatedByOracle(new_r_yN)
# Keep on replacing r_yN's each byte with any other random bytes
# and check the validation. Stop only until r_15(not i) are replaced
# Or any validation is failed(0)
while (oracle_validation == 1) and (k < 15):
	# Ready to replace the next byte
	byte_to_replace += 1
	k = byte_to_replace + 1
	# Re-construct the r_yN_new with the specific byte replaced
	new_r_yN = new_r_yN[:byte_to_replace] + generateRandomBytes(1) + new_r_yN[byte_to_replace + 1:]
	oracle_validation = isValidatedByOracle(new_r_yN, False)
	#printAsMessage("rK_to_replace", k)
	#printAsMessage("Oracle Validation", oracle_validation)
	#printAsByte("new_r_yN", new_r_yN)
# Still need to move to next
byte_to_replace += 1
k = byte_to_replace + 1
printAsByte("new_r_yN", new_r_yN)
printAsMessage("rK_to_replace", k)

### [Step 5] & [Step 6] ###
# Check if the r_yN kept on replacing until the very end
D_yN_16 = i_of_r ^ (17 - k)

### [Step 7]: Generate the final byte of xN(the plain text) ###
x_N_16 = D_yN_16 ^ b_to_num_single(ciphertext[ciphertext_length - 17])
printAsMessage("x_N_16", x_N_16)
printAsMessage("End of Decrypt Byte", "=========================")





#################### Decypt Block ####################
printAsMessage("Decrypt Block", "=========================")


### To find x_N_15, ..., x_N_1

D_yN = ciphertext[ciphertext_length - 16:]
printAsByte("D_yN", D_yN)
D_yN_1_k = ciphertext[ciphertext_length - 32: ciphertext_length - 16]
printAsByte("D_yN_1_k", D_yN_1_k)

# Start from r15
k_th = 15
# byte_k_th starts from 14 (0...15)
byte_k_th = k_th - 1




k = 15
r = r[:k-1] + intToHex(0) + intToHex(D_yN_16 ^ (17 - k_th))
(i_of_r, r_yN) = getFinalI(r, k)



'''

# Init i = 0
i_of_r = 0

# r = r1...r14 + i(0), length = 15
r = r[:byte_k_th] + intToHex(i_of_r)
printAsByte("r", r)

# Concantenate the following D_y_k+1 ... D_y_16
new_byte = intToHex(D_yN_16 ^ (17 - k_th))
printAsByte("new_byte", new_byte)
r = r + new_byte
printAsByte("r", r)

r_y = r + D_yN

oracle_validation = isValidatedByOracle(r_y, False)

# If validation is false(0), increment i_of_r by 1, and validate again
# Until the validation is True(1), or i_of_r exceeds 255(ERROR)
while ((oracle_validation) == 0) and (i_of_r < 255):
	# Update i
	i_of_r += 1
	# Re-construct r, the 
	r = r[:byte_k_th] + intToHex(i_of_r) + r[byte_k_th+1:]
	# Re-construct r_yN
	r_y = r + D_yN
	# Validate again
	oracle_validation = isValidatedByOracle(r_y, False)

'''


# Validation process finish. Get the correct i_of_r
printAsByte("Validated", r_yN)
printAsMessage("r_15 Oracle Validation", "=========================")

printAsMessage("i_of_r", i_of_r)

D_yN_15 = i_of_r ^ (17 - k_th)
printAsByte("D_yN_15", intToHex(D_yN_15))

x_N_15 = D_yN_15 ^ b_to_num_single(D_yN_1_k[14])
printAsMessage("x_N_15", x_N_15)






