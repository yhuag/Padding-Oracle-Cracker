### Dependencies
import os
import subprocess
import array

# Initialization
MAX_FINAL_I = 255

# Print a string of pretty-styling byte array
def printAsByte(label, s, chunk_id = -1):
	if(chunk_id != -1):
		print label + "[" + str(chunk_id) + "]" + " (" + str(len(s)) + ") ==> " + ':'.join(x.encode('hex') for x in str(s)) + "\n"
	else:
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


def getFinalI(r, k, yN_id = 2):
	### [Step 1]: Generate random block r = (r1|r2|...|r15|i) ###
	i_of_r = 0	# Init i of r to be 0
	byte_k_th = k - 1
	r = r[:byte_k_th] + intToHex(i_of_r) + r[byte_k_th+1:]

	### [Step 2]: Ask the oracle if r_yN is valid ###
	yN = cipher_yN[yN_id]
	#yN = ciphertext[ciphertext_length - 16:]	# Get (r|yN)
	r_yN = r + yN
	oracle_validation = isValidatedByOracle(r_yN, False)	# Validate (r|yN) by oracle

	### [Step 3]: Increment i and keep on validation ###
	while ((oracle_validation) == 0) and (i_of_r < MAX_FINAL_I):
		i_of_r += 1	     										# Update i
		r = r[:byte_k_th] + intToHex(i_of_r) + r[byte_k_th+1:]	# Re-construct r
		r_yN = r + yN 											# Re-construct r_yN
		oracle_validation = isValidatedByOracle(r_yN, False)	# Validate again

	return (i_of_r, r_yN)

# Yield successive n-sized chunks from l
def chunks(l, n):
	result = []
	for j in xrange(0, len(l), n):
		result.append(l[j:j + n])
	return result


### Load byte from ciphertext
file = open("ciphertext", "rb")
ciphertext = file.read()
file.close()
cipher_len = len(ciphertext)
printAsByte("ciphertext", ciphertext)

# Chop the ciphertext into chunks of 16-bytes
# cipher_yN[0] is the first chunk, might be the IV
cipher_yN = chunks(ciphertext, 16)

# Print out the ciphertext chunks
for j in range(len(cipher_yN)):
	printAsByte("cipher_yN", cipher_yN[j], j)

# Get the last chunk
r_yN = cipher_yN[2]

# Create current D_yN_1 ... D_yN_16
D_yN = bytearray(16)
# Create current x_N_1 ... x_N_16
x_N = bytearray(16)



######################### Decypt Byte #########################
printAsMessage("Decrypt Byte", "=========================")

r = generateRandomBytes(15) + intToHex(0)
k = 16
(i_of_r, r_yN) = getFinalI(r, k)

### [Step 4]: Replace each byte and check validation ###
# Replace r1 with any other byte
# Start from 0-th
byte_to_replace = 0
k = byte_to_replace + 1
# re-construct r_yN
new_r_yN = generateRandomBytes(1) + r_yN[1:]
# validatation
oracle_validation = isValidatedByOracle(new_r_yN, False)
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

# Still need to move to next
byte_to_replace += 1
k = byte_to_replace + 1

### [Step 5] & [Step 6] ###
# Check if the r_yN kept on replacing until the very end
D_yN[15] = i_of_r ^ (17 - k)
printAsByte("D_yN[15]", intToHex(D_yN[15]))

### [Step 7]: Generate the final byte of xN(the plain text) ###
x_N[15] = D_yN[15] ^ b_to_num_single(ciphertext[cipher_len - 17])
printAsMessage("x_N[15]", x_N[15])






#################### Decypt Block ####################
printAsMessage("Decrypt Block", "=========================")


k = 15
r = r[:k-1] + intToHex(0) + intToHex(D_yN[15] ^ (17 - k))
(i_of_r, r_yN) = getFinalI(r, k)

D_yN[14] = i_of_r ^ (17 - k)
printAsByte("D_yN[14]", intToHex(D_yN[14]))

x_N[14] = D_yN[14] ^ b_to_num_single(cipher_yN[1][14])
printAsMessage("x_N[14]", x_N[14])






