### Dependencies
import os
import subprocess

### Initialization
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

# Converts bytes to nums
def b_to_num_single(_byte):
    return int(_byte.encode('hex'), 16)

# Get the i and r, given rK's k and block_id: Step 1 to Step 3
def getFinalI(r, k, yN_id = 2):
	### [Step 1]: Generate random block r = (r1|r2|...|r15|i) ###
	i_of_r = 0	# Init i of r to be 0
	byte_k_th = k - 1
	r = r[:byte_k_th] + intToHex(i_of_r) + r[byte_k_th+1:]

	### [Step 2]: Ask the oracle if r_yN is valid ###
	yN = cipher_y[yN_id]
	r_yN = r + yN 											# Get (r|yN)
	oracle_validation = isValidatedByOracle(r_yN, False)	# Validate (r|yN) by oracle

	### [Step 3]: Increment i and keep on validation ###
	while ((oracle_validation) == 0) and (i_of_r < MAX_FINAL_I):
		i_of_r += 1	     										# Update i
		r = r[:byte_k_th] + intToHex(i_of_r) + r[byte_k_th+1:]	# Re-construct r
		r_yN = r + yN 											# Re-construct r_yN
		oracle_validation = isValidatedByOracle(r_yN, False)	# Validate again

	return (i_of_r, r_yN)

# Return successive n-sized chunks from l
def chunks(l, n):
	result = []
	for j in xrange(0, len(l), n):
		result.append(l[j:j + n])
	return result

# Convert array to string for printing
def arrayToString(arr):
	return "".join(chr(x) for x in arr)


### Load byte from ciphertext
file = open("ciphertext", "rb")
ciphertext = file.read()
file.close()
cipher_len = len(ciphertext)
printAsByte("ciphertext", ciphertext)

# Chop the ciphertext into chunks of 16-bytes
# cipher_y[0] is the first chunk, might be the IV
cipher_y = chunks(ciphertext, 16)
cipher_y_len = len(cipher_y)

# Print out the ciphertext chunks
for j in range(cipher_y_len):
	printAsByte("cipher_y", cipher_y[j], j)

# The entire plain text, without the IV
x_all = bytearray(cipher_len - 16)


# Iteratively go through all the blocks
# If length is 5, start from ID4 to ID1, not ID0(IV)
for block_id in range(cipher_y_len - 1, 0, -1):

	######################### Decypt Byte #########################
	printAsMessage("Decrypt Byte", "=========================")

	printAsMessage("Block ID", block_id)

	# Get the last chunk
	r_yN = cipher_y[block_id]
	# Create current D_yN_1 ... D_yN_16
	D_yN = bytearray(16)
	# Create current x_N_1 ... x_N_16
	x_N = bytearray(16)

	r = generateRandomBytes(15) + intToHex(0)
	k = 16
	(i_of_r, r_yN) = getFinalI(r, k, block_id)

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

	### [Step 5] & [Step 6]: Check if the r_yN kept on replacing until the very end ###
	D_yN[15] = i_of_r ^ (17 - k)
	printAsByte("D_yN[15]", intToHex(D_yN[15]))

	### [Step 7]: Generate the final byte of xN(the plain text) ###
	x_N[15] = D_yN[15] ^ b_to_num_single(cipher_y[block_id-1][15])
	printAsMessage("x_N[15]", x_N[15])


	#################### Decypt Block #################### ~52 sec ###
	printAsMessage("Decrypt Block", "=========================")

	# Iteratively go through all the bytes
	for k in range(15,0,-1):
		# k = j (th)
		r = r[:k-1] + intToHex(0)
		for m in range(k, 16):
			r = r + intToHex(D_yN[m] ^ (17 - k))
		# Get the correct i_of_r and r_yN
		(i_of_r, r_yN) = getFinalI(r, k, block_id)

		D_yN[k-1] = i_of_r ^ (17 - k)
		printAsByte("D_yN", intToHex(D_yN[k-1]), k-1)

		x_N[k-1] = D_yN[k-1] ^ b_to_num_single(cipher_y[block_id-1][k-1])

		print "x_N[" + str(k-1) + "]" + str(x_N[k-1]) + " --> \'" + str(chr(x_N[k-1]) + "\'")
		print "-------------------------\n"

	# Print out the plain text of the block
	print "Block " + str(block_id) + " Text: " + arrayToString(x_N)

	# Add all block texts to collector
	for j in range(len(x_N)):
		x_all[(block_id-1) * 16 + j] = chr(x_N[j])


#################### Decypt #################### ~77 sec for two blocks ###
printAsMessage("Decrypt All", "=========================")

# Print out the entire plain text
final_answer = arrayToString(x_all)
print "Final Answer:"
print final_answer


