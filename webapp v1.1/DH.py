# Functions File for the Double hashing project

import hashlib
import os
import random

#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
encryption_key = 'Batch B Group 17'*2  # Replace with your actual key (keep it secret!)
encryption_key = encryption_key.encode('utf-8').hex()   # Convert to hex 
#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

################################################################
# RANDOM GENERATOR
def random_gen(n=10):
    '''Generates a random value of length 10'''
    salt = ""
    for _ in range(0, n):
        salt = salt + chr(random.randint(33, 126))
    return salt

################################################################
# ENCRYPTION & HASHING
################################################################
#---------------------------------------------------------------
# User-defined AES encryption function
# S-box
sbox = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            )
sbox_inv = (
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
            )

# Shift rows
def shift_rows(state):
    # Shift row 1
    temp = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = state[13]
    state[13] = temp

    # Shift row 2
    temp = state[2]
    state[2] = state[10]
    state[10] = temp
    temp = state[6]
    state[6] = state[14]
    state[14] = temp

    # Shift row 3
    temp = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = state[3]
    state[3] = temp

    return state

# Inverse Shift rows
def inv_shift_rows(state):
    # Shift row 1
    temp = state[13]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = state[1]
    state[1] = temp

    # Shift row 2
    temp = state[2]
    state[2] = state[10]
    state[10] = temp
    temp = state[6]
    state[6] = state[14]
    state[14] = temp

    # Shift row 3
    temp = state[3]
    state[3] = state[7]
    state[7] = state[11]
    state[11] = state[15]
    state[15] = temp

    return state

# Mix columns
def mix_columns(state):
    # First column
    temp = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[0] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[1] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[2] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[3] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    # Second column
    temp = state[4] ^ state[5] ^ state[6] ^ state[7]
    state[4] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[4] ^ state[5] ^ state[6] ^ state[7]
    state[5] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[4] ^ state[5] ^ state[6] ^ state[7]
    state[6] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[4] ^ state[5] ^ state[6] ^ state[7]
    state[7] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    # Third column
    temp = state[8] ^ state[9] ^ state[10] ^ state[11]
    state[8] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[8] ^ state[9] ^ state[10] ^ state[11]
    state[9] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[8] ^ state[9] ^ state[10] ^ state[11]
    state[10] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[8] ^ state[9] ^ state[10] ^ state[11]
    state[11] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    # Fourth column
    temp = state[12] ^ state[13] ^ state[14] ^ state[15]
    state[12] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[12] ^ state[13] ^ state[14] ^ state[15]
    state[13] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[12] ^ state[13] ^ state[14] ^ state[15]
    state[14] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[12] ^ state[13] ^ state[14] ^ state[15]
    state[15] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    return state

# Inverse Mix Columns
def inv_mix_columns(state):
    # First column
    temp = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[0] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[1] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[2] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[0] ^ state[1] ^ state[2] ^ state[3]
    state[3] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    # Second column
    temp = state[4] ^ state[5] ^ state[6] ^ state[7]
    state[4] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[4] ^ state[5] ^ state[6] ^ state[7]
    state[5] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[4] ^ state[5] ^ state[6] ^ state[7]
    state[6] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[4] ^ state[5] ^ state[6] ^ state[7]
    state[7] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    # Third column
    temp = state[8] ^ state[9] ^ state[10] ^ state[11]
    state[8] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[8] ^ state[9] ^ state[10] ^ state[11]
    state[9] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[8] ^ state[9] ^ state[10] ^ state[11]
    state[10] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[8] ^ state[9] ^ state[10] ^ state[11]
    state[11] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    # Fourth column
    temp = state[12] ^ state[13] ^ state[14] ^ state[15]
    state[12] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[12] ^ state[13] ^ state[14] ^ state[15]
    state[13] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[12] ^ state[13] ^ state[14] ^ state[15]
    state[14] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    temp = state[12] ^ state[13] ^ state[14] ^ state[15]
    state[15] ^= temp ^ (temp << 1) ^ (temp & 0x80 and 0x1b)

    return state


# Key schedule
def key_schedule(key, round):
    # Rotate the word
    temp = key[0]
    key[0] = key[1]
    key[1] = key[2]
    key[2] = key[3]
    key[3] = temp

    # Substitute the word
    key[0] = sbox[key[0]]
    key[1] = sbox[key[1]]
    key[2] = sbox[key[2]]
    key[3] = sbox[key[3]]

    # XOR the round constant
    key[0] = key[0] ^ round ^ 0x80

    return key

#---------------------------------------------------------------

# AES encryption
def aes_encrypt(key, data):
    global sbox
    #print(data)
    # Manual method
    # Initialize the state array
    state = []
    for i in range(16):
        state.append(data[i])
    print(state)
    #print(len(state))

    # Initialize the round key
    round_key = []
    for i in range(16):
        round_key.append(key[i])
    print(round_key)
    #print(len(round_key))

    print(len(sbox))

    # Add the first round key to the state before starting the rounds
    for i in range(16):
        state[i] = state[i] + round_key[i]
    #print(state)
        
    # Perform 9 rounds
    for i in range(1, 10):
        # SubBytes
        for j in range(16):
            state[j] = sbox[state[j]%len(sbox)]
        #print(state)

        # ShiftRows
        state = shift_rows(state)
        #print(state)

        # MixColumns
        state = mix_columns(state)
        #print(state)

        # Add round key
        round_key = key_schedule(round_key, i)
        #print(round_key)
        for j in range(16):
            state[j] = state[j] ^ round_key[j]
        #print(state)

    # Perform the 10th round
    # SubBytes
    for j in range(16):
        state[j] = sbox[state[j]%len(sbox)]
    print(state)

    # ShiftRows
    state = shift_rows(state)
    #print(state)

    # Add round key
    round_key = key_schedule(round_key, 10)
    #print(round_key)
    for j in range(16):
        state[j] = state[j] ^ round_key[j]
    #print(state)

    # Return the ciphertext
    return bytes(state)

#---------------------------------------------------------------
# AES decryption
def aes_decrypt(key, data):
    # Manual method
    # Initialize the state array
    state = []
    for i in range(16):
        state.append(data[i])
    #print(state)

    # Initialize the round key
    round_key = []
    for i in range(16):
        round_key.append(key[i])
    #print(round_key)

    # Add the first round key to the state before starting the rounds
    for i in range(16):
        state[i] = state[i] ^ round_key[i]
    #print(state)

    # Perform 9 rounds
    for i in range(1, 10):
        # Inverse ShiftRows
        state = inv_shift_rows(state)
        #print(state)

        # Inverse SubBytes using the inverse S-box
        for j in range(16):
            state[j] = sbox_inv[state[j]%len(sbox_inv)]
        #print(state)

        # Add round key
        round_key = key_schedule(round_key, i)
        #print(round_key)
        for j in range(16):
            state[j] = state[j] ^ round_key[j]
        #print(state)

        # Inverse MixColumns
        state = inv_mix_columns(state)
        #print(state)

    # Perform the 10th round
    # Inverse ShiftRows
    state = inv_shift_rows(state)
    #print(state)

    # Inverse SubBytes
    for j in range(16):
        state[j] = sbox_inv[state[j]%len(sbox_inv)]
    #print(state)

    # Add round key
    round_key = key_schedule(round_key, 10)
    #print(round_key)
    for j in range(16):
        state[j] = state[j] ^ round_key[j]
    #print(state)

    # Return the ciphertext
    return bytes(state)


#---------------------------------------------------------------
# User-defined SHA256 function without libraries
def sha256(data):
    #return hashlib.sha256(data.encode()).hexdigest()
    # Manual method
    # Convert the data from bytes to normal string
    # Convert data to binary for sha256
    data = ''.join(format(ord(i), '08b') for i in str(data))

    # Initialize the hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # Initialize the array of round constants:
    K = [ 
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
    
    # Pre-processing (Padding)
    # append the bit '1' to the message
    data = data + chr(0x80)

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    data_len = len(data)
    k = 0
    while (data_len + k + 8) % 64 != 0:
        k = k + 1
    data = data + chr(0x00)*k + chr(data_len*8//0x100000000) + chr(data_len*8%0x100000000//0x1000000) + chr(data_len*8%0x1000000//0x10000) + chr(data_len*8%0x10000//0x100) + chr(data_len*8%0x100)

    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    chunks = []
    for i in range(0, len(data), 64):
        chunks.append(data[i:i+64])

    # Makes sure each chunk is of currect length
    for i in range(len(chunks)):
        if len(chunks[i]) != 64:
            chunks[i] = chunks[i] + chr(0x00)*(64-len(chunks[i]))

    # for each chunk
    for chunk in chunks:
        # create a 64-entry message schedule array w[0..63] of 32-bit words
        w = []
        # copy chunk into first 16 words w[0..15] of the message schedule array
        for i in range(0, 64, 4):
            w.append(ord(chunk[i])*0x1000000 + ord(chunk[i+1])*0x10000 + ord(chunk[i+2])*0x100 + ord(chunk[i+3]))
        # Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for i in range(16, 64):
            s0 = (w[i-15] >> 7 | w[i-15] << 25) ^ (w[i-15] >> 18 | w[i-15] << 14) ^ (w[i-15] >> 3) ^ (w[i-15] << 29)
            s1 = (w[i-2] >> 17 | w[i-2] << 15) ^ (w[i-2] >> 19 | w[i-2] << 13) ^ (w[i-2] >> 10) ^ (w[i-2] << 22)
            w.append((w[i-16] + s0 + w[i-7] + s1) % 0x100000000)

        # Initialize working variables to current hash value:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Compression function main loop:
        for i in range(64):
            s1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + K[i] + w[i]) % 0x100000000
            s0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) % 0x100000000

            h = g
            g = f
            f = e
            e = (d + temp1) % 0x100000000
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % 0x100000000

        # Add the compressed chunk to the current hash value:
        h0 = (h0 + a) % 0x100000000
        h1 = (h1 + b) % 0x100000000
        h2 = (h2 + c) % 0x100000000
        h3 = (h3 + d) % 0x100000000
        h4 = (h4 + e) % 0x100000000
        h5 = (h5 + f) % 0x100000000
        h6 = (h6 + g) % 0x100000000
        h7 = (h7 + h) % 0x100000000

    # Produce the final hash value (big-endian):
    return '%08x%08x%08x%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4, h5, h6, h7)

#---------------------------------------------------------------

# User-defined SHA512 function
def sha512(data):
    #return hashlib.sha512(data.encode()).hexdigest()

    # Manual method
    # Initialize the hash values (first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    h0 = 0x6a09e667f3bcc908
    h1 = 0xbb67ae8584caa73b
    h2 = 0x3c6ef372fe94f82b
    h3 = 0xa54ff53a5f1d36f1
    h4 = 0x510e527fade682d1
    h5 = 0x9b05688c2b3e6c1f
    h6 = 0x1f83d9abfb41bd6b
    h7 = 0x5be0cd19137e2179

    # Initialize the array of round constants:
    K = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ]
    
    # Pre-processing (Padding)
    # append the bit '1' to the message
    data = data + chr(0x80)

    # append 0 <= k < 1024 bits '0', so that the resulting message length (in bits)
    #    is congruent to 896 (mod 1024)
    # append length of message (before pre-processing), in bits, as 128-bit big-endian integer
    data_len = len(data)
    k = 0
    while (data_len + k + 16) % 128 != 0:
        k = k + 1
    data = data + chr(0x00)*k + chr(data_len*8//0x10000000000000000) + chr(data_len*8%0x10000000000000000//0x100000000000000) + chr(data_len*8%0x100000000000000//0x1000000000000) + chr(data_len*8%0x1000000000000//0x10000000000) + chr(data_len*8%0x10000000000//0x100000000) + chr(data_len*8%0x100000000//0x1000000) + chr(data_len*8%0x1000000//0x10000) + chr(data_len*8%0x10000//0x100) + chr(data_len*8%0x100)

    # Process the message in successive 1024-bit chunks:
    # break message into 1024-bit chunks
    chunks = []
    for i in range(0, len(data), 128):
        chunks.append(data[i:i+128])

    # Make sure all chunks are of correct length
    for i in range(len(chunks)):
        if len(chunks[i]) != 128:
            chunks[i] = chunks[i] + chr(0x00)*(128-len(chunks[i]))

    # for each chunk
    for chunk in chunks:
        # create a 80-entry message schedule array w[0..79] of 64-bit words
        w = []
        # copy chunk into first 16 words w[0..15] of the message schedule array
        for i in range(0, 128, 8):
            w.append(ord(chunk[i])*0x100000000000000 + ord(chunk[i+1])*0x1000000000000 + ord(chunk[i+2])*0x10000000000 + ord(chunk[i+3])*0x100000000 + ord(chunk[i+4])*0x1000000 + ord(chunk[i+5])*0x10000 + ord(chunk[i+6])*0x100 + ord(chunk[i+7]))
        # Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array:
        for i in range(16, 80):
            s0 = (w[i-15] >> 1 | w[i-15] << 63) ^ (w[i-15] >> 8 | w[i-15] << 56) ^ (w[i-15] >> 7) ^ (w[i-15] << 57)
            s1 = (w[i-2] >> 19 | w[i-2] << 45) ^ (w[i-2] >> 61 | w[i-2] << 3) ^ (w[i-2] >> 6) ^ (w[i-2] << 58)
            w.append((w[i-16] + s0 + w[i-7] + s1) % 0x10000000000000000)

        # Initialize working variables to current hash value:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Compression function main loop:
        for i in range(80):
            s1 = (e >> 14 | e << 50) ^ (e >> 18 | e << 46) ^ (e >> 41 | e << 23)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + s1 + ch + K[i] + w[i]) % 0x10000000000000000
            s0 = (a >> 28 | a << 36) ^ (a >> 34 | a << 30) ^ (a >> 39 | a << 25)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) % 0x10000000000000000

            h = g
            g = f
            f = e
            e = (d + temp1) % 0x10000000000000000
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % 0x10000000000000000

        # Add the compressed chunk to the current hash value:
        h0 = (h0 + a) % 0x10000000000000000
        h1 = (h1 + b) % 0x10000000000000000
        h2 = (h2 + c) % 0x10000000000000000
        h3 = (h3 + d) % 0x10000000000000000
        h4 = (h4 + e) % 0x10000000000000000
        h5 = (h5 + f) % 0x10000000000000000
        h6 = (h6 + g) % 0x10000000000000000
        h7 = (h7 + h) % 0x10000000000000000

    # Produce the final hash value (big-endian):
    return '%016x%016x%016x%016x%016x%016x%016x%016x' % (h0, h1, h2, h3, h4, h5, h6, h7)

#---------------------------------------------------------------
################################################################
# File Management
################################################################

'''# Initializing the json file
def init_data():
    # create pepper file if it does not exist
    if not os.path.exists('pepper.txt'):
        with open('pepper.txt', 'w') as f:
            f.write(random_gen())
    
init_data()
'''
################################################################
# Main Hashing Functions
################################################################

################################################################
# PBKDF
def pbkdf(pwd,salt,c=255,dkLen=50):
    # pwd is the password as a string
    # salt is the salt as a string
    # c is the number of iterations as an integer
    # dkLen is the length of the derived key as an integer
    # returns the derived key as a string of hex characters

    # convert pwd and salt to byte arrays
    pwd = pwd.encode()
    salt = salt.encode()
    P = pwd + salt

    # initialize derived key to empty string
    DK = b''
    for i in range(1,c+1):
        U = sha256(P)
        P = U
        DK = DK + U.encode()
    return DK.hex()[:dkLen]

################################################################
# Salting
def salting(pwd,salt):
    return pwd + salt

################################################################
'''# Pepper
def pepper(pwd,pepper):
    return pwd + pepper
'''
################################################################
# Double Hashing
def double_hash(pwd):
    # pwd is the password as a string
    # returns the double hashed password as a string of hex characters
    return sha256(sha512(pwd))

################################################################
'''# Pepper Checking
def pepper_check():
    # If file exists, return the pepper value from the file
    # If file does not exist, generate a random pepper value and save it to the file and also return the value
    if os.path.exists('pepper.txt'):
        with open('pepper.txt', 'r') as f:
            pepper = f.read()
            return pepper
    else:
        pepper = random_gen()
        with open('pepper.txt', 'w') as f:
            f.write(pepper)
            return pepper'''
        
################################################################
# hash function
def hash(user, pwd, kdf_salt, main_salt):
    # Retrive the Encryption Key
    global encryption_key
    key = encryption_key
    key = bytes.fromhex(key)

    # Double Hash the password with Salts
    kdf = pbkdf(pwd, kdf_salt)
    salted = salting(kdf, main_salt)
    double_hashed = double_hash(salted)

    # Encrypt the double hashed password
    double_hashed = bytes(double_hashed, 'utf-8')
    encrypted_hash = aes_encrypt(key, double_hashed)

    # Return the user, kdf_salt, main_salt, encrypted_hash
    return user, kdf_salt, main_salt, encrypted_hash.hex()

################################################################
# verify function
def verify(pwd, kdf_salt, main_salt, encrypted_hash):
    # Retrive the Encryption Key
    global encryption_key
    key = encryption_key
    key = bytes.fromhex(key)

    # Double Hash the password with Salts
    kdf = pbkdf(pwd, kdf_salt)
    salted = salting(kdf, main_salt)
    double_hashed = double_hash(salted)

    # Encrypt the double hashed password
    double_hashed = bytes(double_hashed, 'utf-8')

    # Decrypt the existing encrypted hash
    encrypted_hash = bytes.fromhex(encrypted_hash)
    decrypted_hash = aes_decrypt(key, encrypted_hash)

    # Return true or false based on whether decrypted hash matches
    return double_hashed == decrypted_hash

############################################################
# Functions for the Webpage
############################################################
       
# Function to sign up a user
def sign_up(username, password):
    kdf_salt = random_gen()
    main_salt = random_gen()
    user, kdf_salt, main_salt, encrypted_hash = hash(username, password, kdf_salt, main_salt)
        
    return user, kdf_salt, main_salt, encrypted_hash, 100

############################################################
# Session Transaction history stuff added by Parthvi
############################################################
transactions = []

def get_transaction_history(username):
    user_transactions = []
    for transaction in transactions:
        if transaction['username'] == username:
            user_transactions.append(transaction)
    return user_transactions

# Add a function to add transactions to the list
def add_transaction(username, date, transaction_type, amount):
    transactions.append({
        'username': username,
        'date': date,
        'type': transaction_type,
        'amount': amount
    })
############################################################