# SCU.py
# Secure Communications Utilities
#   Taylor JL Whitaker - Spring 2017

import codecs
import mmap
import os
import random
import string
import socket
import sys
import time


# Delimiter for concatenating data
delimiter = ':-:'

# Data format used for IVs
dataType_IV = 'Binary'

# Block Padding
paddingChar = '1'


# Allows the use of hardware encryption cores with trojans and subsequent sandbox protection
EnableHWRSACore = False
EnableHWAES128Core = False
EnableHWRSATrojans = False
EnableHWAES128Trojans = False
EnableHWRSASandbox = False
EnableHWAES128Sandbox = False

# Setup the AES128 HW Core
AES128BlockSize = 128                   # Trusthub AES128 Core Block size
AES128Core = 'TH-AES128-TrojanFree'     # Trusthub AES128 - trojan free
# AES128Core = 'TH-AES128-T100'           # Trusthub AES128 - T100 design
# AES128Core = 'TH-AES128-T200'           # Trusthub AES128 - T200 design
# AES128Core = 'TH-AES128-T300'           # Trusthub AES128 - T300 design
# AES128Core = 'TH-AES128-T400'           # Trusthub AES128 - T400 design

# Set the RSA HW Core
RSABlockSize = 32
RSACore = 'TH-BasicRSA-TrojanFree'     # Trusthub BasicRSA - trojan free
# RSACore = 'TH-BasicRSA-T100'           # Trusthub BasicRSA - T100 design
# RSACore = 'TH-BasicRSA-T200'           # Trusthub BasicRSA - T200 design
# RSACore = 'TH-BasicRSA-T300'           # Trusthub BasicRSA - T300 design
# RSACore = 'TH-BasicRSA-T400'           # Trusthub BasicRSA - T400 design
# T300_T400_Counter = 0


# Sets options
def setOptions(options):
    global EnableHWRSACore
    global EnableHWAES128Core
    global EnableHWRSATrojans
    global EnableHWAES128Trojans
    global EnableHWRSASandbox
    global EnableHWAES128Sandbox

    EnableHWRSACore         = options[0]
    EnableHWAES128Core      = options[1]
    EnableHWRSATrojans      = options[2]
    EnableHWAES128Trojans   = options[3]
    EnableHWRSASandbox      = options[4]
    EnableHWAES128Sandbox   = options[5]

# Generate a random key of specified length
def generateKey(bytes):
    # key = os.urandom(bytes)
    key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(bytes))
    # print('Generated key: ' + str(key))
    return key


# Check the key size for selected algorithm
def checkKeySize(key, algorithm):
    # print(key)
    if algorithm is 'AES128':
        if len(key) is not AES128BlockSize:
            print('AES128 key provided is not ' +  str(AES128BlockSize) + ' bits...')
            print('Length: ' + str(len(key)))
            return False
    # if algorithm is 'RSA':
    #     if len(key[0]) is not RSABlockSize or len(key[1]) is not RSABlockSize:
    #         print('RSA modulus or exponent provided is not ' +  str(RSABlockSize) + ' bits...')
    #         return False
    return True


# Encrypt text
#   Return format: IV:-:Cipher
def encryptText(key, data, mode, algorithm):

    # Add the original message length to data to be encrypted
    data = delimiter.join((str(len(data)), data))

    # Convert text data and key to binary string
    binData = ''.join('{0:08b}'.format(ord(x), 'b') for x in data)


    if algorithm is 'AES128':
        binKey = ''.join('{0:08b}'.format(ord(x), 'b') for x in key)
        pad = ''
        for x in range(AES128BlockSize-len(binKey)):
            pad += '0'

        binKey = pad + binKey

        # print('AES Binary Key: ' + str(binKey))


    if algorithm is 'RSA':
        # print(str(key))
        binKey = [''.join('{0:08b}'.format(ord(x), 'b') for x in key[0]), ''.join('{0:08b}'.format(ord(x), 'b') for x in key[1])]

        pad0 = ''
        pad1 = ''

        for x in range(RSABlockSize-len(binKey[0])):
            pad0 += '0'
        for x in range(RSABlockSize-len(binKey[1])):
            pad1 += '0'

        binKey[0] = pad0 + binKey[0]
        binKey[1] = pad1 + binKey[1]


        # print('RSA Binary Key: ' + str(binKey))

    # Returns encryption output
    if mode is 'CBC':
        IV, cipher = encryptBinaryData(binKey, binData, mode, algorithm)

        # Convert binary IV and cipher to text
        cipher = ''.join(chr(int(cipher[i*8:i*8+8],2)) for i in range(len(cipher)//8))
        IV = ''.join(chr(int(IV[i*8:i*8+8],2)) for i in range(len(IV)//8))
        return delimiter.join((IV, cipher))




# Decrypt text
#   Cipher format: DataLength:-:IV:-:Cipher
def decryptText(key, cipher, mode, algorithm):

    # Extract cipherText parts
    IV = cipher.split(delimiter)[0]
    data = cipher.split(delimiter)[1]

    # print('IV:')
    # print(IV)
    # print('Cipher:')
    # print(data)

    # Convert ciphertext, key, and IV to binary strings
    binData = ''.join('{0:08b}'.format(ord(x), 'b') for x in data)
    binIV = ''.join('{0:08b}'.format(ord(x), 'b') for x in IV)

    if algorithm is 'AES128':
        binKey = ''.join('{0:08b}'.format(ord(x), 'b') for x in key)
        pad = ''
        for x in range(AES128BlockSize-len(binKey)):
            pad += '0'
            binKey = pad + binKey

        # print('AES Binary Key: ' + str(binKey))


    if algorithm is 'RSA':
        binKey = [''.join('{0:08b}'.format(ord(x), 'b') for x in key[0]), ''.join('{0:08b}'.format(ord(x), 'b') for x in key[1])]

        pad0 = ''
        pad1 = ''

        for x in range(RSABlockSize-len(binKey[0])):
            pad0 += '0'
        for x in range(RSABlockSize-len(binKey[1])):
            pad1 += '0'

        binKey[0] = pad0 + binKey[0]
        binKey[1] = pad1 + binKey[1]


        # print('RSA Binary Key: ' + str(binKey))

    # Returns decryption output
    if mode is 'CBC':
        dataOut = decryptBinaryData(binKey, binData, binIV, mode, algorithm)

        # print('DATAOUT: ' + str(data))
        # Convert binary dataOut to text
        data = ''.join(chr(int(dataOut[i*8:i*8+8],2)) for i in range(len(dataOut)//8))

        # print('DATA: ' + str(data))
        # print('DATA split: ' + str(data.split(delimiter)[0]))

        # Get the original message's length
        dataLength = int(data.split(delimiter)[0])
        plaintext = data.split(delimiter)[1][:dataLength]

        return plaintext


# Encrypt binary data
def encryptBinaryData(key, data, mode, algorithm):

    # Check key size
    if not checkKeySize(key, algorithm):
        return False

    # Cipher Block Chaining Mode
    if mode is 'CBC':
        if algorithm is 'AES128':
            # Returns IV, cipher
            return encrypt_CBC(key, data, algorithm, EnableHWAES128Core)
        if algorithm is 'RSA':
            # Returns IV, cipher
            return encrypt_CBC(key, data, algorithm, EnableHWRSACore)


# Decrypt binary data
def decryptBinaryData(key, cipher, IV, mode, algorithm):

    # Check key size
    if not checkKeySize(key, algorithm):
        return False

    # Cipher Block Chaining Mode
    if mode is 'CBC':
        if algorithm is 'AES128':
            # Returns decrypted data
            return decrypt_CBC(key, cipher, IV, algorithm, EnableHWAES128Core)
        if algorithm is 'RSA':
            # Returns decrypted data
            return decrypt_CBC(key, cipher, IV, algorithm, EnableHWRSACore)


# AES128 algorithm
def AES128_HWCore(key, data, mode):
    # HW Design Register Layout (32 bits wide)
    #
    #   0   SW Load Flag (upper 16 bits) | HW Load Flag (lower 16 bits)
    #   1   Key[127:96]
    #   2   Key[95:64]
    #   3   Key[63:32]
    #   4   Key[31:0]
    #   5   SWData[127:96]
    #   6   SWData[95:64]
    #   7   SWData[63:32]
    #   8   SWData[31:0]
    #   9   HWData[127:96]
    #   10  HWData[95:64]
    #   11  HWData[63:32]
    #   12  HWData[31:0]
    # Total memory size: 13 registers * 32 bits each
    #                    52 bytes * 8 bits each
    #                    416 bits
    # Open memory
    # with open('/root/Drivers/AEScontrl.ko', 'r+b') as f:
    #     # Memory-map the AES memory block
    #     mm = mmap.mmap(f.fileno(), 416) # Reading entire file will read a '\0' char
    # # Set the key and data inputs
    # mm[32:160] = key
    # mm[160:288] = data
    # # Signal ready for run
    # mm[0:16] = '0000000000000001'
    # # Read again when HW load flag is asserted
    # while (int(mm[16:32], 2) is not 0x1):
    #     pass
    #     # mm.seek(0)
    #     # Should I wait some time?
    # # Read the resulting output
    # output = mm[288:416]
    # # Set SW load flag to low
    # mm[0:16] = '0000000000000000'
    # return output
    # print data
    # print key
    return data


def RSA_HWCore(key, inData, mode):

    inExp = key[0]
    inMod = key[1]

    # HW Design Register Layout (32 bits wide)
    #
    #   0   SW Load Flag (upper 16 bits) | HW Load Flag (lower 16 bits)
    #   1   inMod
    #   2   inExp
    #   3   inData
    #   4   outData
    # Total memory size: 5 registers * 32 bits each
    #                    20 bytes * 8 bits each
    #                    160 bits

    # Example 32 bit keys for BasicRSA Benchmarks

    #   inMod = 301 = 0x0000012d = 0000 0000 0000 0000 0000 0001 0010 1101
    #   public exponent = 11 = 0x0000000b = 0000 0000 0000 0000 0000 0000 0000 1010
    #   private exponent = 23 = 0x00000017 = 0000 0000 0000 0000 0000 0000 0001 0111

    #   inMod = 77 = 0x0000004d = 0000 0000 0000 0000 0000 0000 0100 1101
    #   public exponent = 23 = 0x00000017 = 0000 0000 0000 0000 0000 0000 0001 0111
    #   private exponent = 47 = 0x0000002f = 0000 0000 0000 0000 0000 0000 0010 1111

    #   inMod = 187 = 0x000000bb = 0000 0000 0000 0000 0000 0000 1011 1011
    #   public exponent = 7 = 0x00000007 = 0000 0000 0000 0000 0000 0000 0000 0111
    #   private exponent = 23 = 0x00000017 = 0000 0000 0000 0000 0000 0000 0001 0111


    # Open memory
    # with open('/root/Drivers/secondcontrl.ko', 'r+b') as f:
    #     # Memory-map the RSA memory block
    #     mm = mmap.mmap(f.fileno(), 160) # Reading entire file will read a '\0' char
    # # Set the inputs
    # mm[32:64] = inMod
    # mm[64:96] = inExp
    # mm[96:128] = inData
    # # Signal ready for run
    # mm[0:16] = '0000000000000001'
    # # Read again until HW load flag is asserted
    # while (int(mm[16:32], 2) is not 0x1):
    #     pass
    #     # mm.seek(0)
    #     # Should I wait some time?
    # # Set SW load flag to low
    # mm[0:16] = '0000000000000000'
    # # Read the resulting output
    # output = mm[128:160]
    # return output
    return inData


# Pads a data block
def padBlock(data, blockSize):
    return (data + ((blockSize -len(data) % blockSize) + 1) * paddingChar)[:blockSize]


# Cipher Block Chaining Encryption
def encrypt_CBC(key, data, algorithm, enableHW):
    # print 'Data start: ' + data
    # print key

    # Set block size
    blockSize = 0
    if algorithm is 'AES128':
        blockSize = AES128BlockSize
    if algorithm is 'RSA':
        blockSize = RSABlockSize

    # Generate IV
    IV = generateIV(blockSize, 'Binary')
    # print('IV: ' + str(IV))

    ######
    # Forces repition in encryptions for RSA demonstration
    if algorithm is 'RSA':
        IV = '10000000001101110011011110100010'


    # With hardware acceleration
    if enableHW is True:
        # Data and cipher block arrays
        dataBlocks = [ data[i : i + blockSize] for i in range(0, len(data), blockSize) ]
        cipherBlocks = []

        # Add padding to last block before encrypting
        dataBlocks[-1] = padBlock(dataBlocks[-1], blockSize)
        # print 'Data blocks: '
        # print dataBlocks

        # Loop through all dataBlocks
        for block in dataBlocks:
            # print 'Block: ' + block

            # Holds the data input to crypto algorithm
            dataInput = block

            # First block uses IV
            if len(cipherBlocks) is 0:
                # XOR plaintext with IV
                # print('Binary IV')
                # print('{:0128b}'.format(int(IV,2)))
                # print('Binary data')
                # print(format(int(dataInput,2), '08b'))
                dataInput = '{:0{width}b}'.format(int(IV,2) ^ int(dataInput,2), width=blockSize)
                # print 'Block after XOR with IV ' + IV + ': '
                # print dataInput

            # All other blocks use the preceding cipher block
            else:
                # XOR block with previous cipher block (currently last in array)
                dataInput = '{:0{width}b}'.format(int(cipherBlocks[-1],2) ^ int(dataInput,2), width=blockSize)
                # print 'Block after XOR with ' + cipherBlocks[-1] + ': '
                # print dataInput

            # Encrypt dataInput
            if algorithm is 'AES128':
                cipherBlocks += [ str(AES128_HWCore(key, dataInput, 'Encrypt')) ]
            if algorithm is 'RSA':
                cipherBlocks += [ str(RSA_HWCore(key, dataInput, 'Encrypt')) ]

        # Join cipherBlocks
        cipher = ''.join(cipherBlocks)
        # print 'Encrypted data: ' + cipher

        # Return IV, cipher
        return IV, cipher

    # Python crypto library
    else:
        # AES128
        if algorithm is 'AES128':
            # Return IV, cipher
            return IV, AES.new(key, AES.MODE_CBC, IV).encrypt(data)
        # RSA
        if algorithm is 'RSA':
            # Return IV, cipher
            return IV, AES.new(key, AES.MODE_CBC, IV).encrypt(data)


# Cipher Block Chaining Decryption
def decrypt_CBC(key, cipher, IV, algorithm, enableHW):

    global T300_T400_Counter
    global keyID

    # cipher = '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111110100000001100000001'
    # cipher = '01FA030115DCFC8122EFB9C811BEEB9D5DE9B8D10416472E'
    # cipher = '000000000000000000000000000000000000000001FA0301'
# 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111110100000001100000001

    # print('\t\tCipher: ' + '%0*X' % ((len(cipher) + 3) // 4, int(cipher, 2)))
    # print key


    # Set block size
    blockSize = 0
    if algorithm is 'AES128':
        blockSize = AES128BlockSize
    if algorithm is 'RSA':
        blockSize = RSABlockSize

    # With hardware acceleration
    if enableHW is True:
        # Data and cipher block arrays
        cipherBlocks = [ cipher[i : i + blockSize] for i in range(0, len(cipher), blockSize) ]
        dataBlocks = []
        # print('Cipher blocks: ')
        # print(str(cipherBlocks))

        roundCount = 1
        T300_T400_Counter = 0

        # Loop through all cipherBlocks
        for block in cipherBlocks:
            # print('Block: ' + str(block))


            # Decrypt
            if algorithm is 'AES128':
                cipherOutput = str(AES128_HWCore(key, block, 'Decrypt'))
            if algorithm is 'RSA':
                cipherOutput = str(RSA_HWCore(key, block, 'Decrypt'))

                # falseOutput = generateKey(8)
                falseOutput = '%08X' % random.randrange(16**8)

                if roundCount == 1 or roundCount == 6:
                    print('\t\tRound ' + str(roundCount))
                    # print('\t\t\tInput Block\t' + '%0*X' % ((len(block) + 3) // 4, int(block, 2)))

                    print('\t\t\tTFree Output\t' + falseOutput)


                    # T100 Trigger (See SessionKey Note in clientSimpleTLSHandshake)
                    #   87959B63
                    if(str(block) == '10000111100101011001101101100011'):
                        print('\t\t\tT100 Output\t' + '00000017 **KEY LEAK**')
                        print('\t\t\tT100 SB Output\t' + '00000000')
                    else:
                        print('\t\t\tT100 Output\t' + falseOutput)
                        print('\t\t\tT100 SB Output\t' + falseOutput)


                    # T200 Trigger (See SessionKey Note in clientSimpleTLSHandshake)
                    #   8D889D66
                    if(str(block) == '10001101100010001001110101100110'):
                        print('\t\t\tT200 Output\t' + '00000017 **KEY LEAK**')
                        print('\t\t\tT200 SB Output\t' + '00000000')
                    else:
                        print('\t\t\tT200 Output\t' + falseOutput)
                        print('\t\t\tT200 SB Output\t' + falseOutput)


                    # T300 Trigger
                    if(T300_T400_Counter > 2):
                        print('\t\t\tT300 Output\t' + '00000017 **KEY LEAK**')
                    else:
                        print('\t\t\tT300 Output\t' + falseOutput)
                    print('\t\t\tT300 SB Output\t' + falseOutput)


                    # T400 Trigger
                    #   Sets 4 possible combinations with session keys to reflect an #  #     operation with the Injected key

                    # print('cipher:' + str(cipher))

                    if(T300_T400_Counter > 2):
                        print('\t\t\tT400 Output\t' + '%08X' % random.randrange(16**8) + ' **KEY INJECTION**')
                    else:
                        print('\t\t\tT400 Output\t' + falseOutput)

                    print('\t\t\tT400 SB Output\t' + falseOutput)

                # Increment RSA_ds signal counter
                T300_T400_Counter += 1


            # Add to block collection
            dataBlocks += [ cipherOutput ]

            # First block uses IV
            if len(dataBlocks) is 1:
                # XOR plaintext with IV
                cipherOutput = '{:0{width}b}'.format(int(IV,2) ^ int(cipherOutput,2), width=blockSize)
                # print 'Block after XOR with IV ' + IV + ': '
                # print cipherOutput

            # All other blocks use the preceding data block
            else:
                # XOR block with previous data block (currently last in array)
                cipherOutput = '{:0{width}b}'.format(int(cipherBlocks[len(dataBlocks)-2],2) ^ int(cipherOutput,2), width=blockSize)
                # print 'Block after XOR with ' + cipherBlocks[len(dataBlocks)-2] + ': '
                # print cipherOutput
            # Update the block to the digest
            dataBlocks[-1] = cipherOutput

            roundCount += 1

        # Strip any padding added
        # dataBlocks[-1].strip(paddingChar)

        # Join dataBlocks
        data = ''.join(dataBlocks)#.strip(paddingChar)
        # print 'Decrypted data: ' + data

        # Return data
        return data

    # Python crypto library
    else:
        # AES128
        if algorithm is 'AES128':
            # Return data
            return AES.new(key, AES.MODE_CBC, IV).decrypt(cipher)
        # RSA
        # if algorithm is 'RSA':
            # Return IV, cipher
            # return IV, AES.new(key, AES.MODE_CBC, IV).encrypt(data)


# Generate IV based on argument options
def generateIV(blockSize, encoding):
    # Binary IV of blockSize bits
    if encoding is 'Binary':
        return ''.join(str(random.randint(0, 1)) for i in range(blockSize))
    # Hex IV of blockSize hex characters
    if encoding is 'Hex':
        return ''.join(hex(random.randint(0, 16))[2:] for i in range(blockSize))
    # # ASCII IV of blockSize characters
    # if encoding is 'ASCII':
    #     return ''.join(chr(random.randint(0, 255))[2:] for i in range(blockSize))



# TLSS/SL Summary
# 1. Client connects to server, shares certificate, asks server to identify itself
# 2.    Server sends certficate
# 3. Verify certificate against trusted certifcate authorities
#       - If enexpired, unrevoked, and common name is relevant for server
#           - Create, encrypt (with server public key), and send AES session key
# 4.    Server decrypts session key, send acknowlegement (encrypted with session key)
# .... All proceeding transmissions encrypted with session key


# Perform simplified TLS handshake as server
#   Returns secret AES session key negotiated
def serverSimpleTLSHandshake(serverPubKey, serverPrivateKey, socket):

    # Socket is pre-connected to client
    #   Listen for handshake start
    response = socket.recv(1024).decode()
    print('\t1)\tClient Handshake Request: ' + str(response))

    # Respond with the server public key
    message = delimiter.join((str(serverPubKey[0]), str(serverPubKey[1])))
    # print('\tSending Server Public Key: ' + message)
    print('\t2)\tSending Server Public Key: ' + str(serverPubKey))
    socket.send(message.encode())


    # Listen for sessionKey (encrypted with serverPubKey)
    response = socket.recv(1024).decode()
    # print('\tReceived Encrypted SessionKey: ' + str(codecs.encode(b'response', 'hex')))

    # Extract IV and cipher
    # IV = data[0 : RSABlockSize/8]
    # cipher = data[RSABlockSize/8 : ]

    print('\t3)\tReceived Encrypted Session Key')


    print('\t\tBeginning RSA Decryption of Session Key with HW Engine...')
    print('\t\t\tAvailable HW Cores: ' + 'Trust-Hub BasicRSA (TFree, T100, T200, T300, T400)')
    print('\t\t\t--Utilizing HW Sandbox')

    print('\t\t\t\tPrivate Key: \t' + str(serverPrivateKey[0]) + " (Hex: 00000017)")

    print('\t\t\t\tModulus: \t' + str(serverPrivateKey[1]) + " (Hex: 0000004D)")
    print('')


    # Decrypt session key
    sessionKey = decryptText(serverPrivateKey, str(response), 'CBC', 'RSA')
    # sessionKey = decryptText(serverPrivateKey, str(response), 'CBC', 'RSA')

    print('\t\tDecrypted SessionKey: ' + sessionKey)

    # Send ack encrypted with sessionKey
    ack = "TLS-SUCCESS"

    message = encryptText(sessionKey, ack, 'CBC', 'AES128')
    # print('\tSending Server Encrypted Ack: ' + str(message))
    print('\t4)\tSending Server Encrypted Ack')
    print('\t\tServer Decrypted Ack: ' + ack)

    socket.send(message.encode())

    return sessionKey


# Perform simplified TLS handshake as client
#   Returns secret AES session key negotiated
def clientSimpleTLSHandshake(clientPubKey, socket):
    global keys

    # Socket is pre-connected to server
    print('\t1)\tStarting Simlple TLS Handshake')

    # Share the client public key and flag the start of handshake
    message = "TLS-START"
    socket.send(message.encode())

    # Listen for server's response containing its public key
    serverPubKey = socket.recv(1024).decode()
    serverPubKey = str(serverPubKey).split(delimiter)
    print('\t2)\tServer Public Key: ' + str(serverPubKey))

    # No verification via certificate authorities in simple handshake

    # Generate session key and encrypt with server public key
    sessionKey = generateKey(int(AES128BlockSize/8))

    #######
    # Forces repitition for RSA demonstration
    #   43W71HQD6YRJXKG5 - Triggers T100
    #   64RAXXAON5FMV6CE - Triggers T200
    keys = ['43W71HQD6YRJXKG5', '64RAXXAON5FMV6CE', 'ZZ9YVPWPH3Z3SRCS', 'T0163ISV2O6RP2BK']

    sessionKey = random.choice(keys)

    print('\t\tSessionKey: ' + str(sessionKey))
    # print('\t\tSessionKey(Hex): ' + str(codecs.encode(b'sessionKey', 'hex')))



    message = encryptText(serverPubKey, str(sessionKey), 'CBC', 'RSA')
    # print('\tSessionKey Encryption Digest: ' + str(codecs.encode(b'message', 'hex')))
    print('\t3)\tSending Encrypted Session Key')
    socket.send(message.encode())

    # Await an acknowledgement encrypted with generated sessionKey
    response = socket.recv(1024).decode()
    # print('Server Encrypted Ack: ' + str(response))

    # # Extract IV and cipher
    # IV = data[0 : RSABlockSize/8]
    # cipher = data[RSABlockSize/8 : ]

    # Decrypt
    ack = decryptText(sessionKey, str(response), 'CBC', 'AES128')
    print('\t4)\tServer Decrypted Ack: ' + ack)

    # Verify
    if 'TLS-SUCCESS' in ack:
        return sessionKey
    else:
        # Kill the connection
        socket.close()

        return False


# Perform TLS handshake as server
#   Returns secret AES session key negotiated
def serverTLSHandshake(certificate, clientPubKey, socket):
    # Socket is pre-connected to client
    return 0


# Perform TLS handshake as client
#   Returns secret AES session key negotiated
def clientTLSHandshake(certificate, serverPubKey, socket):
    # Socket is pre-connected to server
    return 0
