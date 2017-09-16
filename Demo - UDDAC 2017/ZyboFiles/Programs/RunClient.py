# RunClient.py

import os
import random
import socket
import sys
import time
from threading import Thread

import SCU

# Set RSA keys
clientPubKey = [11, 301]
clientPrivKey = [23, 301]

# Flags
EnableHWRSACore = True
EnableHWAES128Core = True
EnableHWRSATrojans = False
EnableHWAES128Trojans = False
EnableHWRSASandbox = False
EnableHWAES128Sandbox = False


def randomLine(afile):
    line = next(afile)
    for num, aline in enumerate(afile):
      if random.randrange(num + 2): continue
      line = aline
    return line


# Processes the data returned from server
def processData(ID, message, response, sessionKey):
    # print('Received encrypted data:')
    # print(data)

    # Parse data for IV and cipher
    # IV = data[0:SCU.AES128BlockSize/8]
    # cipher = data[SCU.AES128BlockSize/8:]

    # print('IV:')
    # print(IV)
    # print('Cipher:')
    # print(cipher)

    # print('IV+Cipher: ' + (IV+cipher))

    # Decrypt data
    plaintext = SCU.decryptText(sessionKey, response, 'CBC', 'AES128')
    # print('Plaintext:')
    print('\t' + ID + ' Echo: ' + plaintext)


# Creates a new client and connects to the server
def createClientConnection(ID, serverAddress):

    print('Starting new client: ' + ID)

    # Set up client
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect(serverAddress)

    # Do TLS handshake
    sessionKey = SCU.clientSimpleTLSHandshake(clientPubKey, connection)

    # message = randomLine(open('Wordlist.txt'))
    message = randomLine(open('/root/Programs/TrojanWordlist.txt'))

    print('\t' + ID + ' Message: ' + message)

    # Digest:
    #   Length:-:IV:-:Cipher
    digest = SCU.encryptText(sessionKey, message, 'CBC', 'AES128')

    # data = SCU.delimiter.join((str(messageLength), IV, cipher))
    # print('Length:-:IV:-:Cipher: ')
    # print(str(digest))

    connection.send(digest.encode())
    response = connection.recv(1024).decode()
    # print('Server reponse: ' + response)

    # Process server response
    processData(ID, message, response, sessionKey)

    # Close
    connection.close()


# Main

if len(sys.argv) < 3:
    print('Usage: python client.py HOST PORT')
    sys.exit(1)

dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir


# Set options
SCU.setOptions([EnableHWRSACore, EnableHWAES128Core, EnableHWRSATrojans, EnableHWAES128Trojans, EnableHWRSASandbox, EnableHWAES128Sandbox])

# Spawn threads according to trafficProfiles
# for i in range(100):
i = 0
while True:
    ID = 'Client' + str(i)
    t = Thread(target=createClientConnection, args=(ID, (sys.argv[1], int(sys.argv[2]))))
    t.start()
    i += 1
    time.sleep(5)
