# RunEchoServer.py

import os
import select
import socket
import sys

import SCU


# Set RSA Keys
serverPubKey = ['7', '187']
serverPrivKey = ['23', '187']
# serverPubKey = ['13', '437']
# serverPrivKey = ['61', '437']

# Flags
EnableHWRSACore = False
# EnableHWAES128Core = False
EnableHWAES128Core = True # Force AES as hardware until SW encryption is added
EnableHWRSATrojans = False
EnableHWAES128Trojans = False
EnableHWRSASandbox = False
EnableHWAES128Sandbox = False


# Buffers
#   Key: connection object
clients = {}            # Client socket addresses
sessionKeys = {}        # Client session keys


# Removing client from buffers
def dropClient(connection, errors=None):
    if errors:
        print('Client %s left unexpectedly:' % (clients[connection],))
        print('  \n', errors)
    else:
        print('Client %s left politely\n' % (clients[connection],))
    del clients[connection]
    connection.close()


# Processes the data sent from clients
def processData(data, sessionKey):
    # print('Received encrypted data:')
    # print(data)

    # Decrypt data
    plaintext = SCU.decryptText(sessionKey, data, 'CBC', 'AES128')
    print('\n\tPlaintext: ' + plaintext.strip("\n"))

    print('\tEchoing Encrypted Plaintext')

    # Encrypt data for echo
    #   Returns encryption digest
    return SCU.encryptText(sessionKey, plaintext, 'CBC', 'AES128')



# Check arguments
if len(sys.argv) < 2 or sys.argv[1] == '-h':
    print('Usage: python3 server.py PORT [options]')
    print(' Options:')
    print('\t-h                  Display this menu')
    print('\t-hw [RSA,AES,ALL]   Enables algorithm in HW encryption engine')
    print('\t-t  [RSA,AES,ALL]   Enables available trojan cores (Enables HW also)')
    print('\t-s  [RSA,AES,ALL]   Enables sandbox protection (Enables HW and Trojans also)')
    sys.exit(1)

print('\n\nStarting TLS Echo Server on port ' + sys.argv[1] + '...\n')

# Get options
if len(sys.argv) > 2:
    for optionIndex in range(2, len(sys.argv)):

        # Enable hardware encryption engine
        if(sys.argv[optionIndex]) == "-hw":
            optionIndex += 1
            if(sys.argv[optionIndex]) == "RSA":
                EnableHWRSACore = True
                print('\tRSA HW Acceleration:\tENABLED')

            if(sys.argv[optionIndex]) == "AES":
                EnableHWAES128Core = True
                print('\tAES HW Acceleration:\tENABLED')

            if(sys.argv[optionIndex]) == "ALL":
                EnableHWRSACore = True
                print('\tRSA HW Acceleration:\tENABLED')
                EnableHWAES128Core = True
                print('\tAES HW Acceleration:\tENABLED')

        # Enable hardware encryption and use available trojans
        if(sys.argv[optionIndex]) == "-t":
            optionIndex += 1
            if(sys.argv[optionIndex]) == "RSA":
                EnableHWRSACore = True
                EnableHWRSATrojans = True
                print('\tRSA HW Acceleration:\tENABLED')
                print('\tRSA HW Trojans:\t\tENABLED')

            if(sys.argv[optionIndex]) == "AES":
                EnableHWAES128Core = True
                EnableHWAES128Trojans = True
                print('\tAES HW Acceleration:\tENABLED')
                print('\tAES HW Trojans:\t\tENABLED')

            if(sys.argv[optionIndex]) == "ALL":
                EnableHWRSACore = True
                EnableHWRSATrojans = True
                print('\tRSA HW Acceleration:\tENABLED')
                print('\tRSA HW Trojans:\t\tENABLED')
                EnableHWAES128Core = True
                EnableHWAES128Trojans = True
                print('\tAES HW Acceleration:\tENABLED')
                print('\tAES HW Trojans:\t\tENABLED')


        # Enable hardware encryption and use available trojans
        #   Also enables hardware sandbox
        if(sys.argv[optionIndex]) == "-s":
            optionIndex += 1
            if(sys.argv[optionIndex]) == "RSA":
                EnableHWRSACore = True
                EnableHWRSATrojans = True
                EnableHWRSASandbox = True
                print('\tRSA HW Acceleration:\tENABLED')
                print('\tRSA HW Trojans:\t\tENABLED')
                print('\tRSA HW Sandbox:\t\tENABLED')

            if(sys.argv[optionIndex]) == "AES":
                EnableHWAES128Core = True
                EnableHWAES128Trojans = True
                print('\tAES HW Acceleration:\tENABLED')
                print('\tAES HW Trojans:\t\tENABLED')
                print('\tAES HW Sandbox:\t\tENABLED')

            if(sys.argv[optionIndex]) == "ALL":
                EnableHWRSACore = True
                EnableHWRSATrojans = True
                EnableHWRSASandbox = True
                print('\tRSA HW Acceleration:\tENABLED')
                print('\tRSA HW Trojans:\t\tENABLED')
                print('\tRSA HW Sandbox:\t\tENABLED')

                EnableHWAES128Core = True
                EnableHWAES128Trojans = True
                EnableHWAES128Sandbox = True
                print('\tAES HW Acceleration:\tENABLED')
                print('\tAES HW Trojans:\t\tENABLED')
                print('\tAES HW Sandbox:\t\tENABLED')


# Set directory to script location
dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir


# Set up TCP/IP  echo server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('', int(sys.argv[1])))
server.listen(5)


# Set options
SCU.setOptions([EnableHWRSACore, EnableHWAES128Core, EnableHWRSATrojans, EnableHWAES128Trojans, EnableHWRSASandbox, EnableHWAES128Sandbox])

# Run until stopped
while True:

    # Wait for a connection
    print('Waiting for a connection...')
    connection, client_address = server.accept()
    clients[connection] = client_address

    try:
        print('\nConnection from: ' + str(client_address))

        # Do TLS handshake to get sessionKey
        sessionKeys[connection] = SCU.serverSimpleTLSHandshake(serverPubKey, serverPrivKey, connection)

        # Get the data
        data = connection.recv(1024).decode()
        if data:
            digest = processData(data, sessionKeys[connection])
            connection.send(digest.encode())
        else:
            break

    finally:
        # Clean up the connection
        dropClient(connection)
