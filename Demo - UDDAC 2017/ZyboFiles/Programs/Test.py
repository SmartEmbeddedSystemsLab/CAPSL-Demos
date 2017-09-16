# RSA_Test.py - RSA Core Test
#  Author: Taylor JL Whitaker - SmartES Lab
#  Date: 13 June 2017
#
#  This file is made to test the BasicRSA IP from Trust-Hub.org
#    utilized for trojan evaluations with embedded linux applications.
#    It encrypts a value with a private key and decrypts the result with
#    the public key. Success if final result is equal to intial input.
#
#  RSA Device Memory (Eight 32 bit registers, 28 bytes used)
#    [0] Reset     (0)
#    [1] SWReady   (0)
#    [2] Exponent  (31 downto 0)
#    [3] Modulus   (31 downto 0)
#    [4] DataIn    (31 downto 0)
#    [5] HWReady   (0)
#    [6] DataOut   (31 downto 0)
#    [8] Empty


import subprocess

def readAll(DeviceMemory):
    NoPrint = DeviceMemory.seek(0,0)
    registers = DeviceMemory.read(28)

    print('Reset\t\t' + str(int.from_bytes(registers[0:4], byteorder='little')))
    print('SWReady\t\t' + str(int.from_bytes(registers[4:8], byteorder='little')))
    print('Exponent\t' + str(int.from_bytes(registers[8:12], byteorder='little')))
    print('Modulus\t\t' + str(int.from_bytes(registers[12:16], byteorder='little')))
    print('DataIn\t\t' + str(int.from_bytes(registers[16:20], byteorder='little')))
    print('HWReady\t\t' + str(int.from_bytes(registers[20:24], byteorder='little')))
    print('DataOut\t\t' + str(int.from_bytes(registers[24:28], byteorder='little')))

# Using binary blocks
PubExp = '00000000000000000000000000001011'  # 11
PrivExp = '00000000000000000000000000010111' # 23
Modulus = '00000000000000000000000100101101' # 301
Block = '00000000000000000000000000001001'  # 9
High = '1'
Low = '0'

BlockOut = '00000000000000000000000000000000'


# Main
with open('/dev/rsa', 'rb') as f:

    # Read device state
    print('Starting Device State')
    readAll(f)

    f.close()

# Toggle Reset and set all registers to 0
args = ['./rsawrite', '-device', '/dev/rsa', '-reset', High, '-ready', Low, '-exp', Low, '-mod', Low, '-block', Low]
p = subprocess.Popen(args)
p.wait()
args = ['./rsawrite', '-device', '/dev/rsa', '-reset', Low]
p = subprocess.Popen(args)
p.wait()

# Toggle SWReady to purge
args = ['./rsawrite', '-device', '/dev/rsa', '-ready', High]
p = subprocess.Popen(args)
p.wait()
args = ['./rsawrite', '-device', '/dev/rsa', '-ready', Low]
p = subprocess.Popen(args)
p.wait()


# Write data for encryption with private key
args = ['./rsawrite', '-device', '/dev/rsa', '-exp', PrivExp, '-mod', Modulus, '-block', Block]
p = subprocess.Popen(args)
p.wait()

# Toggle SWReady
args = ['./rsawrite', '-device', '/dev/rsa', '-ready', High]
p = subprocess.Popen(args)
p.wait()
args = ['./rsawrite', '-device', '/dev/rsa', '-ready', Low]
p = subprocess.Popen(args)
p.wait()


# Read device state
with open('/dev/rsa', 'rb') as f:

    # Get DataOut
    registers = f.read(28)
    BlockOut = "{0:0>32b}".format(int.from_bytes(registers[24:28], byteorder='little'))

    # readAll(f)
    f.close()


# Write data for decryption with public key
args = ['./rsawrite', '-device', '/dev/rsa', '-exp', PubExp, '-mod', Modulus, '-block', BlockOut]
p = subprocess.Popen(args)
p.wait()


# Toggle SWReady
args = ['./rsawrite', '-device', '/dev/rsa', '-ready', High]
p = subprocess.Popen(args)
p.wait()
args = ['./rsawrite', '-device', '/dev/rsa', '-ready', Low]
p = subprocess.Popen(args)
p.wait()


# Read device state
with open('/dev/rsa', 'rb') as f:

    # Get DataOut
    registers = f.read(28)
    BlockOut = "{0:0>32b}".format(int.from_bytes(registers[24:28], byteorder='little'))

    print('\nFinal Device State')
    readAll(f)
    f.close()


if BlockOut == Block:
    print('RSA TEST SUCCESS\n')
else:
    print('RSA TEST FAILURE\n')
