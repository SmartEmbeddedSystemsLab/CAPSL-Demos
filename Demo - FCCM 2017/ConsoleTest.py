# Python Console Tests for Register Drivers

import os

filename = '/dev/rsa'
# filename = '/root/test'

size = os.path.getsize(filename)
print(size)

with open(filename, 'r+') as f:
    print(f)
    # print(f.readline())
    # print(f.readline())
    # print(f.readline())
    # print(f.readline())
    # os.lseek(f.fileno(), 0, os.SEEK_SET)
    print(f.read(2))
    f.seek(1, os.SEEK_SET)
    print(f.read(2))
    f.write('100')
    print(f.read(2))
