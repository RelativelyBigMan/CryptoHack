#!/usr/bin/env python3

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from os import urandom
import copy
import pwn 
import json


message = b'\xac\xeb\xeaL}\x8f\x03\xf46\xca\xc5W\x1c5\xfb\xfe'
key = b'\xc1\xf6\xc5\x1b\xad\x94\xf5\xa7tVt\x9d\xd0\x87Y\x12'



def check_padding(key,ct):
    ct = bytes.fromhex(ct)
    iv, ct = ct[:16], ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ct)  # does not remove padding
    pts = copy.deepcopy(pt)
    try:
        unpad(pt, 16)
    except ValueError:
        good = False
    else:
        good = True
    # print(pts)
    return good

# p = pwn.remote("socket.cryptohack.org", "13421")
# print(p.recvline())
# p.sendline(json.dumps({"option" : "encrypt"}))
# ct = (json.loads(p.recvline())["ct"])
# print(ct)
# iv = ct[:32]
# ct = ct[32:64]

# def check_padding(key,ct):
#     p.sendline(json.dumps({"option":"unpad", "ct":ct}))
#     # print(json.loads(p.recvline())["result"])
#     if (json.loads(p.recvline())["result"]) == False:
#         # print("notyo")
#         return False
#     else:
#         # print("yo")
#         return True




iv = bytearray(b"\xf7\x93\x72\x32\xa3\x42\x91\xb3\xa3\x92\x23\x11\x01\x40\x99\x12")
zeroed_iv = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
msg = "134cda71718dc34b138e716769a0ac66"

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
message = (cipher.encrypt(bytes.fromhex(msg)))


org_iv = copy.deepcopy(iv)


# check_padding(key,message.hex())
for u in range(0,16):
    iv = [x^u+1 for x in zeroed_iv]
    iv = bytearray(iv)
    # print(iv)
    for i in range(256):
        iv[-1-u] = i
        # print(iv)
        if (check_padding(key,(iv+message).hex())) == True:
            print(i)
            zeroed_iv[-1-u] = i ^ (u + 1) # adds the byte to the iv
            break
print(pwn.xor(zeroed_iv, org_iv).hex())

# p.sendline(json.dumps({"option":"check", "message": pwn.xor(zeroed_iv, org_iv).hex()}))
# print(p.recvline())
# print(p.recvline())
# print(p.recvline())
