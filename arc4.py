import random
import copy
import requests
import json

def list_to_hex(lst):
    return ''.join(f'{x:02x}' for x in lst)


def ksa_server_side(iv):
    return bytes.fromhex(json.loads(requests.get(f"https://aes.cryptohack.org/oh_snap/send_cmd/70696e67/{list_to_hex(iv)}/").text)["error"][17:])[0]


print(ksa_server_side([3,253,43]))
candidates = []
plaintext = b"ping"  
FLAG = [byte for byte in b"crypto{AAA}"] 

def most_frequent(arr):
    """Find the most frequently occurring element in a list"""
    return max(set(arr), key=arr.count)

def ksa(key, iterations=0x100):
    """Key Scheduling Algorithm (KSA) for RC4"""
    S = list(range(0x100))
    j = 0
    for i in range(iterations):
        j = (S[i] + key[i % len(key)] + j) & 0xff
        S[i], S[j] = S[j], S[i]
    return S, j

def keystream_generator(S):
    """Generator for RC4 keystream (PRGA)"""
    S = S.copy()
    x = y = 0
    while True:
        x = (x + 1) & 0xff
        y = (S[x] + y) & 0xff
        S[x], S[y] = S[y], S[x]
        yield S[(S[x] + S[y]) & 0xff]




recovered_bytes = []
for i in range(3,50):
    iv = [i, 255, 43]
    candidates = []
    for x in range(256):
        arr = [i, 255, x]
        arr.extend(recovered_bytes)
        SBOX,j=(ksa(arr,i))
        
        iv[2] = x
        val = ksa_server_side(iv)
        # print(val)

        ciphertext_byte = val ^ plaintext[0]
        Q = val ^ plaintext[0] 
        
        candidate = (Q - j - SBOX[i]) % 256
        candidates.append(candidate)

    recovered_byte = most_frequent(candidates)
    print(f"Recovered key byte: {chr(recovered_byte), recovered_byte}")
    recovered_bytes.append(recovered_byte)

# Recovered key byte: ('c', 99)
# Recovered key byte: ('r', 114)
# Recovered key byte: ('y', 121)
# Recovered key byte: ('p', 112)
# Recovered key byte: ('t', 116)
# Recovered key byte: ('o', 111)
# Recovered key byte: ('{', 123)
# Recovered key byte: ('w', 119)
# Recovered key byte: ('1', 49)
# Recovered key byte: ('R', 82)
# Recovered key byte: ('3', 51)
# Recovered key byte: ('d', 100)
# Recovered key byte: ('_', 95)
# Recovered key byte: ('e', 101)
# Recovered key byte: ('q', 113)
# Recovered key byte: ('u', 117)
# Recovered key byte: ('1', 49)
# Recovered key byte: ('v', 118)
# Recovered key byte: ('4', 52)
# Recovered key byte: ('l', 108)
# Recovered key byte: ('3', 51)
# Recovered key byte: ('n', 110)
# Recovered key byte: ('t', 116)
# Recovered key byte: ('_', 95)
# Recovered key byte: ('@', 64)
# Recovered key byte: ('¢', 162)
# Recovered key byte: ('1', 49)
# Recovered key byte: ('v', 118)
# Recovered key byte: ('4', 52)
# Recovered key byte: ('c', 99)
# Recovered key byte: ('y', 121)
# Recovered key byte: ('?', 63)
# Recovered key byte: ('!', 33)
# Recovered key byte: ('}', 125)
