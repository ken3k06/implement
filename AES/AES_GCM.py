from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES 
from pwn import * 
from tqdm import tqdm 
import requests 
import json 

context.log_level = 'debug'

# helper functions

a = GF(2)['a'].gen()
F = GF(2**128, name = 'x' ,modulus = a**128+a**7+a**2+a+1)
def nullpad(msg):
    return bytes(msg) + b'\x00' *(-len(msg) % 16)
def un_nullpad(msg):
    return bytes(msg).strip(b'\x00')
c = b'test'
assert un_nullpad(nullpad(c)) == c 


def bytes_to_n(b):
    v = int.from_bytes(nullpad(b),'big')
    return int(f"{v:0128b}"[::-1],2)
def bytes_to_poly(b):
    return F.from_integer(bytes_to_n(b))
def poly_to_n(p):
    v = p.to_integer()
    return int(f"{v:0128b}"[::-1],2)
def poly_to_bytes(p):
    return poly_to_n(p).to_bytes(16,'big')
def length_block(lad, lct):
    return int(lad * 8).to_bytes(8, 'big') + int(lct * 8).to_bytes(8, 'big')
def ghash(H, A, C):
    X = F(0)
    for i in range(0, len(A) + (-len(A) % 16), 16):
        B = (A + b'\x00'*16)[i:i+16]
        X = (X + bytes_to_poly(B)) * H
    for i in range(0, len(C) + (-len(C) % 16), 16):
        B = (C + b'\x00'*16)[i:i+16]
        X = (X + bytes_to_poly(B)) * H
    L = bytes_to_poly((len(A)*8).to_bytes(8,'big') + (len(C)*8).to_bytes(8,'big'))
    X = (X + L) * H
    return X

def calculate_tag(key, ct, nonce, ad):
    assert len(nonce) == 12
    E = AES.new(key, AES.MODE_ECB).encrypt
    H = bytes_to_poly(E(b'\x00'*16))
    J0 = nonce + b'\x00\x00\x00\x01'
    S  = ghash(H, ad, ct)
    return bytes(x ^ y for x, y in zip(E(J0), poly_to_bytes(S)))

def check():
    key = os.urandom(16)
    nonce = os.urandom(12)

    ad = os.urandom(os.urandom(1)[0])
    pt = os.urandom(os.urandom(1)[0])
    
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(ad)
    ct, tag = cipher.encrypt_and_digest(pt)

    assert tag == calculate_tag(key, ct, nonce, ad)
    print("OK")

if __name__ == "__main__":
    check()
