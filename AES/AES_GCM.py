from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES 
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

def calculate_tag(key, ct, nonce, ad):
    y = AES.new(key, AES.MODE_ECB).encrypt(bytes(16))
    s = AES.new(key, AES.MODE_ECB).encrypt(nonce + b"\x00\x00\x00\x01")
    assert len(nonce) == 12
    y = bytes_to_poly(y)

    l = length_block(len(ad), len(ct))

    blocks = nullpad(ad) + nullpad(ct)
    bl = len(blocks) // 16

    blocks = [blocks[16 * i:16 * (i + 1)] for i in range(bl)]
    blocks.append(l)
    blocks.append(s)

    tag = F(0)
    
    for exp, block in enumerate(blocks[::-1]):
        tag += y**exp * bytes_to_poly(block)

    tag = poly_to_bytes(tag)

    return tag

def check():
    key = os.urandom(16)
    nonce = os.urandom(12)

    ad = os.urandom(os.urandom(1)[0])
    pt = os.urandom(os.urandom(1)[0])
    
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(ad)
    ct, tag = cipher.encrypt_and_digest(pt)

    assert tag == calculate_tag(key, ct, nonce, ad)

if __name__ == "__main__":
    check()
