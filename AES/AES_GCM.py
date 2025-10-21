from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES 


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
    L = bytes_to_poly(length_block(len(A),len(C)))
    X = (X + L) * H
    return X

def calculate_tag(key, ct, nonce, ad):
    assert len(nonce) == 12
    E = AES.new(key, AES.MODE_ECB).encrypt
    H = bytes_to_poly(E(b'\x00'*16))
    J0 = nonce + b'\x00\x00\x00\x01'
    S  = ghash(H, ad, ct)
    tag = S + bytes_to_poly(E(J0))
    return poly_to_bytes(tag)

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
# Forbidden attack



def recover_possible_auth_keys(a1, c1, t1, a2, c2, t2):
    '''
    2 msgs được mã hóa bởi cùng 1 Auth key là H = Enc_k(null)
    Chung authkey thì tức là chung key k    
    a1: AAD của msg1 
    c1: ct của msg1
    t1: Auth Tag của msg1
    tương tự 
    '''
    h = F["h"].gen()
    s1 = ghash(h,a1,c1) + bytes_to_poly(t1)
    s2 = ghash(h,a2,c2) + bytes_to_poly(t2)
    for h, _ in (s1+s2).roots():
        yield h 
def forge_tag(h, a, c, t, target_a, target_c):
    '''
    giả mạo một tag hợp lệ cho cặp (target_a, target_c) từ một bộ (h,a,c,t) biết trước
    điều kiện áp dụng là cả hai phải dùng chung nonce 
    '''
    s = bytes_to_poly(t) + ghash(h,a,c)
    forged = s + ghash(h,target_a, target_c)
    return poly_to_bytes(forged)
