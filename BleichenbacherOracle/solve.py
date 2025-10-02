from Crypto.Util.number import *
import random
def ceil_div(x, y):
    return x//y + (1 if x%y else 0)
def floor_div(x, y):
    return x//y
keysize = 256
p = getPrime(keysize//2)
q = getPrime(keysize//2)
e = 65537
phi = (p-1)*(q-1)
d = inverse(e, phi)
N = p*q
k = (N.bit_length() + 7)//8
B = 2**(8*(k-2))
def pkcs1_pad(m):
    pad_len = k - len(m) - 3
    pad = b''
    while len(pad) < pad_len:
        pad += bytes([random.randint(1,255)])
    return b'\x00\x02' + pad + b'\x00' + m
def oracle(c):
    m = pow(c, d, N)
    msg = long_to_bytes(m, k)
    if len(msg) < k:
        msg = b'\x00'*(k-len(msg)) + msg
    if not (msg[0] == 0 and msg[1] == 2):
        return False  
    separator_idx = None
    for i in range(2, len(msg)):
        if msg[i] == 0:
            separator_idx = i
            break
    if separator_idx is None or separator_idx < 10:
        return False
    for i in range(2, separator_idx):
        if msg[i] == 0:
            return False
    return True

def step1(c):
    if oracle(c):
        return 1, c
    s0 = 1
    c0 = c
    while not oracle(c0):
        s0 = random.randrange(2, N)
        c0 = (c * pow(s0, e, N)) % N
    return s0, c0

def step2a(c0):
    s = ceil_div(N, 3*B)
    while True:
        c1 = (c0 * pow(s, e, N)) % N
        if oracle(c1):
            return s, c1
        s += 1

def step2b(c0, prev_s):
    s = prev_s + 1
    while True:
        c1 = (c0 * pow(s, e, N)) % N
        if oracle(c1):
            return s, c1
        s += 1

def step2c(c0, prev_s, a, b):
    r = ceil_div(a*prev_s - (3*B - 1), N)
    while True:
        left = ceil_div(2*B + r*N, b)
        right = floor_div(3*B - 1 + r*N, a)
        for s in range(left, right+1):
            c1 = (c0 * pow(s, e, N)) % N
            if oracle(c1):
                return s, c1
        r += 1

def insert_and_merge(M, new):
    a, b = new
    merged = []
    for x, y in M:
        if y < a or x > b:
            merged.append((x, y))
        else:
            a = min(a, x)
            b = max(b, y)
    merged.append((a, b))
    return merged

def step3(prev_M, s):
    M = []
    for a, b in prev_M:
        r_min = ceil_div(a*s - (3*B - 1), N)
        r_max = floor_div(b*s - 2*B, N)
        for r in range(r_min, r_max+1):
            a1 = ceil_div(2*B + r*N, s)
            b1 = floor_div(3*B - 1 + r*N, s)
            if a1 <= b1:
                M = insert_and_merge(M, (a1, b1))
    return sorted(M, key=lambda x: x[0])

def bleichenbacher_attack(c):
    s0, c0 = step1(c)
    M = [(2*B, 3*B - 1)]
    i, s, c_i = 1, None, c0
    while True:
        if i == 1:
            s, c_i = step2a(c0)
        elif len(M) > 1:
            s, c_i = step2b(c0, s)
        else:
            a,b = M[0]
            s, c_i = step2c(c0, s, a, b)
        M = step3(M, s)
        if len(M)==1 and M[0][0]==M[0][1]:
            m = M[0][0]
            inv_s0 = inverse(s0, N)
            return (m * inv_s0) % N
        i += 1

def extract_message(padded_msg_int):
    msg = long_to_bytes(padded_msg_int, k)
    if len(msg) < k:
        msg = b'\x00'*(k-len(msg)) + msg
    separator_idx = None
    for i in range(2, len(msg)):
        if msg[i] == 0:
            separator_idx = i
            break
    
    if separator_idx is None:
        return None
    return msg[separator_idx+1:]
