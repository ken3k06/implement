from sage.all import *
from sage.crypto.sbox import SBox
from Crypto.Util.number import bytes_to_long
from sage.crypto.sboxes import AES

# Tài liệu sử dụng: 
# [1] https://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/sbox.html
# [2] https://nguyenquanicd.blogspot.com/2019/09/aes-bai-1-ly-thuyet-ve-ma-hoa-aes-128.html
# [3] https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf?

N_ROUNDS = 10
# Bước xử lí dữ liệu
F.<y> = GF(2)[]
G.<x> = GF(2**8,name ='x', modulus = y**8+y**4+y**3+y+1)
R.<z> = PolynomialRing(G)
def bytes_to_poly(v):
    v = int.from_bytes(v,'big')
    v = G._cache.fetch_int(v)
    return v  
def poly_to_bytes(b):
    po = b.polynomial()
    val =  sum(1<<i for i, x in enumerate(po.coefficients(sparse=False)) if x)
    return val.to_bytes(1,'big')
c = b'T'
assert poly_to_bytes(bytes_to_poly(c)) == c 


def bytes_to_matrix(block):
    assert len(block) == 16  
    M = Matrix(G, 4, 4)
    for c in range(4):
        for r in range(4):
            M[r,c] = bytes_to_poly(bytes([block[4*c+r]]))
    return M
def matrix_to_bytes(mat):
    res = []
    for c in range(4):
        for r in range(4):
            res.append(poly_to_bytes(mat[r,c]))
    return b''.join(res)

text = b'crypto{inmatrix}'

print(bytes_to_matrix(text))
print(matrix_to_bytes(bytes_to_matrix(text)))
S_box = SBox(AES)

inv_S = [0]*256
for idx, val in enumerate(AES): 
    inv_S[val] = idx
inv_Sbox = SBox(inv_S)

def add_round_key(s,k):
    for r in range(4):
        for c in range(4):
            s[r,c] += k[r,c]

def sub_bytes(s, box):
    for i in range(4):
        for j in range(4):
            val = box[int.from_bytes(poly_to_bytes(s[i,j]),'big')]
            s[i,j] = G._cache.fetch_int(val)



two = G._cache.fetch_int(0x02)
three = G._cache.fetch_int(0x03)
one = G._cache.fetch_int(0x01)
def mix_one_columns(col):
    assert len(col) == 4
    a0, a1 , a2, a3 = col
    return [
        two*a0+three*a1+a2+a3,
        a0+two*a1+three*a2+a3,
        a0+a1+two*a2+three*a3,
        three*a0+a1+a2+two*a3
    ]
col_bytes = [0xdb, 0x13, 0x53, 0x45]
col = [G._cache.fetch_int(b) for b in col_bytes]
print([int.from_bytes(poly_to_bytes(x)) for x in mix_one_columns(col)])
# ok  
def mix_one_columns_poly(col):
    assert len(col) == 4
    a = three*z**3+one*z**2+one*z+two   
    modulo = z**4+1
    a0, a1, a2, a3 = col 
    poly = a3*z**3+a2*z**2+a1*z+a0
    prod = (poly*a) % (z**4+1)
    l = prod.coefficients(sparse = False)
    return l 

col_bytes = [0xdb, 0x13, 0x53, 0x45]
col = [G._cache.fetch_int(b) for b in col_bytes]
l = mix_one_columns_poly(col)
new_l = [G(p) for p in l]

res = [int.from_bytes(poly_to_bytes(x)) for x in new_l]
print(res)


assert res == [int.from_bytes(poly_to_bytes(x)) for x in mix_one_columns(col)]

      
def mix_columns(s):
    col = [[s[i,j] for i in range(4)] for j in range(4)]
    R = Matrix(G,4,4)
    for c in range(4):
        col = [s[r,c] for r in range(4)]    
        new = mix_one_columns(col)
        for r in range(4):
            R[r,c] = new[r]
    return R
def shift_rows(s):
    s[0,1], s[1,1], s[2,1], s[3,1] = s[1,1], s[2,1], s[3,1], s[0,1]
    s[0,2], s[1,2], s[2,2], s[3,2] = s[2,2], s[3,2], s[0,2], s[1,2]
    s[0,3], s[1,3], s[2,3], s[3,3] = s[3,3], s[0,3], s[1,3], s[2,3]


def inv_shift_rows(s):
    s[0,1], s[1,1], s[2,1], s[3,1] = s[3,1], s[0,1], s[1,1], s[2,1]
    s[0,2], s[1,2], s[2,2], s[3,2] = s[2,2], s[3,2], s[0,2], s[1,2]
    s[0,3], s[1,3], s[2,3], s[3,3] = s[1,3], s[2,3], s[3,3], s[0,3]



def expand_key(master_key):
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )
    key_columns = bytes_to_matrix(master_key)
    iteration_size = len(master_key) // 4
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.   
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # Map to S-BOX.
            word = [S_box[b] for b in word]
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Run word through S-box in the fourth iteration when using a
            # 256-bit key.
            word = [S_box[b] for b in word]

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]



# def encrypt(key, plaintext):

# def decrypt(key, ciphertext):
