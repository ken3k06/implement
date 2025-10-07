# sẽ fix sau
from sage.all import *
# Documents and syntax: 
# [1]https://doc.sagemath.org/html/en/reference/matrices/index.html
# [2]

# tất cả các thuật đều trên full-rank lattice, nên chú ý nhập các ma trận vuông mới chạy oke
# using flatter:
def flatter(M):
    import os
    import re
    from subprocess import check_output
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    env = os.environ.copy()
    env["OMP_NUM_THREADS"] = str(os.cpu_count() or 8)
    ret = check_output(["flatter"], input=z.encode(), env=env)
    return matrix(M.nrows(), M.ncols(), map(int, re.findall(rb"-?\d+", ret)))
M = Matrix([[-10 , -8 , 10 , -2],
[ -2 , -6 , -3 , -1],
[ -3,  10  ,-8 , -8],
[  1,  -2, -10,  -6]])


def toList(mat):
    return [mat[i] for i in range(mat.nrows())]
# pure python + sage matrix supporter
# M = Matrix(ZZ,[[4, 1, 7, -1],[2, 1, -3, 4], [1, 0, -2, 7], [6, 2, 9, -5]])
def gram_schmidt(mat):
    u = []
    v = toList(mat)
    n = mat.nrows()
    mu = Matrix(QQ, mat.nrows(), mat.ncols())
    n = mat.nrows()
    for i in range(n):
        vi = v[i]
        for j in range(i):
            mu[i,j] = (vi * u[j]) / (u[j]*u[j])
            vi = vi - mu[i,j] * u[j]
        u.append(vi)
    mu[0,0] = 1
    return Matrix(QQ, u), Matrix(QQ, mu)
def print_mat(mat):
    for row in mat:
        print(row,'\n')

_, riel = M.gram_schmidt()
_ , mu = gram_schmidt(M)
assert mu[0,0] == riel[0,0]
def my_LLL(mat, delta= 0.99):
    mat = Matrix(QQ,mat)
    ortho, mu = mat.gram_schmidt()
    k = 1
    n = ortho.nrows()
    while k < n :
        for j in range(k-1, -1,-1):
            prod = (mu[k,j])
            if abs(prod) > 1/2:
                mat[k] = mat[k] - round(prod)*mat[j]
                ortho , mu = mat.gram_schmidt()
        if (ortho[k].dot_product(ortho[k])) >= (delta-mu[k,k-1]**2)*(ortho[k-1].dot_product(ortho[k-1])):
            k +=1
        else:
            mat[k], mat[k-1] = mat[k-1], mat[k]
            ortho , mu = mat.gram_schmidt()
            k = max(k-1, 1)
    return mat 
def size_reduce(B):
    d = B.nrows()
    i = 1
    while i<d:
        Bs,M = B.gram_schmidt()
        for j in reversed(range(i)):
            B[i] -= round(M[i,j])*B[j]
            Bs,M = B.gram_schmidt()
    return B
# def my_fixed_LLL(mat,delta = 0.99):
#     mat = Matrix(QQ,mat)
#     ortho, mu = 


print(flatter(M),"\n")
print(M.LLL(),"\n")
print(my_LLL(M,delta=0.99))



# sao dòng cuối nó k swap vậy?
# lưu ý là hàm LLL của sage nó có delta = 0.99, còn hàm mình viết là 0.75
# delta càng lớn thì càng khó để swap, nên kết quả sẽ khác nhau
# delta = 0.75 thì sẽ swap nhiều hơn, nên kết quả sẽ ngắn hơn, do mình để 0.75 nên nó không swap 2 hàng cuối

def compare_mat(mat1, mat2):
    if mat1.nrows() != mat2.nrows() or mat1.ncols() != mat2.ncols():
        return False
    for i in range(mat1.nrows()):
        if mat1[i] != mat2[i]:
            return False
    return True
for _ in range(100):
    M = Matrix(ZZ,[[randint(-100,100) for _ in range(5)] for _ in range(5)])
    res1 = my_LLL(M)
    res2 = M.LLL()
    if not compare_mat(res1, res2):
        print(_)
        print("Mismatch found!")
        print("Input matrix:")
        print(M)
        print("Custom LLL result:")
        print(res1)
        print("Sage LLL result:")
        print(res2)
        break
else:
    print("All tests passed!")



for  _ in range(100):
    M = random_matrix(ZZ,5,5)
    res1,_ = gram_schmidt(M)
    res2, _ = M.gram_schmidt()
    if not compare_mat(res1,res2):
        print(_)
        print("Mismatch found!")
        print("Input matrix:")
        print(M)
        print("Custom LLL result:")
        print(res1)
        print("Sage LLL result:")
        print(res2)
        break
else:
    print("All tests passed!")


def babai_CVP(mat, t,opt=0):
    if opt == 1:
        B = mat.LLL(delta = 0.75)
    else:
        B = my_LLL(mat, delta = 0.75)
    G = gram_schmidt(B)[0]
    b = t
    n = B.nrows()
    for i in reversed(range(n)):
        c_i = ((b.dot_product(G[i]))/(G[i].dot_product(G[i]))).round()
        b = b - c_i*B[i]
    return vector(QQ,t) - b  


def kanna_embedding_cvp(mat, t, opt=0):
    n = mat.nrows()
    m = mat.ncols()
    B_ = matrix(QQ, mat)                   
    zero_col = vector(QQ, [0] * n)          
    B_ = B_.augment(zero_col)              
    last_row = vector(QQ, list(t) + [1])    
    B_ = B_.stack(last_row)                 
    if opt == 1:
        B = B_.LLL(delta=0.75)
    else:
        B = my_LLL(B_, delta=0.75)
    for row in B.rows():
        last = row[-1]
        first_part = vector(QQ, row[:m])   
        if last == 1:
            return vector(QQ, t) - first_part
        if last == -1:
            return vector(QQ, t) + first_part
    return None
M = Matrix(ZZ, [[35,72,-100],[-10,0,-25],[-20,-279,678]])
target = vector(ZZ,[100,100,100])

res1 = babai_CVP(M,target)
res2 = kanna_embedding_cvp(M,target, opt = 1)
print(res1, '\n')
print(res2)





    
