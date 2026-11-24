from Crypto.Cipher import AES
from Crypto.Util import strxor
from Crypto import Random
import hashlib
import base64

BLOCK_SIZE = 16
IV_SIZE = 12
COUNTER_SIZE = BLOCK_SIZE - IV_SIZE


def xor(a,b):
    return strxor.strxor(a,b)

#Converts a 128 bit string into a polynomial in GF(2^128) 
#x has to be the unknown in the polynomial. 
def strToPoly(s,x):
    if len(s) != BLOCK_SIZE:
        raise Exception("Need " + str(BLOCK_SIZE) + " bytes string")
    res = 0
    for i in range(BLOCK_SIZE):
        res *= x^8
        temp = s[i]
        for j in range(8):
            res += x^j* ((temp >>j)&1)
    return res

#Converts a polynomial in GF(2^128) into a 128 bitstring
def polyToStr(p):
    coefs = p.polynomial().coefficients(sparse=False)
    coefs.reverse()
    res = 0
    for c in coefs:
        res*= 2
        if c == 1:
            res += 1 
    resStr  = b""
    for i in range(BLOCK_SIZE):
        resStr = (int(res & 0xff)).to_bytes(1,"little") + resStr
        res = res >> 8
    return resStr

#Multiply the 128bit string by the polynomial H. 
#Returns a 128bit-string 
def multByH(b,H,x):
    p = strToPoly(b,x)
    return polyToStr(p*H)

#Increases by 1 ctr which is a bitstring counter. 
def increaseCounter(ctr):
    ctr_int = int.from_bytes(ctr, "big")
    ctr_int += 1
    return int(ctr_int).to_bytes(BLOCK_SIZE, byteorder="big")

# Convert python bytes to GCM NIST format
# The inverse of this function is f itself
def f(x):
    b = '{:0{width}b}'.format(int.from_bytes(x, 'little'), width=128)
    return int(b[::-1], 2).to_bytes(16, 'little')

def authenticate(key, ct, T):
    if len(ct)% BLOCK_SIZE != 0:
        raise Exception("Error: the content to authenticate need to have a length multiple of the blocksize")
    cipher = AES.new(key, AES.MODE_ECB)
    G.<y> = PolynomialRing(GF(2)) #Ring of polynomials over Z_2
    F.<x> = GF(2^128, modulus = y^128 + y^7 + y^2 + y + 1) #GF(2^128) with the GCM modulus
    H = strToPoly(f(cipher.encrypt(b"\x00"*BLOCK_SIZE)), x) 
    tag = b"\x00"*BLOCK_SIZE
    for i in range(len(ct)//BLOCK_SIZE):
        tag = xor(tag, f(ct[BLOCK_SIZE*i: BLOCK_SIZE*(i+1)]))
        tag = multByH(tag, H, x)
    tag = xor(tag, f(T))
    return f(tag) #La fonction f est appelée pour avoir le bon format. 


def CTR(key, IV, m):
    cipher = AES.new(key, AES.MODE_ECB)
    if len(m)%BLOCK_SIZE != 0:
        raise Exception("ERROR: the message length has to be a multiple of the block size")
    ctr = (IV + b"\x00"*(COUNTER_SIZE-1)+b"\x02") 
    ciphertext = []
    for i in range(len(m)//BLOCK_SIZE):
        #Encrypt bloc
        current = m[BLOCK_SIZE*i: BLOCK_SIZE*(i+1)]
        res = xor(current, cipher.encrypt(ctr))
        ciphertext.append(res)
        ctr = increaseCounter(ctr)
    return b"".join(ciphertext)


#Performs the GCM Encryption function whithout AD
#m the message to encrypt. It has to be a multiple of 128 bits. 
#Returns a ciphertext and a tag
def GCM_Encrypt(key, IV, m):
    ciphertext = CTR(key, IV, m)
    cipher = AES.new(key, AES.MODE_ECB)
    tag = authenticate(key, ciphertext, cipher.encrypt((IV + b"\x00"*(COUNTER_SIZE -1) + b"\x01")))
    return (ciphertext, tag)


def GCM_Decrypt(key, IV, ct, tag):
    cipher = AES.new(key, AES.MODE_ECB)
    tag2 = authenticate(key, ct, cipher.encrypt((IV + b"\x00" * (COUNTER_SIZE - _sage_const_1) + b"\x01")))
    if tag != tag2:
        raise Exception("Error: the tag is not valid")
    plaintext = CTR(key, IV, ct)
    return plaintext


def test_GCM_decrypt():
    print("-- Test GCM Decrypt --")
    key = b'0123456789abcdef'
    iv = b'0123456789ab'
    m = b'Bonjour bonjour!'
    c, t = GCM_Encrypt(key, iv, m)
    print(f"Initial message: {m.decode()}")
    print(f"Decrypted: {GCM_Decrypt(key, iv, c, t).decode()}")


def find_second_message():
    print("-- Find second message --")
    m1 = b'This is a Test !'
    c1 = base64.b64decode(b'R4C3f8X+u+wjPo76DEg1YQ==')
    c2 = base64.b64decode(b'Q4mtf8Wq6K43eLz6DVV7Jw==')
    ek = xor(m1, c1)
    m2 = xor(ek, c2)
    print(f"Found the second message: {m2.decode()}")


def break_integrity():
    print("-- Break Integrity --")
    iv = base64.b64decode(b'NuIpy3Lh/Ldy7Mu8')
    m1 = b'This is a Test !'
    c1 = base64.b64decode(b'R4C3f8X+u+wjPo76DEg1YQ==')
    t1 = base64.b64decode(b'ElxFElYoozGMiSn2i3jf/Q==')
    c2 = base64.b64decode(b'Q4mtf8Wq6K43eLz6DVV7Jw==')
    t2 = base64.b64decode(b'ymW7lENkO0kNv+N4KQU1Iw==')
    mChall = b'100.00CHF to ADC'

    ek = xor(m1, c1)
    cx = xor(mChall, ek)

    c1 = f(c1)
    c2 = f(c2)
    t1 = f(t1)
    t2 = f(t2)

    G.<y> = PolynomialRing(GF(2)) #Ring of polynomials over Z_2
    F.<x> = GF(2^128, modulus = y^128 + y^7 + y^2 + y + 1) #GF(2^128) with the GCM modulus

    H = (strToPoly(t2, x) - strToPoly(t1, x)) / (strToPoly(c1, x) - strToPoly(c2, x))
    T = strToPoly(multByH(c1, H, x), x) + strToPoly(t1, x)

    tx = xor(multByH(f(cx), H, x), polyToStr(T))
    tx = f(tx)

    print(f"IV (same): {base64.b64encode(iv).decode()}")
    print(f"New ciphertext: {base64.b64encode(cx).decode()}")
    print(f"New tag: {base64.b64encode(tx).decode()}")


def main():
    test_GCM_decrypt()
    find_second_message()
    break_integrity()


if __name__ == "__main__":
    main()