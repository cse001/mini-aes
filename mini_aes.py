from mini_aes_utils import *
from mini_aes_constants import *


def nibbleSub(block):
    res = []
    for nibble in block:
        res.append(sBox.get(nibble))
    return res

def inverseNibbleSub(block):
    res = []
    for nibble in block:
        res.append(sBoxInverse.get(nibble))
    return res

def shiftRow(block):
    temp = block[1]
    block[1] = block[3]
    block[3] = temp
    return block

def nibbleMultiply(nibble1,nibble2):
    product = MULTIPLICATION_MATRIX[int(nibble1,2)][int(nibble2,2)]
    res = '{0:04b}'.format(product)
    return res

def nibbleXor(nibble1,nibble2):
    # Padding for inconsistent plaintext size
    if nibble1 == "":
        nibble1 = "00"
    if nibble2 == "":
        nibble2 = "00"
    y=int(nibble1,2) ^ int(nibble2,2)
    res = '{0:04b}'.format(y)
    return res

def mixColumn(block):
    res = []
    # Calculate d0
    d0 = nibbleXor(nibbleMultiply(constantMatrix[0],block[0]),nibbleMultiply(constantMatrix[2],block[1]))
    # Calculate d1
    d1 = nibbleXor(nibbleMultiply(constantMatrix[1],block[0]),nibbleMultiply(constantMatrix[3],block[1]))
    # Calculate d2
    d2 = nibbleXor(nibbleMultiply(constantMatrix[0],block[2]),nibbleMultiply(constantMatrix[2],block[3]))
    # Calculate d3
    d3 = nibbleXor(nibbleMultiply(constantMatrix[1],block[2]) , nibbleMultiply(constantMatrix[3],block[3]))
    res.append(d0)
    res.append(d1)
    res.append(d2)
    res.append(d3)
    return res

def getKeyRounds(key):
    w = []
    k0 = bytes_to_blocks(key)[0]
    for k in k0:
        w.append(k)
    # Let's work on k1
    w.append(nibbleXor(nibbleXor(w[0],sBox.get(w[3])),"0001"))
    w.append(nibbleXor(w[1],w[4]))
    w.append(nibbleXor(w[2],w[5]))
    w.append(nibbleXor(w[3],w[6]))
    # Let's work on k2
    w.append(nibbleXor(nibbleXor(w[4],sBox.get(w[7])),"0010"))
    w.append(nibbleXor(w[5],w[8]))
    w.append(nibbleXor(w[6],w[9]))
    w.append(nibbleXor(w[7],w[10]))
    return (w)

def keyAddition(plaintext,key):
    res = []
    for i in range(4):
        res.append(nibbleXor(plaintext[i],key[i]))
    return res

def encryption(plaintext,key):
    # Round Zero - Key Addition
    k0 = key[0:4]
    round0 = (keyAddition(plaintext,k0))
    
    # Round - 1
    ## Nibble Sub
    round1 = keyAddition(mixColumn(shiftRow(nibbleSub(round0))),key[4:8])

    # Round - 2
    ciphertext = keyAddition(shiftRow(nibbleSub(round1)),key[8:12])
    return ciphertext

def decryption(ciphertext,key):
    # Round Keys and the round contants are applied in reverse order,
    # and the NibbleSub is replaced by its inverse
    k0 = key[8:12]
    round0 = keyAddition(ciphertext,k0)
    
    # Round 1
    round1 = keyAddition(inverseNibbleSub(shiftRow(round0)),key[4:8])

    # Round 2
    round2 = keyAddition(inverseNibbleSub(shiftRow(mixColumn(round1))),key[0:4])
    return round2

def encrypt(plaintext,key):
    # Convert ASCII to Bytes
    plaintext = string_to_bytes(plaintext)
    key = string_to_bytes(key)
    
    # Key Generation
    encryption_key = getKeyRounds(key)

    # Get blocks for streaming
    pt_blocks = bytes_to_blocks(plaintext)
    # Store Cipher Text String in Binary
    ct_binary_string = ''

    # Encrypt plaintext block streams
    for pt in pt_blocks:
        c = encryption(pt,encryption_key)
        for i in c:
            ct_binary_string+=i
    
    return ct_binary_string

def decrypt(ciphertext,key):
    # Convert ASCII to Bytes
    key = string_to_bytes(key)

    # Key Generation
    decyption_key = getKeyRounds(key)

    # Get blocks for streaming
    ct_blocks = bytes_to_blocks(ciphertext)
    # Store Cipher Text String in Binary
    pt_binary_string = ''

    # Encrypt plaintext block streams
    for ct in ct_blocks:
        p = decryption(ct,decyption_key)
        for i in p:
            pt_binary_string+=i
    
    return bytes_to_string(pt_binary_string)

def main():
    # Can be any string.
    plaintext = "Hello World"
    # Can be any string, but only first 16 bits are taken!
    secretkey = "on"
    ciphertext = encrypt(plaintext,secretkey)
    print(ciphertext)
    plaintext = decrypt(ciphertext,secretkey)
    print(plaintext)

if __name__=="__main__": 
    main()