from Crypto.Hash import SHA3_256
import random
import re

def merkle_tree_build(filename ,TxCnt):
    f = open(filename, "r")
    hash_arr =[]
    whole_file = f.readlines()
    f.close()
    for  i in range (0,TxCnt): #first get hash of transactions to array
        hash_arr.append(SHA3_256.new("".join(whole_file[i*7:(i+1)*7]).encode('UTF-8')).digest()) # digest not hex

    current_size = int(TxCnt / 2)
    while True: # then fill the values after arr[TxCnt]

        new_array= []
        for i in range (current_size):
            #print(i)
            m = hash_arr[2*i] + hash_arr[2*i+1]
            hash = SHA3_256.new(m).digest()
            new_array.append(hash)
        hash_arr = new_array
        current_size = current_size // 2
        #print('c: ',current_size)
        if current_size == 1:
            break

    #print("In Merkle tree build")
    #print(new_array[-1])
    return new_array[-1]


def PoW(PoWLen, q, p, g, TxCnt, filename):
    # filename = transactions.txt
    merkle_tree_root = merkle_tree_build("transactions.txt",TxCnt)
    """
    Read a transaction from transactions.txt
    compute root hash (Hr) using merkle tree  with SHA3_256
    Append random number called nonce to Hr
    Compute hash  again
    SHA3_256(Hr||Nonce) must start with 4*PoWLen 0 bits
    if you print hash value with hexdigest() first PoWLen hexadecimal digits must be zero

    """
    Hr = merkle_tree_root #final element of array -> root hash
    print("merkle tree root in PoW: ", Hr)
    nonce = random.getrandbits(128)# 128 bit random sayi
    digest = Hr + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder = 'big')
    digest = SHA3_256.new(digest).hexdigest()
    check_zeros =""
    i = 0
    while i < PoWLen:
        check_zeros += "0"
        i+=1
    while digest[:PoWLen] != check_zeros : # 12 zeros for PoWLen = 3
        #print("proof = ", digest)
        nonce = random.getrandbits(128)
        digest = Hr + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder = 'big')
        digest = SHA3_256.new(digest).hexdigest()
        #print("proof = ", digest)

    #now digest value has enough zeros

    print("Calculated proof in PoW function: ",digest)
    fh = open("block.txt","a")
    fh.write(str(digest))
    fh.close()
    return digest


def CheckPow(p, q, g, PoWLen, TxCnt, filename):


    #filename = block_sample.txt
    #yine hash tree hesapla en sondaki nonce ile kontrol et
    #print("Checkpoint1")
    merkle_tree_root = merkle_tree_build("transactions.txt", TxCnt)
    #print("merkle tree root in CheckPoW: ", merkle_tree_root)
    #print("Checkpoint2")
    f = open(filename, "r")
    for line in f:
        pass
    #nonce = map(int, re.findall(r'\d+', line))
    s = ''.join(x for x in line if x.isdigit())
    nonce = int(s)
    print("nonce", nonce)
    f.close()
    zeros = ""
    i = 0
    while i < PoWLen:
        zeros +="0"
        i += 1



    #print("zeros = ", zeros)
    #print("root hash = ", merkle_tree_root)
    val = merkle_tree_root + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder = 'big')
    final_hash = SHA3_256.new(val).hexdigest()
    #print("Checkpoint4")
    print("final_hash = ", final_hash)
    if final_hash[:PoWLen] != zeros: # if there are not enough zeros
        return ""
    return final_hash

