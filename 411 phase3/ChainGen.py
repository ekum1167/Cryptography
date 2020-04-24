from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import random

def CheckPow(filename):
    blocks = []
    length = len(filename)
    for i in range(len(filename) - 9):
        if i % 9 is 0:
            blocks.append(''.join(filename[i:i+9]))
    PrevPoW = filename[-2][14:]
    PrevPoW = PrevPoW.rstrip()
    PrevPoW = PrevPoW.encode('UTF-8')
    hash1 = [SHA3_256.new(i.encode('UTF-8')).digest() for i in blocks]
    str = filename[-1][7:]
    s = str.rstrip()
    nonce = int(s)
    H_r = Root_of_merkle(hash1)
    """
    print("type of root hash", type(root_hash))
    print("type of prevpow", type(PrevPoW))
    print("type of root nonce", type(nonce))
    """
    digest = H_r + PrevPoW + nonce.to_bytes((nonce.bit_length() + 7) // 8, byteorder = 'big')
    #digest_value = root_hash + previous_pow.encode("utf-8")+nonce.to_bytes((nonce.bit_length()+7)//8, byteorder='big')
    # SHA3_256.new(digest).hexdigest() --> this is our proof of work
    return SHA3_256.new(digest).hexdigest()


def Root_of_merkle(tree):
    if len(tree) == 1:
        return tree[0]  # root of the merkletree
    else:
        new_tree = []
        i = 0
        while i + 1 < len(tree):
            entry = tree[i] + tree[i+1]
            new_tree.append((SHA3_256.new(entry)).digest())
            i = i + 2
        return Root_of_merkle(new_tree)




def AddBlock2Chain(PoWLen, TxCnt, block_candidate, PrevBlock):
    PrevPoW1 = "00000000000000000000\n"
    if PrevBlock == "":
        block_candidate.append("Previous PoW: " + "00000000000000000000\n")
    else:
        PrevPoW1 = CheckPow(PrevBlock)
        block_candidate.append("Previous PoW: " + PrevPoW1 + "\n")

    arr = []
    for i in range(len(block_candidate) - 9):
        if i % 9 == 0:
            arr.append(''.join(block_candidate[i:i + 9]))
    PPOW = block_candidate[-1][14:]
    PPOW = PPOW.rstrip()
    hashedList = [SHA3_256.new(i.encode("utf-8")).digest() for i in arr]
    H_r = Root_of_merkle(hashedList)
    notfound = True
    while notfound:
        nonce = random.randint(2 ** 16, 2 ** 64)
        digest = H_r + PPOW.encode("utf-8") + nonce.to_bytes((nonce.bit_length() + 7) // 8, byteorder='big')
        if SHA3_256.new(digest).hexdigest()[:PoWLen] == (PoWLen * "0"):
            notfound = False
            nonce = "Nonce: " + str(nonce) + "\n"
    block_candidate.append(nonce)
    return ''.join(block_candidate), PrevPoW1