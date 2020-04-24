from random import randint
import random
import DS
import math

def gen_random_txblock(q, p, g, TxCnt, filename):

  if not math.log2(TxCnt).is_integer():
    print("TxCnt is not a power of 2")
  i = 0
  while i < TxCnt:
    gen_random_tx(q,p,g)
    i = i+1


def  gen_random_tx(q, p, g):
  serial_number = random.getrandbits(128)#randint(2**(128-1), 2**128-1)
  payee_alpha,payee_public_key = DS.Key_Gen(q, p, g)
  payer_alpha,payer_public_key = DS.Key_Gen(q, p, g)
  Amount = randint(1, 1000000)
  message = "*** Bitcoin transaction ***\nSerial number: " + str(serial_number) + "\nPayer public key (beta): " + str(payer_public_key) + "\nPayee public key (beta): " + str(payee_public_key) + "\nAmount: " + str(Amount) +"\n"

  signature_s, signature_r = DS.SignGen(message.encode('UTF-8'), q, p, g, payer_alpha)
  try:
    f = open("transaction.txt", "x")
    #print("Transactions.txt not found, creating new and writing to it.")
    f.write(message + "Signature (s): " + str(signature_s) + "\nSignature (r): " + str(signature_r) + "\n")
  except FileExistsError:
    #print("File exists, appending to it")
    f = open("transactions.txt","a")
    f.write(message + "Signature (s): " + str(signature_s) + "\nSignature (r): " + str(signature_r) +"\n")

  f.close()
  return message + "Signature (s): " + str(signature_s) + "\nSignature (r): " + str(signature_r) +"\n"
