from random import randint
import random
import DS


def  gen_random_tx(q, p, g):
  serial_number = random.getrandbits(128)#randint(2**(128-1), 2**128-1)
  payee_alpha,payee_public_key = DS.Key_Gen(q, p, g)
  payer_alpha,payer_public_key = DS.Key_Gen(q, p, g)
  Amount = randint(1, 1000000)
  """
  message = "**** Bitcoin transaction ****\n"
  message += "Serial number: "
  message += str(serial_number)
  message += "\nPayer public key (beta):  \n"
  message += str(payer_public_key)
  message += "\nPayee public key (beta): \n"
  message += str(payee_public_key)
  message += "\nAmount: "
  message += str(Amount)
  print(message)
  """
  message = "*** Bitcoin transaction ***\nSerial number: " + str(serial_number) + "\nPayer public key (beta): " + str(payer_public_key) + "\nPayee public key (beta): " + str(payee_public_key) + "\nAmount: " + str(Amount) +"\n"


  signature_s, signature_r = DS.SignGen(message.encode('UTF-8'), q, p, g, payer_alpha)

  #print(message)

  return message + "Signature (s): " + str(signature_s) + "\nSignature (r): " + str(signature_r) +"\n"
