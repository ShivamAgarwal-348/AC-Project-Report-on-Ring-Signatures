from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import os
import random
from Crypto.Cipher import AES

number_of_users = int(input("Enter number of Users : "))
message = input("Enter the message : ")
user = int(input("Enter the number of the user who is signing the message : "))
keys = []
for i in range(number_of_users):
    key = RSA.generate(1024, os.urandom)
    keys.append((key.e, key.n))

def g(m, key, max_number):
    e = key[0]
    n = key[1]
    q, r = divmod(m, n)

    if (q+1)*n <= max_number : 
        return q*n + pow(r, e, n)
    else:
        return m

def E(x, k):
    x = x.to_bytes(128, byteorder='big')
    key = k.to_bytes(32, byteorder='big')
    cipher = AES.new(key, AES.MODE_EAX)
    y = cipher.encrypt(x)
    # print(y.hex())
    y = int(y.hex(),16)
    return y

def _E(x, k):
    x = x.to_bytes(128, byteorder='big')
    key = k.to_bytes(32, byteorder='big')
    cipher = AES.new(key, AES.MODE_EAX)
    y = cipher.decrypt(x)
    # print(y.hex())
    y = int(y.hex(),16)
    return y


def sign_message(keys, message, number_of_users, user):
    user = user - 1
    m = message.encode('utf-8')
    hash = SHA256.new()
    hash.update(m)
    k = int(hash.hexdigest(), 16)
    max_number = (1 << 1024) - 1
    v = random.randint(0, max_number)
    
    x = [None] * number_of_users

    for i in range(number_of_users):
        if i != user : 
            xi = random.randint(0, max_number)
            x[i] = xi
    v1 = v

    for i in range(user):  

        yi = g(x[i], keys[i], max_number)
        v1 = E(v1 ^ yi, k)

    v2 = v
    for i in range(number_of_users-1, user, -1):

        yi = g(x[i], keys[i], max_number)
        v2 = _E(v2, k) ^ yi
        
    
    y_user = _E(v2, k) ^ v1
    x[user] = g(y_user, keys[user], max_number)

    output = keys + [v] + x
    return output

def verify(sign, message):
    n = len(sign)
    n = n//2
    keys = sign[0:n]
    v = sign[n]
    x = sign[n+1:]
    
    m = message.encode('utf-8')
    hash = SHA256.new()
    hash.update(m)
    k = int(hash.hexdigest(), 16)
    max_number = (1 << 1024) - 1
    v1 = v
    for i in range(n):

        yi = g(x[i], keys[i], max_number)
        v1 = E(v1 ^ yi, k)

    if v1 == v :
        print("verified")
        return "verified"
        
    else:
        print(v)
        print(v1)
        return "not verified"


sign = sign_message(keys, message, number_of_users, user)
print(sign)
# verify(sign, message)