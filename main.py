import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from getpass import getpass
import base64
from os.path import join

route = r'C:\Documents\folder_containing_file_to_encrypt'
file = r'file_to_encrypt.txt'
store_folder = r'Make_this_a_folder_on_a_memory_stick'
hmac_file = r'a_file_on_the_memory_stick.txt'
store_file = r'another_file_on_the_memory_stick.txt'


password = getpass('Enter the chosen encryption password').encode('utf-8')
salt = os.urandom(16)

kdf = PBKDF2HMAC(hashes.SHA256(),length = 32, salt = salt, iterations = 100000)
key_1 = base64.urlsafe_b64encode(kdf.derive(password))

Encryptor = Fernet(key_1)
with open(join(route,file),'rb') as text:
    contents = text.read()
    encrypted = Encryptor.encrypt(contents)
with open(join(route,file),'wb') as text:
    text.write(encrypted)


key_2 = os.urandom(16)
h = hmac.HMAC(key_2,hashes.SHA256())
with open(join(route,file),'rb') as text:
    message = text.read()
h.update(message)
signature = h.finalize()
with open(join(route,hmac_file),'wb') as text:
    text.write(signature)

bs = bcrypt.gensalt()
hashed = str(bcrypt.hashpw(password,bs)).encode('utf-8')

with open(join(store_folder,store_file),'wb') as text:
    text.write(salt + b'\n' + key_2 + b'\n' + hashed)
















