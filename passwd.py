import hashlib
import os
import base64
import sys

password, verify = sys.argv[1:3]

password = password.encode('utf-8')
verify = verify.encode('utf-8')

salt = os.urandom(16)

hashvalue = base64.b64encode(salt + hashlib.scrypt(password, salt=salt, n=8, r=8, p=1))


recovered_salt = base64.b64decode(hashvalue)[:16]

verified_hash = base64.b64encode(recovered_salt + hashlib.scrypt(verify, salt=recovered_salt, n=8, r=8, p=1))


print(hashvalue)
print(verified_hash)

