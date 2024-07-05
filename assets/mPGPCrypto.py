import base64, random
import mpgpsettings
from mnemonic import Mnemonic
from pathlib import Path

from quantcrypt.kem import Kyber
from quantcrypt.dss import Dilithium
from quantcrypt.cipher import KryptonKEM

import sys, os
if os.name == "posix":
    sys.path.append('/usr/share/mpgp')
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA512, SHA256
    from Crypto.Random import get_random_bytes
    from Crypto.Cipher import AES, PKCS1_OAEP
elif os.name == "nt":
    sys.path.append(os.getenv('APPDATA'))
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Signature import pkcs1_15
    from Cryptodome.Hash import SHA512, SHA256
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Cipher import AES, PKCS1_OAEP


# Non Views functions
def RSA_Keygen(keysize, password, passphrase):
    salt = get_random_bytes(32)

    if password == "NULL":
        mnemo = Mnemonic("english")
        password = mnemo.generate(strength=256)

    master = PBKDF2(password, salt, count=100000)

    def notrand(n):
        notrand.i += 1
        return PBKDF2(password, str(notrand.i), dkLen=n, count=1)
    
    notrand.i = 0
    RSA_key = RSA.generate(keysize, randfunc=notrand)
    bprivate_key = RSA_key.export_key(passphrase=passphrase, pkcs=8, protection="scryptAndAES256-CBC")
    bpublic_key = RSA_key.public_key().export_key()
    
    h = SHA256.new(bpublic_key)
    pubkey_hash_digest = h.hexdigest()

    h2 = SHA256.new(bprivate_key)
    privkey_hash_digest = h2.hexdigest()

    return bprivate_key, privkey_hash_digest, bpublic_key, pubkey_hash_digest, password

def RSASign(message, key, passphrase):
    key = RSA.import_key(key, passphrase=passphrase)

    h = SHA256.new(message)

    signature = pkcs1_15.new(key).sign(h)
    return signature, h

def RSACheckSignature(signature, file_contents, file_cont_hash, public_key):
    key = RSA.import_key(public_key)
    
    h = SHA256.new(file_contents)

    if h.hexdigest() != file_cont_hash and h.hexdigest() != file_cont_hash.hexdigest():
        return "Hashes don't match"

    try:
        pkcs1_15.new(key).verify(h, signature)
        return "GOODSIG"
    except (ValueError, TypeError):
        return "BADSIG"

def AESEncrypt(content):
    session_key = get_random_bytes(32)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(content)

    return ciphertext, tag, session_key, cipher_aes.nonce

def RSAEncrypt(message, key, session_key):
    key = RSA.import_key(key)

    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    return enc_session_key

def RSADecrypt(key, enc_session_key, nonce, tag, ciphertext, passphrase):
    private_key = RSA.import_key(key, passphrase=passphrase)

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    try:
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except:
        return False
    
    out = data.decode("utf-8")
    return out

def AESCryptPK(passphrase, sk_bytes):
    aes_key = PBKDF2(passphrase, 1, 32)

    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(sk_bytes)
    nonce = aes_cipher.nonce

    return ciphertext, tag, nonce

def AESDecryptPK(ciphertext, passphrase):
    to_split = base64.b64decode(ciphertext)
    splitted = to_split.decode().split(":")
    key = PBKDF2(passphrase, 1, 32)
    ciphertext = base64.b64decode(splitted[0].encode())
    tag = base64.b64decode(splitted[1].encode())
    nonce = base64.b64decode(splitted[2].encode())
    
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
    try:
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except:
        return False

    return data

def QuantumSign(contents, private_key, passphrase):
    real_key = AESDecryptPK(private_key, passphrase)
    if real_key == "False":
        print("Invalid password")
        exit()

    dss = Dilithium()

    signature = dss.sign(real_key, contents)
    return signature

def QuantumCheckSignature(signature, file_contents, key):
    dss = Dilithium()
    public_key = dss.dearmor(key)
    try:
        dss.verify(public_key, file_contents, signature)
    except:
        return "BADSIG"

    return "GOODSIG"

def QuantumEncrypt(public_key, plaintext_file, ciphertext_file):
    kem = Kyber()
    krypton = KryptonKEM(Kyber)

    data = krypton.encrypt(public_key, plaintext_file, ciphertext_file)

    return data

def QuantumDecrypt(private_key, ciphertext_file, passphrase):
    real_key = AESDecryptPK(private_key, passphrase)
    if real_key == False:
        print("Invalid password")
        exit()
    kem = Kyber()
    krypton = KryptonKEM(Kyber)

    data = krypton.decrypt_to_memory(real_key, ciphertext_file)

    return data