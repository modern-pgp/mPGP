import mpgpsettings, mPGPCrypto, mPGPUtil
import base64
from time import gmtime, strftime
from getpass import getpass

import sys, os
if os.name == "posix":
    sys.path.append('/usr/share/mpgp')
    from Crypto.Hash import SHA256
elif os.name == "nt":
    sys.path.append(os.getenv('APPDATA'))
    from Cryptodome.Hash import SHA256

def RSASignMessage(fingerprint, file):
    key_path, key_name = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PRIV")
    if key_path == "NotFound":
        print(f"Key not found with fingerprint'{fingerprint}'")
        exit()

    file_contents = open(file, "rb").read()
    file_contents_hash = SHA256.new(file_contents).hexdigest()

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END SUB KEY-----", "").replace("\n", "")

    private_key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

    passphrase = getpass("Enter your private key password:\n> ")

    timestamp = strftime("%Y-%m-%d %H.%M.%S", gmtime())
    timestamp_hash = SHA256.new(bytes(timestamp, "utf-8")).hexdigest()

    signed_data, hashed_data = mPGPCrypto.RSASign(file_contents, private_key, passphrase)
    timestamp_signed, hashed_data_timestamp = mPGPCrypto.RSASign(bytes(timestamp, "utf-8"), private_key, passphrase)

    signature = ''
    signature += fingerprint + ":"
    signature += (base64.b64encode(signed_data)).decode() + ":"
    signature += (base64.b64encode(file_contents)).decode() + ":"
    signature += file_contents_hash + ":"
    signature += timestamp + ":"
    signature += (base64.b64encode(timestamp_signed)).decode() + ":"
    signature += timestamp_hash + ":"
    signature += "RSA"

    sig_b64 = base64.b64encode(bytes(signature, "utf-8"))

    outfile = mPGPUtil.PackKeyData(keytype="mPGP SIGNED DATA", content=sig_b64.decode(), special="")

    with open(file+".sig", "w+") as f:
        f.write(outfile)
    f.close()

    print(f"Written signature data to {file}.sig")

"""
    SCHEMA:
        [0] - fingerprint
        [1] - base64 encoded signature
        [2] - base64 encoded file contents
        [3] - file contents hash
        [4] - timestamp
        [5] - timestamp hash
        [6] - key algo
"""

def RSACheckSignature(unpacked, file):
    cleartext = base64.b64decode(bytes(unpacked, "utf-8"))

    splitted = cleartext.decode().split(":")

    fingerprint = splitted[0]
    b64_enc_sig = splitted[1]
    b64_enc_file_cont = splitted[2]
    file_cont_hash = splitted[3]
    timestamp = splitted[4]
    timestamp_sig = splitted[5]
    timestamp_hash = splitted[6]
    key_algo = splitted[7]

    signature = base64.b64decode(bytes(b64_enc_sig, "utf-8"))
    file_contents = base64.b64decode(bytes(b64_enc_file_cont, "utf-8"))

    key_path, key_name = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PUB")

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END SUB KEY-----", "").replace("\n", "")

    key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

    sig_check = mPGPCrypto.RSACheckSignature(signature, file_contents, file_cont_hash, key)

    timestamp_sig_check = mPGPCrypto.RSACheckSignature(signature=base64.b64decode(timestamp_sig), file_contents=bytes(timestamp, "utf-8"), file_cont_hash=timestamp_hash, public_key=key)

    if sig_check == "GOODSIG":
        verd = f"GOOD Signature from {fingerprint[-16:].upper()}.  This message or file is from the intended sender and has not been modified."
        
    else:
        verd = f"BAD Signature from {fingerprint[-16:].upper()}.  This message or file is not from the intended sender or has been modified."

    if timestamp_sig_check == "GOODSIG":
        timestamp_status = "correct"
    else:
        timestamp_status = "incorrect"

    print(f"""
mPGP:
    File {file} signed with key {fingerprint[-16:].upper()} at {timestamp.replace(".", ":")} (timestamp verified {timestamp_status}).

        verdict:  {verd}
    """)

def RSAClearsignMessage(fingerprint, file):
    key_path, key_name = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PRIV")
    if key_path == "NotFound":
        print(f"Key not found with fingerprint'{fingerprint}'")
        exit()

    file_contents = open(file, "r").read()
    file_contents_hash = SHA256.new(file_contents.encode()).hexdigest()

    final_out = "-----BEGIN mPGP SIGNED MESSAGE-----\n\n"
    final_out += file_contents

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END SUB KEY-----", "").replace("\n", "")

    private_key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

    passphrase = getpass("Enter your private key password:\n> ")

    timestamp = strftime("%Y-%m-%d %H.%M.%S", gmtime())
    timestamp_hash = SHA256.new(bytes(timestamp, "utf-8")).hexdigest()

    signed_data, hashed_data = mPGPCrypto.RSASign(file_contents.encode(), private_key, passphrase)
    timestamp_signed, hashed_data_timestamp = mPGPCrypto.RSASign(bytes(timestamp, "utf-8"), private_key, passphrase)

    signature = ''
    signature += fingerprint + ":" 
    signature += (base64.b64encode(signed_data)).decode() + ":"
    signature += timestamp + ":"
    signature += (base64.b64encode(timestamp_signed)).decode() + ":"
    signature += timestamp_hash + ":"
    signature += "RSA"

    sig_b64 = base64.b64encode(bytes(signature, "utf-8"))

    outfile = mPGPUtil.PackKeyData(keytype="mPGP SIGNATURE", content=sig_b64.decode(), special="")


    final_out += "\n" + outfile

    with open(file+".asc", "w+") as f:
        f.write(final_out)
    f.close()

    print(f"Written signature data to {file}.asc")

"""
 schema:
    splitted[0] = fingerprint
    splitted[1] = b64_enc_signature
    splitted[2] = timestamp
    splitted[3] = b64_time_signature
    splitted[4] = timestamp_hash
    splitted[5] = key_type
"""

def RSACheckCleartextSignature(unpacked, message, file):
    cleartext = base64.b64decode(bytes(unpacked, "utf-8"))

    splitted = cleartext.decode().split(":")

    fingerprint = splitted[0]
    b64_enc_sig = splitted[1]
    timestamp = splitted[2]
    b64_time_sig = splitted[3]
    timestamp_hash = splitted[4]
    key_type = splitted[5]

    signature = base64.b64decode(bytes(b64_enc_sig, "utf-8"))

    key_path, key_name = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PUB")

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END SUB KEY-----", "").replace("\n", "")

    key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

    h = SHA256.new(bytes(message, "utf-8"))
    sig_check = mPGPCrypto.RSACheckSignature(signature, bytes(message, "utf-8"), h, key)

    timestamp_sig_check = mPGPCrypto.RSACheckSignature(signature=base64.b64decode(b64_time_sig), file_contents=bytes(timestamp, "utf-8"), file_cont_hash=timestamp_hash, public_key=key)

    if sig_check == "GOODSIG":
        verd = f"GOOD Signature from {fingerprint[-16:].upper()}.  This message or file is from the intended sender and has not been modified."
        
    else:
        verd = f"BAD Signature from {fingerprint[-16:].upper()}.  This message or file is not from the intended sender or has been modified."

    if timestamp_sig_check == "GOODSIG":
        timestamp_status = "correct"
    else:
        timestamp_status = "incorrect"

    print(f"""
mPGP:
    File {file} signed with key {fingerprint[-16:].upper()} at {timestamp.replace(".", ":")} (timestamp verified {timestamp_status}).

        verdict:  {verd}
    """)