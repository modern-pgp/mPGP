import mPGPUtil, mPGPCrypto, mpgpsettings
import base64, os
from getpass import getpass
from time import gmtime, strftime
from quantcrypt.kem import Kyber
from quantcrypt.dss import Dilithium
from pathlib import Path

import sys, os
if os.name == "posix":
    sys.path.append('/usr/share/mpgp')
    from Crypto.Hash import SHA256
elif os.name == "nt":
    sys.path.append(os.getenv('APPDATA'))
    from Cryptodome.Hash import SHA256

def GenerateQuantumKeypair(kname, passphrase):
    """
    Generates a Kyber1024 and Delithium Keypair and stores it in the mPGP format.  Mnemonic not available just yet.
    """

    kem = Kyber()
    public_key, secret_key = kem.keygen()

    secret_key_bytes, tag, nonce = mPGPCrypto.AESCryptPK(passphrase, secret_key)
    encrypted_secret_key = base64.b64encode(secret_key_bytes)
    tag_b64 = base64.b64encode(tag)
    nonce_b64 = base64.b64encode(nonce)

    key = ""
    key += encrypted_secret_key.decode() + ":"
    key += tag_b64.decode() + ":"
    key += nonce_b64.decode()

    enc_public_kyber = kem.armor(public_key)
    enc_private_kyber = mPGPUtil.PackKeyData(keytype="KYBER SECRET KEY", content=base64.b64encode(key.encode()).decode(), special="")

    dss = Dilithium()
    public_key, secret_key = dss.keygen()

    secret_key_bytes, tag, nonce = mPGPCrypto.AESCryptPK(passphrase, secret_key)
    encrypted_secret_key = base64.b64encode(secret_key_bytes)
    tag_b64 = base64.b64encode(tag)
    nonce_b64 = base64.b64encode(nonce)

    key2 = ""
    key2 += encrypted_secret_key.decode() + ":"
    key2 += tag_b64.decode() + ":"
    key2 += nonce_b64.decode()

    enc_public_dilithium = dss.armor(public_key)
    enc_private_dilithium = mPGPUtil.PackKeyData(keytype="DILITHIUM SECRET KEY", content=base64.b64encode(key2.encode()).decode(), special="")

    encoded_pub_primary_key = base64.b64encode(bytes(enc_public_dilithium, "utf-8"))
    primary_key = mPGPUtil.PackKeyData(keytype="PRIMARY KEY", content=encoded_pub_primary_key.decode(), special="")

    encoded_pub_sub_key = base64.b64encode(bytes(enc_public_kyber, "utf-8"))
    sub_key = mPGPUtil.PackKeyData(keytype="SUB KEY", content=encoded_pub_sub_key.decode(), special="")

    encoded_full_pub_key = base64.b64encode(bytes((primary_key+"\n"+sub_key), "utf-8"))
    fingerprint = (SHA256.new(encoded_full_pub_key)).hexdigest()
    pub_key = mPGPUtil.PackKeyData(keytype="mPGP PUBLIC KEY BLOCK", content=encoded_full_pub_key.decode(), special=f"Name:{kname}\nKey:mPGP-Quantum\n\n")

    
    encoded_priv_primary_key = base64.b64encode(bytes(enc_private_dilithium, "utf-8"))
    primary_key = mPGPUtil.PackKeyData(keytype="PRIMARY KEY", content=encoded_priv_primary_key.decode(), special="")

    encoded_priv_sub_key = base64.b64encode(bytes(enc_private_kyber, "utf-8"))
    sub_key = mPGPUtil.PackKeyData(keytype="SUB KEY", content=encoded_priv_sub_key.decode(), special="")

    encoded_full_priv_key = base64.b64encode(bytes((primary_key+"\n"+sub_key), "utf-8"))
    priv_key = mPGPUtil.PackKeyData(keytype="mPGP PRIVATE KEY BLOCK", content=encoded_full_priv_key.decode(), special=f"Name:{kname}\nKey:mPGP-Quantum\n\n")

    with open(f"{mpgpsettings.KEY_FOLDER}{fingerprint}.pub", "wb+") as f:
        f.write(bytes(pub_key, "utf-8"))
    f.close()\
    
    with open(f"{mpgpsettings.KEY_FOLDER}{fingerprint}.priv", "wb+") as f:
        f.write(bytes(priv_key, "utf-8"))
    f.close()

    with open(f"{mpgpsettings.BASE_LOCATION}keyring.rf", "a+") as f:
        f.write(f"PUB:{kname}:{mpgpsettings.KEY_FOLDER}{fingerprint}.pub:{fingerprint}:mPGP-Quantum:True\n")
        f.write(f"PRIV:{kname}:{mpgpsettings.KEY_FOLDER}{fingerprint}.priv:{fingerprint}:mPGP-Quantum:True\n")

    return f"Done!"

def QuantumSignMessage(fingerprint, file):
    key_path, key_name = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PRIV")
    if key_path == "NotFound":
        print(f"Key not found with fingerprint'{fingerprint}'")
        exit()

    file_contents = open(file, "rb").read()
    file_contents_hash = SHA256.new(file_contents).hexdigest()

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    pri_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[0].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----\n\n", "").replace("\n", "")
    private_key = base64.b64decode(bytes(pri_key_b64, "utf-8"))
    priv_key_unpack, keytype, special = mPGPUtil.UnpackKeyData(private_key.decode()) # base64 encoding of encrypted sk bytes

    passphrase = getpass("Enter your private key password:\n> ")

    timestamp = strftime("%Y-%m-%d %H.%M.%S", gmtime())

    signed_data = mPGPCrypto.QuantumSign(file_contents, priv_key_unpack, passphrase)
    timestamp_signed = mPGPCrypto.QuantumSign(timestamp.encode(), priv_key_unpack, passphrase)

    signature = ''
    signature += fingerprint + ":"
    signature += (base64.b64encode(signed_data)).decode() + ":"
    signature += (base64.b64encode(file_contents)).decode() + ":"
    signature += timestamp + ":"
    signature += (base64.b64encode(timestamp_signed)).decode() + ":"
    signature += "mPGP-Quantum"

    sig_b64 = base64.b64encode(bytes(signature, "utf-8"))

    outfile = mPGPUtil.PackKeyData(keytype="mPGP SIGNED DATA", content=sig_b64.decode(), special="")

    with open(file+".sig", "w+") as f:
        f.write(outfile)
    f.close()

    print(f"Written signature data to {file}.sig")

def QuantumCheckSignature(unpacked, file):
    cleartext = base64.b64decode(bytes(unpacked, "utf-8"))

    splitted = cleartext.decode().split(":")

    fingerprint = splitted[0]
    b64_enc_sig = splitted[1]
    b64_enc_file_cont = splitted[2]
    timestamp = splitted[3]
    timestamp_sig = splitted[4]
    key_algo = splitted[5]

    signature = base64.b64decode(bytes(b64_enc_sig, "utf-8"))
    file_contents = base64.b64decode(bytes(b64_enc_file_cont, "utf-8"))

    key_path, key_name = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PUB")

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[0].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----", "").replace("\n", "")

    key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

    #pub_key_unpack, keytype, special = mPGPUtil.UnpackKeyData(private_key.decode())

    sig_check = mPGPCrypto.QuantumCheckSignature(signature, file_contents, key)

    timestamp_sig_check = mPGPCrypto.QuantumCheckSignature(signature=base64.b64decode(timestamp_sig), file_contents=bytes(timestamp, "utf-8"), key=key)

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

def QuantumClearsignMessage(fingerprint, file):
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

    pri_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[0].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----\n\n", "").replace("\n", "")
    private_key = base64.b64decode(bytes(pri_key_b64, "utf-8"))
    priv_key_unpack, keytype, special = mPGPUtil.UnpackKeyData(private_key.decode()) # base64 encoding of encrypted sk bytes

    passphrase = getpass("Enter your private key password:\n> ")

    timestamp = strftime("%Y-%m-%d %H.%M.%S", gmtime())
    timestamp_hash = SHA256.new(bytes(timestamp, "utf-8")).hexdigest()

    signed_data = mPGPCrypto.QuantumSign(file_contents.encode(), priv_key_unpack, passphrase)
    timestamp_signed = mPGPCrypto.QuantumSign(timestamp.encode(), priv_key_unpack, passphrase)

    signature = ''
    signature += fingerprint + ":" 
    signature += (base64.b64encode(signed_data)).decode() + ":"
    signature += timestamp + ":"
    signature += (base64.b64encode(timestamp_signed)).decode() + ":"
    signature += "mPGP-Quantum"

    sig_b64 = base64.b64encode(bytes(signature, "utf-8"))

    outfile = mPGPUtil.PackKeyData(keytype="mPGP SIGNATURE", content=sig_b64.decode(), special="")

    final_out += "\n" + outfile

    with open(file+".asc", "w+") as f:
        f.write(final_out)
    f.close()

    print(f"Written signature data to {file}.asc")

def QuantumCheckCleartextSignature(unpacked, message, file):
    cleartext = base64.b64decode(bytes(unpacked, "utf-8"))

    splitted = cleartext.decode().split(":")

    fingerprint = splitted[0]
    b64_enc_sig = splitted[1]
    timestamp = splitted[2]
    b64_time_sig = splitted[3]
    key_type = splitted[4]

    signature = base64.b64decode(bytes(b64_enc_sig, "utf-8"))

    key_path, key_name = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PUB")

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[0].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----", "").replace("\n", "")

    key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

    sig_check = mPGPCrypto.QuantumCheckSignature(signature, bytes(message, "utf-8"), key)

    timestamp_sig_check = mPGPCrypto.QuantumCheckSignature(signature=base64.b64decode(b64_time_sig), file_contents=bytes(timestamp, "utf-8"), key=key)

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

def EncryptMessage(file, key, signed):
    orig = Path(file)
    after = Path(file+".tmp")
    finalfile = Path(file+'.asc')

    if mPGPUtil.CheckFingerprint(key) == True:
        new_fingerprint = fingerprint
    else:
        new_fingerprint, path = mPGPUtil.KeynameToFingerprint(key)
        key_type = mPGPUtil.FingerprintToKeyType(new_fingerprint, searching_for="PUB")

    if key_type != "mPGP-Quantum":
        print("Not a mPGP-Quantum key, please use encrypt or signencrypt instead.")
        exit()

    key_path, _ = mPGPUtil.FingerprintToPath(new_fingerprint, searching_for="PUB")

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----", "").replace("-----END SUB KEY-----", "").replace("\n", "")

    key = base64.b64decode(bytes(sub_key_b64, "utf-8"))
    pub_key_unpack, keytype, special = mPGPUtil.UnpackKeyData(key.decode()) # base64 encoding of encrypted sk bytes
    pub_key = base64.b64decode(pub_key_unpack.encode())
    mPGPCrypto.QuantumEncrypt(pub_key, orig, after)

    cont = open(after, "rb").read()
    b64_cont = base64.b64encode(cont).decode()
    b64_cont += ":" + new_fingerprint
    if signed == "N":
        to_write = mPGPUtil.PackKeyData("mPGP Q-ENCRYPTED DATA", content=base64.b64encode(b64_cont.encode()).decode(), special="")
    elif signed == "Y":
        with open(mpgpsettings.BASE_LOCATION+"keyring.rf", "r") as f:
            contents = f.readlines()
        f.close()

        print("Choose a private key to use:")
        for line in contents:
            split = line.split(":")
            if split[0] == "PRIV":
                private = split[0]
                kname = split[1]
                privpath = split[2]
                fingerprint = split[3]
                keytype = split[4]
                created_locally = split[5]

                if keytype == "mPGP-Quantum":
                    print(f"{keytype} private key:  {kname} with fingerprint {fingerprint}")

        choice = input("\nType either the key name or fingerprint.\n> ")

        if mPGPUtil.CheckFingerprint(choice) == True:
            new_fingerprint = fingerprint
        else:
            new_fingerprint, path = mPGPUtil.KeynameToFingerprint(choice)
            key_type = mPGPUtil.FingerprintToKeyType(new_fingerprint, searching_for="PRIV")
            key_path, _ = mPGPUtil.FingerprintToPath(new_fingerprint, searching_for="PRIV")

        if key_type != "mPGP-Quantum":
            print(f"{key_type} key detected, encryption aborted..")
            exit()

        key_file_contents = open(key_path, "rb").read()

        first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))
        first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

        pri_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[0].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----\n\n", "").replace("\n", "")
        private_key = base64.b64decode(bytes(pri_key_b64, "utf-8"))

        priv_key_unpack, keytype, special = mPGPUtil.UnpackKeyData(private_key.decode()) # base64 encoding of encrypted sk bytes

        passphrase = getpass("Enter your private key password:\n> ")
        timestamp = strftime("%Y-%m-%d %H.%M.%S", gmtime())

        signed_data = mPGPCrypto.QuantumSign(open(orig, "rb").read(), priv_key_unpack, passphrase)
        timestamp_signed = mPGPCrypto.QuantumSign(timestamp.encode(), priv_key_unpack, passphrase)

        signature = ''
        signature += new_fingerprint + ":" 
        signature += (base64.b64encode(signed_data)).decode() + ":"
        signature += timestamp + ":"
        signature += (base64.b64encode(timestamp_signed)).decode() + ":"
        signature += "mPGP-Quantum"

        sig_b64 = base64.b64encode(bytes(signature, "utf-8"))

        outfile = mPGPUtil.PackKeyData(keytype="mPGP SIGNATURE", content=sig_b64.decode(), special="")
        final = b64_cont + ":" + outfile
        final_b64 = base64.b64encode(final.encode())

        to_write = mPGPUtil.PackKeyData(keytype="mPGP Q-SENCRYPTED DATA", content=final_b64.decode(), special="")

    with open(finalfile, "w") as f:
        f.write(to_write)

    f.close()
    os.remove(after)
    print(f"Written data to {finalfile}")

def QuantumDecrypt(file):
    with open(file, "rb") as f:
        contents = f.read()
    f.close()
    ct_file = Path(file+".tmp")

    unpacked, _, _ = mPGPUtil.UnpackKeyData(contents.decode())

    decoded = base64.b64decode(unpacked.encode())
    decoded_string = decoded.decode()
    splitted = decoded_string.split(":")
    ciphertext = splitted[0]
    fingerprint = splitted[1]

    with open(ct_file, "wb") as f:
        f.write(base64.b64decode(ciphertext))
    f.close()

    keys = mPGPUtil.ReturnPrivateKeys()
    fingerprint_l = [fingerprint]

    if bool(set(keys) & set(fingerprint_l)) == False:
        print("Not encrypted with any of your private keys..")
        exit()

    key_path, _ = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PRIV")
        
    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----", "").replace("-----END SUB KEY-----", "").replace("\n", "")

    key = base64.b64decode(bytes(sub_key_b64, "utf-8"))
    priv_key_unpack, keytype, special = mPGPUtil.UnpackKeyData(key.decode()) # base64 encoding of encrypted sk bytes
    
    passphrase = getpass("Enter your private key password:\n> ")

    result = mPGPCrypto.QuantumDecrypt(priv_key_unpack, ct_file, passphrase)

    with open(file[:-4], "wb") as f:
        f.write(result)
    f.close()

    print(f"Written decrypted data to {file[:-4]}")

    os.remove(ct_file)

def QuantumDecryptAndVerify(file):
    with open(file, "rb") as f:
        contents = f.read()
    f.close()
    ct_file = Path(file+".tmp")

    unpacked, _, _ = mPGPUtil.UnpackKeyData(contents.decode())

    decoded = base64.b64decode(unpacked.encode())
    decoded_string = decoded.decode()
    splitted = decoded_string.split(":")
    ciphertext = splitted[0]
    fingerprint = splitted[1]
    signature = splitted[2]

    with open(ct_file, "wb") as f:
        f.write(base64.b64decode(ciphertext))
    f.close()

    keys = mPGPUtil.ReturnPrivateKeys()
    fingerprint_l = [fingerprint]

    if bool(set(keys) & set(fingerprint_l)) == False:
        print("Not encrypted with any of your private keys..")
        exit()

    key_path, _ = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PRIV")
        
    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----", "").replace("-----END SUB KEY-----", "").replace("\n", "")

    key = base64.b64decode(bytes(sub_key_b64, "utf-8"))
    priv_key_unpack, keytype, special = mPGPUtil.UnpackKeyData(key.decode()) # base64 encoding of encrypted sk bytes
    
    passphrase = getpass("Enter your private key password:\n> ")

    result = mPGPCrypto.QuantumDecrypt(priv_key_unpack, ct_file, passphrase)

    with open(file[:-4], "wb") as f:
        f.write(result)
    f.close()

    print(f"\n\nWritten decrypted data to {file[:-4]}")

    os.remove(ct_file)

    signature_unpacked, _, _ = mPGPUtil.UnpackKeyData(signature)

    signature_dec = base64.b64decode(signature_unpacked.encode())

    sig_split = signature_dec.decode().split(":")

    fingerprint = sig_split[0]
    signed_data = sig_split[1] # b64 encoded
    timestamp = sig_split[2]
    timestamp_sig = sig_split[3] # b64 encoded
    key_type = sig_split[4]

    key_path, key_name = mPGPUtil.FingerprintToPath(fingerprint, searching_for="PUB")

    key_file_contents = open(key_path, "rb").read()

    first_unpack, keytype, special = mPGPUtil.UnpackKeyData(str(key_file_contents.decode()))

    first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

    sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[0].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----", "").replace("\n", "")

    key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

    sig_check = mPGPCrypto.QuantumCheckSignature(base64.b64decode(signed_data), result, key)
    timestamp_sig_check = mPGPCrypto.QuantumCheckSignature(base64.b64decode(timestamp_sig), timestamp.encode(), key)

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