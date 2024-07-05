import mPGPCrypto
import mpgpsettings
import base64
from getpass import getpass
from time import gmtime, strftime

import sys, os
if os.name == "posix":
    sys.path.append('/usr/share/mpgp')
    from Crypto.Hash import SHA256
    from Crypto.Random import get_random_bytes
elif os.name == "nt":
    sys.path.append(os.getenv('APPDATA'))
    from Cryptodome.Hash import SHA256
    from Cryptodome.Random import get_random_bytes

ENCRYPT = "SUB"
SIGN = "PRIMARY"

"""
    schema:
        BEGIN mPGP PUBLIC KEY BLOCK  -- Begins mPGP public key block
        BEGIN mPGP PRIVATE KEY BLOCK -- Begins mPGP private key block
        BEGIN PRIMARY KEY            -- Begins primary key (one keypair)
        BEGIN SUB KEY                -- Begins sub key (one keypair)
        BEGIN mPGP SIGNED DATA       -- Non clear-text signed data, can be a file or data
        BEGIN mPGP SIGNATURE         -- Cleartext signature
        BEGIN mPGP ENCRYPTED DATA    -- Encrypted data
        BEGIN mPGP Q-ENCRYPTED DATA  -- Quantum encrypted data
        BEGIN mPGP Q-SENCRYPTED DATA -- Quantum signed and encrypted data
"""

def ReturnPrivateKeys():
    with open(mpgpsettings.KEYRING) as f:
        contents = f.readlines()
    f.close()

    privkeys = []

    for line in contents:
        section = line.split(":")
        if section[0] == 'PRIV':
            privkeys.append(section[3])

    return privkeys


def PackKeyData(keytype, content, special):
    outstr = f"-----BEGIN {keytype}-----\n\n"
    outstr += special

    count = 0
    for char in content:
        outstr += str(char)
        count += 1
        if count == 64:
            outstr += "\n"
            count = 0
    outstr += f"\n-----END {keytype}-----"

    return outstr

def UnpackKeyData(content):
    count = 0
    content = content.splitlines()
    
    special = ""

    keytype = content[0].replace("-----", "").replace("BEGIN", "")

    del content[0]
    del content[-1]

    base64str = ""

    for element in content:

        if element == "":
            count = 0
        elif element.startswith("Name:"):
            special += element + "\n"
        elif element.startswith("Key:"):
            special += element + "\n"
        else:
            base64str += element
        
        count += 1

    return base64str, keytype, special

def UnpackClearsig(text):
    text = text.replace("-----BEGIN mPGP SIGNED MESSAGE-----\n\n", "")
    text = text.replace("-----END mPGP SIGNATURE-----", "")
    message = text.split("-----BEGIN mPGP SIGNATURE-----")[0]
    unpacked = text.split("-----BEGIN mPGP SIGNATURE-----")[1].replace("\n", "")

    message = message.rstrip()

    key_type = "mPGP SIGNATURE"

    return message, key_type, unpacked

def FingerprintToPath(fingerprint, searching_for):
    with open(mpgpsettings.KEYRING, "r") as f:
        contents = f.read()
    f.close()

    for line in contents.splitlines():
        line_cont = line.split(":")
        if line_cont[3] == fingerprint and line_cont[0] == searching_for:
            return line_cont[2], line_cont[1]

    return "NotFound", "NotFound"

def FingerprintToKeyType(fingerprint, searching_for):
    with open(mpgpsettings.KEYRING, "r") as f:
        contents = f.read()
    f.close()

    for line in contents.splitlines():
        line_cont = line.split(":")
        if line_cont[3] == fingerprint and line_cont[0] == searching_for:
            return line_cont[4]

    return "NotFound"

def KeynameToFingerprint(key_name):
    with open(mpgpsettings.KEYRING, "r") as f:
        contents = f.read()
    f.close()

    for line in contents.splitlines():
        line_cont = line.split(":")
        if line_cont[1] == key_name:
            return line_cont[3], line_cont[2]

    return "NotFound", "NotFound"

def CheckFingerprint(fingerprint):
    with open(mpgpsettings.KEYRING, "r") as f:
        contents = f.read()
    f.close()

    for line in contents.splitlines():
        line_cont = line.split(":")
        if line_cont[3] == fingerprint:
            return True

    return False

def GenerateRSAKeypair(keysize, kname, passphrase):
    """
    Generates RSA Keypair and stores it in the mPGP format.  Includes option for mnemonic phrase recovery.
    """
    bytes_private_key, private_hash, bytes_public_key, public_hash, mnemonic_phrase = mPGPCrypto.RSA_Keygen(keysize=keysize, password="NULL", passphrase=passphrase)

    primary_key_public = bytes_public_key.decode()
    primary_key_private = bytes_private_key.decode()

    mnemo = mnemonic_phrase
    
    bytes_private_key, private_hash, bytes_public_key, public_hash, mnemonic_phrase = mPGPCrypto.RSA_Keygen(keysize=keysize, password=mnemonic_phrase+" mPGP", passphrase=passphrase)

    sub_key_public = bytes_public_key.decode()
    sub_key_private = bytes_private_key.decode()

    encoded_pub_primary_key = base64.b64encode(bytes(primary_key_public, "utf-8"))
    primary_key = PackKeyData(keytype="PRIMARY KEY", content=encoded_pub_primary_key.decode(), special="")

    encoded_pub_sub_key = base64.b64encode(bytes(sub_key_public, "utf-8"))
    sub_key = PackKeyData(keytype="SUB KEY", content=encoded_pub_sub_key.decode(), special="")

    encoded_full_pub_key = base64.b64encode(bytes((primary_key+"\n"+sub_key), "utf-8"))
    fingerprint = (SHA256.new(encoded_full_pub_key)).hexdigest()
    pub_key = PackKeyData(keytype="mPGP PUBLIC KEY BLOCK", content=encoded_full_pub_key.decode(), special=f"Name:{kname}\nKey:RSA-{keysize}\n\n")

    
    encoded_priv_primary_key = base64.b64encode(bytes(primary_key_private, "utf-8"))
    primary_key = PackKeyData(keytype="PRIMARY KEY", content=encoded_priv_primary_key.decode(), special="")

    encoded_priv_sub_key = base64.b64encode(bytes(sub_key_private, "utf-8"))
    sub_key = PackKeyData(keytype="SUB KEY", content=encoded_priv_sub_key.decode(), special="")

    encoded_full_priv_key = base64.b64encode(bytes((primary_key+"\n"+sub_key), "utf-8"))
    priv_key = PackKeyData(keytype="mPGP PRIVATE KEY BLOCK", content=encoded_full_priv_key.decode(), special=f"Name:{kname}\nKey:RSA-{keysize}\n\n")

    with open(f"{mpgpsettings.KEY_FOLDER}{fingerprint}.pub", "wb+") as f:
        f.write(bytes(pub_key, "utf-8"))
    f.close()\
    
    with open(f"{mpgpsettings.KEY_FOLDER}{fingerprint}.priv", "wb+") as f:
        f.write(bytes(priv_key, "utf-8"))
    f.close()

    with open(f"{mpgpsettings.BASE_LOCATION}keyring.rf", "a+") as f:
        f.write(f"PUB:{kname}:{mpgpsettings.KEY_FOLDER}{fingerprint}.pub:{fingerprint}:RSA-{keysize}:True\n")
        f.write(f"PRIV:{kname}:{mpgpsettings.KEY_FOLDER}{fingerprint}.priv:{fingerprint}:RSA-{keysize}:True\n")

    return f"Done!  Back up key with:  {mnemo} and key bits {keysize}"

def GetKeys():
    outstr = ''
    with open(mpgpsettings.BASE_LOCATION+"/keyring.rf") as f:
        for line in f:
            lining = line.split(":")
            if lining[0] == "PUB":
                outstr += f"Public Key:  {lining[1]}\n"
            elif lining[0] == "PRIV":
                outstr += f"Private Key:  {lining[1]}\n"
            outstr += f"    Fingerprint:  {lining[3]}\n"
            outstr += f"    Key Type:     {lining[4]}\n\n"
    
    return outstr

def ImportKey(file):
    with open(file, "rb") as f:
        contents = f.read()
    f.close()

    fingerprint = (SHA256.new(contents)).hexdigest()

    first_unpack, keytype, special = UnpackKeyData(str(contents.decode()))

    if special != "":
        lines = special.splitlines()
        for i in lines:
            if i.startswith("Name:"):
                name = i[5:]
            elif i.startswith("Key:"):
                key_algo = i[4:]
    
    first_content = base64.b64decode(bytes(first_unpack, "utf-8"))

    print("Imported:  ")
    print(f"Name:  {name}")
    print(f"Key algo:  {key_algo}")
    print(f"Fingerprint:  {fingerprint}")

    with open(f"{mpgpsettings.BASE_LOCATION}keyring.rf", "a+") as f:
        if keytype == " mPGP PUBLIC KEY BLOCK":
            f.write(f"PUB:{name}:{mpgpsettings.KEY_FOLDER}{fingerprint}.pub:{fingerprint}:{key_algo}:False")
        elif keytype == " mPGP PRIVATE KEY BLOCK":
            f.write(f"PUB:{name}:{mpgpsettings.KEY_FOLDER}{fingerprint}.pub:{fingerprint}:{key_algo}:False")
            f.write(f"PRIV:{name}:{mpgpsettings.KEY_FOLDER}{fingerprint}.priv:{fingerprint}:{key_algo}:False\n")
        else:
            print(f"Error importing key with keytype '{keytype}'...  Check")
            exit()
    f.close()

    if keytype == " mPGP PUBLIC KEY BLOCK":
        with open(mpgpsettings.KEY_FOLDER+fingerprint+".pub", "wb+") as f:
            f.write(contents)
        f.close()
    else:
        with open(mpgpsettings.KEY_FOLDER+fingerprint+".priv", "wb+") as f:
            f.write(contents)
        f.close()

"""
 schema:
  Signed
    incont[0] = fingerprint
    incont[1] = b64_enc_ciphertext
    incont[2] = b64_enc_signature
    incont[3] = b64_enc_tag
    incont[4] = b64_enc_nonce
    incont[5] = b64_enc_session_keys
    incont[6] = timestamp
    incont[7] = b64_time_signature
  Unsigned
    incont[0] = b64_enc_ciphertext
    incont[1] = b64_enc_tag
    incont[2] = b64_enc_nonce
    incont[3] = b64_enc_session_keys
    incont[4] = timestamp
"""

def EncryptMessage(file, keys, signed):
    with open(file, "rb") as f:
        ocontents = f.read()
    f.close()

    incont = ""
    keys_encd = ""

    ciphertext, tag, session_key, nonce = mPGPCrypto.AESEncrypt(ocontents)

    fingerprints = ""

    for key in keys:
        print(key)
        if CheckFingerprint(key) == False:
            key, _ = KeynameToFingerprint(key)

        fingerprints += key + ":" 

        path, _ = FingerprintToPath(key, searching_for="PUB")
        key_type = FingerprintToKeyType(key, searching_for="PUB")
        key_file_contents = open(path, "rb").read()

        first_unpack, keytype, special = UnpackKeyData(str(key_file_contents.decode()))
        first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))
        pri_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[0].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----\n\n", "").replace("\n", "")
        pub_key = base64.b64decode(bytes(pri_key_b64, "utf-8"))

        if key_type.startswith("RSA") or key_type == "0":
            enc_session_key = mPGPCrypto.RSAEncrypt(session_key, pub_key, session_key)
            b64_enc_key = base64.b64encode(enc_session_key)
            keys_encd += b64_enc_key.decode() + ":"
        else:
            print(f"Key type {key_type} not supported, skipping fingerprint {key}.  If this is an mPGP-Quantum key, please use qencrypt or qsignencrypt, not encrypt.")
            exit()

    if signed == "N":
        incont += base64.b64encode(ciphertext).decode() + ":"
        incont += base64.b64encode(tag).decode() + ":"
        incont += base64.b64encode(nonce).decode() + ":"
        incont += base64.b64encode(keys_encd.encode()).decode() + ":"
        incont += strftime("%Y-%m-%d %H.%M.%S", gmtime()) + ":"
        incont += base64.b64encode(fingerprints.encode()).decode()
    elif signed == "Y":
        with open(mpgpsettings.BASE_LOCATION+"keyring.rf", "r") as f:
            contents = f.readlines()
        f.close()
        print("\n\nChoose a private key to use for the signing:")
        for line in contents:
            split = line.split(":")
            if split[0] == "PRIV":
                private = split[0]
                kname = split[1]
                privpath = split[2]
                fingerprint = split[3]
                keytype = split[4]
                created_locally = split[5]

                print(f"{keytype} private key:  {kname} with fingerprint {fingerprint}")

        choice = input("\nType either the key name or fingerprint.\n> ")

        key_path, key_name = FingerprintToPath(fingerprint, searching_for="PRIV")
    
        if key_path == "NotFound":
            print(f"Key not found with fingerprint'{fingerprint}'")
            exit()

        key_file_contents = open(key_path, "rb").read()

        first_unpack, keytype, special = UnpackKeyData(str(key_file_contents.decode()))

        first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

        sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END SUB KEY-----", "").replace("\n", "")

        private_key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

        passphrase = getpass("Enter your private key password:\n> ")

        timestamp = strftime("%Y-%m-%d %H.%M.%S", gmtime())
        timestamp_hash = SHA256.new(bytes(timestamp, "utf-8")).hexdigest()

        signed_data, hashed_data = mPGPCrypto.RSASign(ocontents, private_key, passphrase)
        timestamp_signed, hashed_data_timestamp = mPGPCrypto.RSASign(bytes(timestamp, "utf-8"), private_key, passphrase)

        incont += fingerprint + ":"
        incont += base64.b64encode(ciphertext).decode() + ":"
        incont += base64.b64encode(signed_data).decode() + ":"
        incont += base64.b64encode(tag).decode() + ":"
        incont += base64.b64encode(nonce).decode() + ":"
        incont += base64.b64encode(keys_encd.encode()).decode() + ":"
        incont += timestamp + ":"
        incont += base64.b64encode(timestamp_signed).decode() + ":"
        incont += base64.b64encode(fingerprints.encode()).decode()
    else:
        print("Invalid `signed` type.  Please try again")

    enc_incont = base64.b64encode(incont.encode())

    towrite = PackKeyData(keytype="mPGP ENCRYPTED DATA", content=enc_incont.decode(), special="")
    with open(file+".asc", "w") as f:
        f.write(towrite)
    f.close()
        
    print(f"Written data to {file}.asc successfully.")

"""
 schema:
  Signed
    incont[0] = fingerprint
    incont[1] = b64_enc_ciphertext
    incont[2] = b64_enc_signature
    incont[3] = b64_enc_tag
    incont[4] = b64_enc_nonce
    incont[5] = b64_enc_session_keys
    incont[6] = timestamp
    incont[7] = b64_time_signature
    incont[8] = b64_enc_fingerprints
  Unsigned
    incont[0] = b64_enc_ciphertext
    incont[1] = b64_enc_tag
    incont[2] = b64_enc_nonce
    incont[3] = b64_enc_session_keys
    incont[4] = timestamp
    incont[5] = b64_enc_fingerprints
"""

def DecryptMessage(splitted, file):
    keys = ReturnPrivateKeys()

    if len(splitted) == 6:
        signed = "N"
        ciphertext = base64.b64decode(splitted[0].encode())
        tag = base64.b64decode(splitted[1].encode())
        nonce = base64.b64decode(splitted[2].encode())
        session_keys = base64.b64decode(splitted[3].encode())
        timestamp = splitted[4]
        fingerprints = base64.b64decode(splitted[5].encode()).decode().split(":")

        if bool(set(keys) & set(fingerprints)) == False:
            print("Not encrypted with any of your private keys..")
            exit()

        for item in keys:
            if item in fingerprints:
                fingerprint_to_use = item
                break

        key_path, _ = FingerprintToPath(fingerprint_to_use, searching_for="PRIV")
        
        key_file_contents = open(key_path, "rb").read()

        first_unpack, keytype, special = UnpackKeyData(str(key_file_contents.decode()))
        first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))
        pri_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----\n\n", "").replace("\n", "")
        key = base64.b64decode(bytes(pri_key_b64, "utf-8"))

        passphrase = getpass("Enter your private key password:\n> ")

        for keyz in session_keys.decode().split(":"):
            if keyz == "":
                pass
            output = mPGPCrypto.RSADecrypt(key=key, enc_session_key=base64.b64decode(keyz.encode()), nonce=nonce, tag=tag, ciphertext=ciphertext, passphrase=passphrase)
            if output != False:
                break

            print("Cannot decrypt, exiting")

        with open(file[:-4], "w") as f:
            f.write(output)

        print(f"Written output to {file[:-4]}")

    elif len(splitted) == 9:
        signed = "Y"
        fingerprint = splitted[0]
        ciphertext = base64.b64decode(splitted[1].encode())
        signature = base64.b64decode(splitted[2].encode())
        tag = base64.b64decode(splitted[3].encode())
        nonce = base64.b64decode(splitted[4].encode())
        session_keys = base64.b64decode(splitted[5].encode())
        timestamp = splitted[6]
        time_sig = base64.b64decode(splitted[7].encode())
        fingerprints = base64.b64decode(splitted[8].encode()).decode().split(":")

        if bool(set(keys) & set(fingerprints)) == False:
            print("Not encrypted with any of your private keys..")
            exit()

        for item in keys:
            if item in fingerprints:
                fingerprint_to_use = item
                break

        key_path, _ = FingerprintToPath(fingerprint_to_use, searching_for="PRIV")
        
        key_file_contents = open(key_path, "rb").read()

        first_unpack, keytype, special = UnpackKeyData(str(key_file_contents.decode()))
        first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))
        pri_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END PRIMARY KEY-----", "").replace("-----BEGIN PRIMARY KEY-----\n\n", "").replace("\n", "")
        key = base64.b64decode(bytes(pri_key_b64, "utf-8"))

        passphrase = getpass("Enter your private key password:\n> ")

        for keyz in session_keys.decode().split(":"):
            if keyz == "":
                pass
            output = mPGPCrypto.RSADecrypt(key=key, enc_session_key=base64.b64decode(keyz.encode()), nonce=nonce, tag=tag, ciphertext=ciphertext, passphrase=passphrase)
            if output != False:
                break

        h = SHA256.new(output.encode())

        key_path, key_name = FingerprintToPath(fingerprint, searching_for="PUB")

        key_file_contents = open(key_path, "rb").read()

        first_unpack, keytype, special = UnpackKeyData(str(key_file_contents.decode()))

        first_unpack_dec = base64.b64decode(bytes(first_unpack, "utf-8"))

        sub_key_b64 = (first_unpack_dec.decode()).split("-----BEGIN SUB KEY-----")[1].replace("-----END SUB KEY-----", "").replace("\n", "")

        key = base64.b64decode(bytes(sub_key_b64, "utf-8"))

        sig_check = mPGPCrypto.RSACheckSignature(signature, output.encode(), h, key)

        timestamp_hash = SHA256.new(timestamp.encode())

        timestamp_sig_check = mPGPCrypto.RSACheckSignature(signature=time_sig, file_contents=bytes(timestamp, "utf-8"), file_cont_hash=timestamp_hash, public_key=key)

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
    File {file} signed with key {fingerprint[-16:].upper()} and encrypted at {timestamp.replace(".", ":")} (timestamp verified {timestamp_status}).

        verdict:  {verd}
    """)   

        with open(file[:-4], "w") as f:
            f.write(output)

        print(f"Written output to {file[:-4]}")

def RestoreRSAKeypair(keysize, kname, passphrase, mnemo):
    """
    Restores RSA Keypair and stores it in the mPGP format.  Includes option for mnemonic phrase recovery.
    """
    bytes_private_key, private_hash, bytes_public_key, public_hash, mnemonic_phrase = mPGPCrypto.RSA_Keygen(keysize=keysize, password=mnemo, passphrase=passphrase)

    primary_key_public = bytes_public_key.decode()
    primary_key_private = bytes_private_key.decode()

    mnemo = mnemonic_phrase
    
    bytes_private_key, private_hash, bytes_public_key, public_hash, mnemonic_phrase = mPGPCrypto.RSA_Keygen(keysize=keysize, password=mnemonic_phrase+" mPGP", passphrase=passphrase)

    sub_key_public = bytes_public_key.decode()
    sub_key_private = bytes_private_key.decode()

    encoded_pub_primary_key = base64.b64encode(bytes(primary_key_public, "utf-8"))
    primary_key = PackKeyData(keytype="PRIMARY KEY", content=encoded_pub_primary_key.decode(), special="")

    encoded_pub_sub_key = base64.b64encode(bytes(sub_key_public, "utf-8"))
    sub_key = PackKeyData(keytype="SUB KEY", content=encoded_pub_sub_key.decode(), special="")

    encoded_full_pub_key = base64.b64encode(bytes((primary_key+"\n"+sub_key), "utf-8"))
    fingerprint = (SHA256.new(encoded_full_pub_key)).hexdigest()
    pub_key = PackKeyData(keytype="mPGP PUBLIC KEY BLOCK", content=encoded_full_pub_key.decode(), special=f"Name:{kname}\nKey:RSA-{keysize}\n\n")

    
    encoded_priv_primary_key = base64.b64encode(bytes(primary_key_private, "utf-8"))
    primary_key = PackKeyData(keytype="PRIMARY KEY", content=encoded_priv_primary_key.decode(), special="")

    encoded_priv_sub_key = base64.b64encode(bytes(sub_key_private, "utf-8"))
    sub_key = PackKeyData(keytype="SUB KEY", content=encoded_priv_sub_key.decode(), special="")

    encoded_full_priv_key = base64.b64encode(bytes((primary_key+"\n"+sub_key), "utf-8"))
    priv_key = PackKeyData(keytype="mPGP PRIVATE KEY BLOCK", content=encoded_full_priv_key.decode(), special=f"Name:{kname}\nKey:RSA-{keysize}\n\n")


    with open(f"{mpgpsettings.KEY_FOLDER}{fingerprint}.pub", "wb+") as f:
        f.write(bytes(pub_key, "utf-8"))
    f.close()\
    
    with open(f"{mpgpsettings.KEY_FOLDER}{fingerprint}.priv", "wb+") as f:
        f.write(bytes(priv_key, "utf-8"))
    f.close()

    with open(f"{mpgpsettings.BASE_LOCATION}keyring.rf", "a+") as f:
        f.write(f"PUB:{kname}:{mpgpsettings.KEY_FOLDER}{fingerprint}.pub:{fingerprint}:RSA-{keysize}:True\n")
        f.write(f"PRIV:{kname}:{mpgpsettings.KEY_FOLDER}{fingerprint}.priv:{fingerprint}:RSA-{keysize}:True\n")

    return f"Done!  Key backed up with:  {mnemo}"