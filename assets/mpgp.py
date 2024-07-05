#!/usr/local/bin/python3.12
'''
modern Pretty Good Privacy
'''
import sys, os
if os.name == "posix":
    sys.path.append('/usr/share/mpgp')
elif os.name == "nt":
    sys.path.append(os.getenv('APPDATA'))

import mPGPUtil, mpgpsettings, mPGPRSA, mPGPQuantum
import argparse, base64, os
from getpass import getpass

class Handler:
    def __init__(self):
        self.program = "mPGP v0.1.0"

    def handle(self):
        """Interpret the first command line argument, and redirect."""
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "action",
            choices=["keygenfull", "importkey", "listkeys", "sign", "verify", "clearsign", "encrypt", "decrypt", "signencrypt", "qencrypt", "qsignencrypt", "qdecrypt", "restorekey"],
            help="mPGP",
        )
        parser.add_argument("other", nargs="*")
        args = parser.parse_args()

        action = getattr(self, args.action)
        action()

    def keygenfull(self):
        print("""
        Keytypes are as follow:
        1) RSA + RSA  (recommented)
        2) ECC + ECC (Not implemented yet, might not be.)
        3) Kyber + Dilithium (Presumed Quantum Secure)
        """)
        keytype = input("Please choose a keytype from the above list:\n> ")
        if keytype != "1" and keytype != "2":
            print("Invalid choice")
        
        if keytype == "1" or keytype == 1:
            print("Please choose how many bits you would like to use for both keys between 2048 and 4096.  4096 is HIGHLY recommended. ")
            keysize = input("> ")
            if int(keysize) < 1024 or int(keysize) > 4096:
                print("Invalid keysize, choose between 2048 and 4096.")
                exit()
            
            print("Please enter a key name:")
            kname = input("> ")
            if kname == "":
                print("Invalid key name, please enter something")
                exit()

            passphrase = getpass("Please enter a password:\n> ")
            if passphrase == "":
                print("Password must not be blank")
                exit()
            passwordc = getpass("Please confirm password:\n> ")
            if passphrase != passwordc:
                print("Passwords do not match..")
                exit()
            print("\nKeys being generated, this may take a while..")
            response = mPGPUtil.GenerateRSAKeypair(int(keysize), kname, passphrase)

            print(response)
            exit()

        elif keytype == "2":
            print("ECC not implemented yet..")
            exit()
        elif keytype == "3":
            print("Please enter a key name:")
            kname = input("> ")
            if kname == "":
                print("Invalid key name, please enter something")
                exit()

            passphrase = getpass("Please enter a password:\n> ")
            if passphrase == "":
                print("Password must not be blank")
                exit()
            passwordc = getpass("Please confirm password:\n> ")
            if passphrase != passwordc:
                print("Passwords do not match..")
                exit()
            response = mPGPQuantum.GenerateQuantumKeypair(kname, passphrase)
            exit()
        else:
            print("Invalid choice")
            exit()

    def importkey(self):
        """Initiate connection with a client"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["importkey"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", " ").replace("\r", "")
        
        mPGPUtil.ImportKey(file)
        exit()

    def listkeys(self):
        keystring = mPGPUtil.GetKeys()
        print(keystring)
        exit()
        
    def sign(self):
        """Sign a message/file"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["sign"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")
        
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

                print(f"{keytype} private key:  {kname} with fingerprint {fingerprint}")

        choice = input("\nType either the key name or fingerprint.\n> ")

        if mPGPUtil.CheckFingerprint(choice) == True:
            new_fingerprint = fingerprint
        else:
            new_fingerprint, path = mPGPUtil.KeynameToFingerprint(choice)
            key_type = mPGPUtil.FingerprintToKeyType(new_fingerprint, searching_for="PRIV")

        if new_fingerprint == "NotFound":
            print("Fingerprint not found..  try again")
            exit()

        if key_type.startswith("RSA"):
            mPGPRSA.RSASignMessage(new_fingerprint, file)
        elif key_type == "mPGP-Quantum":
            mPGPQuantum.QuantumSignMessage(new_fingerprint, file)
        else:
            print("Invalid key type")
            exit()

    def verify(self):
        """Verify a signature"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["verify"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")

        with open(file, "r") as f:
            contents = f.read()
        f.close()

        lines = contents.splitlines()
        if lines[0] == "-----BEGIN mPGP SIGNED MESSAGE-----":
            message, key_type, unpacked = mPGPUtil.UnpackClearsig(contents)
        else:
            unpacked, key_type, special = mPGPUtil.UnpackKeyData(contents)
        
        cleartext = base64.b64decode(bytes(unpacked, "utf-8"))

        splitted = cleartext.decode().split(":")

        if key_type == " mPGP SIGNED DATA" or key_type == "mPGP SIGNED DATA":
            if len(splitted) == 8:
                if splitted[7] == "RSA" or splitted[7] == "0":
                    mPGPRSA.RSACheckSignature(unpacked, file)
                else:
                    print("Invalid key type, consider updating if you believe this to be a mistake..")
                    exit()
            elif len(splitted) == 6:
                if splitted[5] == "mPGP-Quantum" or splitted[5] == "2":
                    mPGPQuantum.QuantumCheckSignature(unpacked, file)
                else:
                    print("Invalid key type, consider updating if you believe this to be a mistake..")
                    exit()
            else:
                print("Invalid key type, consider updating if you believe this to be a mistake..")
                exit()
        elif key_type == "mPGP SIGNATURE" or " mPGP SIGNATURE":
            if len(splitted) == 6:
                if splitted[5] == "RSA" or splitted[5] == "0":
                    mPGPRSA.RSACheckCleartextSignature(unpacked, message, file)
                else:
                    print("Invalid key type")
                    exit()
            elif len(splitted) == 5:
                if splitted[4] == "mPGP-Quantum" or splitted[4] == "2":
                    mPGPQuantum.QuantumCheckCleartextSignature(unpacked, message, file)
            else:
                print("Invalid key type, consider updating if you believe this to be a mistake..")
                exit()
        else:
            print("Signature data cannot be found")
            exit()

    def clearsign(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["clearsign"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")
        
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

                print(f"{keytype} private key:  {kname} with fingerprint {fingerprint}")

        choice = input("\nType either the key name or fingerprint.\n> ")

        if mPGPUtil.CheckFingerprint(choice) == True:
            new_fingerprint = fingerprint
        else:
            new_fingerprint, path = mPGPUtil.KeynameToFingerprint(choice)
            key_type = mPGPUtil.FingerprintToKeyType(new_fingerprint, searching_for="PRIV")

        if new_fingerprint == "NotFound":
            print("Fingerprint not found..  try again")
            exit()

        if key_type.startswith("RSA"):
            mPGPRSA.RSAClearsignMessage(new_fingerprint, file)
        elif key_type == "mPGP-Quantum":
            mPGPQuantum.QuantumClearsignMessage(new_fingerprint, file)
        else:
            print("Invalid key type")
            exit()

    def encrypt(self):
        """Encrypt a file or piece of data"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["encrypt"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")

        with open(mpgpsettings.BASE_LOCATION+"keyring.rf", "r") as f:
            contents = f.readlines()
        f.close()

        print("Choose a private key to use:")
        for line in contents:
            split = line.split(":")
            if split[0] == "PUB":
                public = split[0]
                kname = split[1]
                pubpath = split[2]
                fingerprint = split[3]
                keytype = split[4]
                created_locally = split[5]

                if keytype != "mPGP-Quantum":
                    print(f"{keytype} public key:  {kname} with fingerprint {fingerprint}")

        keys = []
        while True:
            choice = input("\nType either the key name or fingerprint.\n> ")
            keys.append(choice)
            choicecont = input("\nWould you like to enc for another key too? Y/N\n> ")
            if choicecont.upper() == "N":
                break

        mPGPUtil.EncryptMessage(file, keys, signed="N")
        exit()

    def signencrypt(self):
        """Sign and encrypt a file or piece of data"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["signencrypt"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")

        with open(mpgpsettings.BASE_LOCATION+"keyring.rf", "r") as f:
            contents = f.readlines()
        f.close()

        print("Choose a public key to encrpy for:")
        for line in contents:
            split = line.split(":")
            if split[0] == "PUB":
                public = split[0]
                kname = split[1]
                pubpath = split[2]
                fingerprint = split[3]
                keytype = split[4]
                created_locally = split[5]

                print(f"{keytype} public key:  {kname} with fingerprint {fingerprint}")

        keys = []
        while True:
            choice = input("\nType either the key name or fingerprint.\n> ")
            keys.append(choice)
            choicecont = input("\nWould you like to enc for another key too? Y/N\n> ")
            if choicecont.upper() == "N":
                break

        mPGPUtil.EncryptMessage(file, keys, signed="Y")
        exit()

    def decrypt(self):
        """Decrypt a file or piece of data"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["decrypt"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")

        with open(file, "r") as f:
            contents = f.read()
        f.close()

        unpacked, key_type, special = mPGPUtil.UnpackKeyData(contents)
        
        cleartext = base64.b64decode(bytes(unpacked, "utf-8"))

        splitted = cleartext.decode().split(":")

        mPGPUtil.DecryptMessage(splitted, file)

    def qencrypt(self):
        """Quantum encrypt a file or piece of data"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["qencrypt"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")

        with open(mpgpsettings.BASE_LOCATION+"keyring.rf", "r") as f:
            contents = f.readlines()
        f.close()

        print("Choose a private key to use:")
        for line in contents:
            split = line.split(":")
            if split[0] == "PUB":
                public = split[0]
                kname = split[1]
                pubpath = split[2]
                fingerprint = split[3]
                keytype = split[4]
                created_locally = split[5]

                if keytype == "mPGP-Quantum":
                    print(f"{keytype} public key:  {kname} with fingerprint {fingerprint}")

        choice = input("\nType either the key name or fingerprint.\n> ")
            
        mPGPQuantum.EncryptMessage(file, choice, signed="N")
        exit()

    def qsignencrypt(self):
        """Quantum sign and encrypt a file or piece of data"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["qsignencrypt"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")

        with open(mpgpsettings.BASE_LOCATION+"keyring.rf", "r") as f:
            contents = f.readlines()
        f.close()

        print("Choose a private key to use:")
        for line in contents:
            split = line.split(":")
            if split[0] == "PUB":
                public = split[0]
                kname = split[1]
                pubpath = split[2]
                fingerprint = split[3]
                keytype = split[4]
                created_locally = split[5]

                if keytype == "mPGP-Quantum":
                    print(f"{keytype} public key:  {kname} with fingerprint {fingerprint}")

        choice = input("\nType either the key name or fingerprint.\n> ")
            
        mPGPQuantum.EncryptMessage(file, choice, signed="Y")
        exit()

    def qdecrypt(self):
        """Quantum decrypt a file or piece of data"""
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["qdecrypt"])
        parser.add_argument("file", type=str, nargs="*")
        args = parser.parse_args()

        file = ' '.join(args.file).replace("\n", "").replace("\r", "")

        with open(file) as f:
            lines = f.readlines()
        f.close()

        if lines[0] == "-----BEGIN mPGP Q-SENCRYPTED DATA-----\n" or lines[0] == "-----BEGIN mPGP Q-SENCRYPTED DATA-----":
            mPGPQuantum.QuantumDecryptAndVerify(file)
        elif lines[0] == "-----BEGIN mPGP Q-ENCRYPTED DATA-----\n" or lines[0] == "-----BEGIN mPGP Q-ENCRYPTED DATA-----":
            mPGPQuantum.QuantumDecrypt(file)
        else:
            print("Invalid mPGP-Quantum file")

        exit()

    def restorekey(self):
        print("Please enter mnemonic phrase:")
        mnemo = input("> ")
        print("Please enter key bits:")
        bits = input("> ")
        print("Please enter a key name:")
        kname = input("> ")
        if kname == "":
            print("Invalid key name, please enter something")
            exit()

        passphrase = getpass("Please enter a password:\n> ")
        if passphrase == "":
            print("Password must not be blank")
            exit()
        passwordc = getpass("Please confirm password:\n> ")
        if passphrase != passwordc:
            print("Passwords do not match..")
            exit()
        response = mPGPUtil.RestoreRSAKeypair(int(bits), kname, passphrase, mnemo)
        exit()

def perform_checks():
    if mpgpsettings.BASE_LOCATION == "INVALID":
        print("Base location error..")
        exit()

if __name__ == "__main__":
    perform_checks()
    handler = Handler()
    handler.handle()