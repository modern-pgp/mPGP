import os

if os.name == "nt":
    BASE_LOCATION = os.getenv('APPDATA').replace("\\", "/")+"/mpgp/"
elif os.name == "posix":
    BASE_LOCATION = "/usr/share/mpgp/"

KEY_FOLDER = BASE_LOCATION+"keys/"
KEYRING = BASE_LOCATION + "keyring.rf"

VERSION = "mPGP v0.1.0"