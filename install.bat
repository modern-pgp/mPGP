pip3 install argparse
pip3 install pycryptodomex
pip3 install quantcrypt
pip3 install getpass
pip3 install mnemonic
pip3 install pyinstaller

mkdir %AppData%\mpgp
mkdir %AppData%\mpgp\keys
move assets\* %AppData%\mpgp

doskey mpgp= python3 %appdata%\mpgp\mpgp.py $1 $2 $3