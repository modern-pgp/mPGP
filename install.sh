# mPGP Installer

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

printf "Thank you for installing mPGP!  Installing now..."


cwd=$(pwd)

pip3.12 install argparse
pip3.12 install pycryptodome
pip3.12 install quantcrypt
pip3.12 install getpass
pip3.12 install mnemonic
pip3.12 install pathlib

mkdir /usr/share/mpgp
mkdir /usr/share/mpgp/keys
chmod 777 -R /usr/share/mpgp
chown -R $USER:$USER /usr/share/mpgp
mv ./assets/mpgp.py /usr/bin/mpgp
mv ./assets/* /usr/share/mpgp
chmod +x /usr/bin/mpgp