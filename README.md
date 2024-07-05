# mPGP
mPGP is a modern rework of the OpenPGP standard

## Overview
mPGP is a modern rework of the OpenPGP standard built in Python.
Python 3.12 is required!

While it is not perfect, mPGP is a modern implementation which includes (presumed) quantum secure encryption and message signatures.
mPGP also removes `armor headers`, which have been the cause of some inexperienced users being tricked into thinking forged messages are authentic.
There are some other slight changes which do not need to be listed here.

PLEASE NOTE:  mPGP Quantum encryption and signatures may not work on an ARM64 devices

## Schemas
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

##  Installation
First of all, all devices and setups are different, so depending on your setup you may need to install it differently.
The setup tools were designed to cater to the average system, though

For windows:
```console
$ git clone https://github.com/modern-pgp/mPGP

$ install.bat

$ mpgp (args)
```

For Linux
```console
$ git clone https://github.com/modern-pgp/mPGP

$ sudo chmod +x install.sh

$ sudo ./install.sh

$ mpgp (args)
```

## Final thoughts
This project is still in early testing stages and the code is very messy in places.
If you have any issues please feel free to reach me at finlay.business@proton.me or open an issue and I will attempt to help you as best I can.
If you wish to help with the project in any way, feel free to open a pull request or email me.