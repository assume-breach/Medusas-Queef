#!/bin/bash
apt update -y
apt-get install mingw-w64 -y
pip install pycryptodome
apt install osslsigncode -y
cd Resources/
bash createcert.sh
