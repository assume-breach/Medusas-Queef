#!/bin/bash
apt update -y
apt install python-pip -y
apt-get install mingw-w64 -y
pip install pycryptodome
apt install osslsigncode -y
cd Resources/
bash createcert.sh
