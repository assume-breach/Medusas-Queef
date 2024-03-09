# Medusas-Queef

Offensive Security Just Got A Lot Stankier

<img width="466" alt="Screenshot 2024-03-08 at 5 10 59 PM" src="https://github.com/assume-breach/Medusas-Queef/assets/76174163/02364d79-29ed-4a21-8a20-9ade1a8c4ad9">

A variation on the Sektor7 Perun's Fart method from the Windows Evasion Course. 

**Features:**

EXE/DLL compliation

HTTP(s) staging

NT API usage 

Custom GetProcAddress

AES payload encryption

Ntdll unhooking

String/function name obfuscation using the onboard dictionary in /usr/share/dict/words

APC injection via Early Bird method

Self signed certificate automation

Customized binary icon to blend in with other executables/files

**Usage**

Run the setup.sh file to install all dependencies and set up your self signed certificate. Should you want to change out your self signed cert, you can always just run the setup script again. 

Run queef.sh and follow the prompts to compile the binary/dll. 

<img width="482" alt="Screenshot 2024-03-08 at 6 41 20 PM" src="https://github.com/assume-breach/Medusas-Queef/assets/76174163/4b98825d-a765-4737-8e77-fc7b16d99452">

Now set your payload sever according to whatever you entered into the script and host your payload file.

Download to the target.

<img width="850" alt="Screenshot 2024-03-08 at 6 45 22 PM" src="https://github.com/assume-breach/Medusas-Queef/assets/76174163/f89bebe2-6d4a-418f-b40b-feca4772efeb">

<img width="407" alt="Screenshot 2024-02-03 at 3 36 05 PM" src="https://github.com/assume-breach/Medusas-Queef/assets/76174163/3470b112-7e0a-4300-9eb4-e171f5279c9b">

Execute and wait for your C2 callback. 

<img width="1062" alt="Screenshot 2024-02-03 at 3 38 39 PM" src="https://github.com/assume-breach/Medusas-Queef/assets/76174163/2e86f9a0-723c-49ae-9906-21604516d467">

Currently gets past Defender. Elastic flags it for suspicious parent child process and injection, but it could work against other EDRs. Try for yourself!

