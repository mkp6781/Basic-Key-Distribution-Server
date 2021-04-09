# Key distribution with centralised server

A centralised Key Distribution Centre is responsible for storing user details including 
user name, ip address, user port number, and a hash digest obtained from combining passphrase with
name. This hash digest is used as 'salt' to derive the secret key shared between a particular
client and server. For client-server interaction, messages are encrypted using this obtained unique key for each client.
A client 'A' who wishes to communicate with another client 'B' registered with the same server 
approaches the server so that a session key can be generated for secure interaction between both
involved parties. The server encrypts this session key and other details required for
authentication with the respective shared secret keys with the clients A and B. This message
from the server can only be decrypted by these 2 clients ensuring secure distribution of a 
symmetric key.

## Setup Instructions
```
sudo apt install python3
sudo apt install python3-pip
pip3 install cryptography==3.3.1
```

## Running Code
Make sure pwd.txt is present before running code(either as an empty file or with details of
already registered user). 
Input message to be sent is to be stored in a file in.txt

1. KDC
```
./kdc -p <kdc_port_no> -o out.txt -f pwd.txt
```

2. Client - Reciever
Register the reciever client(if not previously registered) with KDC and wait for message
from sender on port number 60000.
```
./client -n <reciever_name> -m R -s outenc -o outfile -a 127.0.0.1 -p <kdcport>
```

3. Client - Sender
Register the sender client(if not previously registered) with KDC. 
```
./client -n <sender_name> -m S -r <reciever_name> -i in.txt -a 127.0.0.1 -p <kdcport>
```
Follow along with the prompts to complete process of sending a message.
Script files of a sample run are available in "SCRIPTS" folder

**NOTE**: 
* Reciever client should be run before sender client.
* All communications are between ports within `localhost`.
* InvalidToken error is raised and socket is closed if passwords used do not match.
