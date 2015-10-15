# Secure File Transfer
A C-program to provide an *scp*-like secure file transfer. The encryption was done in AES-128 in Cipher Block Chaining (CBC) mode. This encrypted content was then hashed using SHA-512 in HMAC mode for authentication.

The program runs as a client and a server, and also runs locally (standalone).

# Kaminsky and Other DNS Attacks
This contains all the different DNS attacks that can be launched. All these attacks were carried out between a workstation and a virtual machine hosted by it. It contains the following tasks:

* Task 1 - Modify HOSTS file
* Task 2 - Directly spoof response to the user
* Task 3 - DNS Server Cache Poisoning
* Task 4 - DNS Server Cache Poisoning
* Task 5 - Kaminsky Attack