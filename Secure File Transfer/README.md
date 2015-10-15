# Requirements
The file encryption programs **gatorcrypt** and **gatordec** should take the following inputs:
```
gatorcrypt <input file> [-d < IP-addr:port >][-l]

gatordec <filename>  [-d < port >][-l] 
```         

where **gatorcrypt** takes an input file and transmits it to the IP address/port specified on the command-line (-d option), or dumps the encrypted contents of the input file to an output file of the same name, but with the added extension ".uf" e.g., if the input file is hello.txt, the output file should hello.txt.uf.

Note that the **gatordec** should run as a network daemon (-d), awaiting incoming network connections on the command-line specified network port. When a connection comes in, it writes the file data to "filename" and exits. gatordec can also be run in local mode (-l) in which it bypasses the network functionality and simply decrypts a file specified as input. It is assumed that the input file (for decryption) ends ".uf", so the output will be the original filename without this additional extension. (This is simply the inverse of gatorcrypt).

On each invocation, *gatorcrypt* and *gatordec* should prompt the user for a password. This password will be used to securely generate an encryption using PBKDF2 (Password Based Key Derivation Function 2). When running PBKDF2, use SHA-512 with 4096 iterations and the string "NaCl" as the salt. libgcrypt implements PBKDF2, so use their implementation. After generation, for grading the key should be printed as a hexadecimal number as in the example execution below.

Encryption must be done using AES128 in Cipher Block Chaining (CBC) Mode. Be sure to initialize the IV of each invocation to 5844 (the integer, not the ASCII character).

In addition to encryption, *gatorcrypt* and *gatordec* should use an HMAC for authentication. On encryption, the HMAC should be appended to the output, and on decryption it should be removed before writing the output. gatordec should give an error and exit (with exit code 62) if the input HMAC is not correct. Use SHA-512 as the hash function, and HMAC the encrypted data. Libgcrypt provides SHA-512 and provides a flag to use it in HMAC mode. Use the same key as encryption (for simplicity).

Both *gatorcrypt* and *gatordec* should display an error and abort the operation if the output file already exists. *main()* should return 33 when this happens.

An example session using these tools might look like (this is not actual output):

    octave% ./gatorcrypt testfile -d 192.168.1.48:8888
    Password: hello
    Key: FA 3A 2F D3 7E CB 27 F2 B3 42 35 06 CF B1 ED 0E 
    Successfully encrypted testfile to testfile.uf (6512 bytes written).
    Transmitting to 192.168.1.42:8888
        Successfully received

    -----

    nittany% ./gatordec testfile -d 8888
    Waiting for connections.   
    Inbound file. 
    Password: hello
    Key: FA 3A 2F D3 7E CB 27 F2 B3 42 35 06 CF B1 ED 0E 
    Successfully received and decrypted testfile (6400 bytes written).
    nittany% 