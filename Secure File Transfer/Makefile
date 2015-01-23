# SPECIFY WHAT NEEDS TO BE DONE WHEN make IS CALLED
all: encrypt decrypt

# COMPILE & LINK THE LIBRARIES REQUIRED FOR ENCRYPTION: gatorcrypt
encrypt: 
	gcc -o gatorcrypt gatorcrypt.c -lgcrypt -lcrypto -g

# COMPILE & LINK THE LIBRARIES REQUIRED FOR dECRYPTION: gatordec
decrypt:
	gcc -o gatordec gatordec.c -lgcrypt -lcrypto -g

# CLEAN UP UNNECESSARY FILES
clean:
	rm gatorcrypt gatordec *.uf RecdFile.check
