#include <stdio.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <gcrypt.h>
#include <openssl/aes.h>
#include <ctype.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

// DEFINE TRUE & FALSE
#define TRUE 1
#define FALSE 0

#define NO_OF_ITER 4096		// DEFINE THE NUBMER OF ITERATIONS FOR PBKDF2

#define MAX 50			// MAX LENGTH FOR PASSWORD

#define MAX_CONN 5		// MAX NUMBER OF CONNECTION ACCEPTED AT A PORT

#define MAX_BUF_SIZE 1024	// MAX BUFFER SIZE


char *inFilename;
char *tempFile = "RecdFile.check";			// TEMPORARY FILE THAT DOES HOLDS DATA RECEIVED FROM THE SOCKET
char* ciphertext;
unsigned char *plaintext;
int hashLen;
char *newCipher;
char pwd[MAX];
char *key;
size_t keyLen;
unsigned char *digest;
unsigned char *redigest;


// CHECK IF THE INPUT IS READY TO BE READ
int iput_ready(int sock_id)
{
	struct timeval tv;
	fd_set read_fd;
	tv.tv_sec=0;
	tv.tv_usec=0;
	FD_ZERO(&read_fd);
	FD_SET(sock_id,&read_fd);

	if(select(sock_id+1, &read_fd, NULL, NULL, &tv) == -1)
		return 0;

	if(FD_ISSET(sock_id,&read_fd))
		return 1;

	return 0;
}


// LISTEN AT THE SPECIFIED PORT FOR INCOMING TRAFFIC
int ListenAt(char *port)
{
	int serv_sockfd, cli_sockfd, portno, clilen;
	int i,DROPTHIS1,DROPTHIS2;
	int dropping = TRUE;
	struct sockaddr_in serv_addr, cli_addr;
	char temp[MAX_BUF_SIZE];
	long int bytesRecd, totalBytes;

	//Get the socket for the server	
	serv_sockfd = socket(AF_INET,SOCK_STREAM,0);

	if(serv_sockfd<0)
		error("ERROR OPENING SOCKET");

	bzero((int *) &serv_addr,sizeof(serv_addr));

	//Set the socket parameters
	portno = atoi(port);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	//Bind: the parameters to this are (descriptor, address, sizeof(address)). It returns zero on success
	if(bind(serv_sockfd,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR ON BINDING");
	
	listen(serv_sockfd, MAX_CONN);		//Listen: the parameters are (descriptor, max no of connections it can accept)
		
	clilen = sizeof(cli_addr);
	printf("Waiting for connections..\n");

	//Accept: (descriptor,pointer to struct of client address, sizeof(pointer to the variable having the size of the structure)
       	cli_sockfd = accept(serv_sockfd,(struct sockaddr *) &cli_addr,&clilen);
		
	if(cli_sockfd < 0)
		error("ERROR on accept");

	i = 0;
	FILE *fh = fopen(tempFile, "w+");
	totalBytes = 0;

	if (fh == NULL)
	{
		printf("Error opening file for writing\n");
		exit(0);
	}

	while(1)
	{
		if(iput_ready(cli_sockfd))
		{
			printf("Inbound data\n");		

			bzero(temp, MAX_BUF_SIZE);				

			//Read data from the socket. parameters are (descriptor,data,sizeof(data))
			bytesRecd = read(cli_sockfd, temp, MAX_BUF_SIZE);
			
			if (fh && bytesRecd > 0)
			{
				int i;
				for(i = 0; i<strlen(temp); i++)
					fputc(temp[i], fh);				
				//fputs(temp, fh);
				totalBytes += bytesRecd;
			}
			else break;
		}		
	}

	if (fh) fclose(fh);

	return 0;
}


// READ THE INPUT FILE TO BE DECRYPTED IN A BUFFER
void ReadFileToDecrypt()
{
	ciphertext = NULL;
	FILE *fp = fopen(tempFile, "r");	// OPEN THE FILE IN A READ MODE
	if (fp != NULL)
	{
		// GET THE FILE SIZE
		if (fseek(fp, 0, SEEK_END) == 0)
		{
			long fileSize = ftell(fp);
			
			if (fileSize == -1)
				printf("FILE READ: Error while computing fileSize\n");

			// ALLOCATE A BUFFER TO DUMP THE FILE CONTENTS
			ciphertext = (char *)malloc(sizeof(char) *(fileSize+1));
			
			// GO BACK TO THE BEGINNING OF THE FILE TO START READING
			if (fseek(fp, 0, SEEK_SET) != 0)
				printf("FILE READ: Error while seeking to the beginning of the file\n");
	
			// READ FILE CONTENTS INTO THE BUFFER
			char buf[MAX_BUF_SIZE];
			while (fgets(buf, MAX_BUF_SIZE, fp) != NULL) 
			{	        	
				strcat(ciphertext, buf);
				//printf("\nBuffer read: \n %s", buf);
			}

       		}

		fclose(fp);		// CLOSE THE FILE
	}
	else
	{
		printf("File %s NOT found\n", tempFile);
		exit(0);
	}	
}



// DERIVE KEY BASED ON PASSWORD BY USING PBKDF2
void GetKeyByPBKDF2()
{
	int err = -1;
	int i;

	unsigned char hashResult[hashLen];
	const char* SALT = "NaCl";
	
	// DERIVE THE KEY BASED ON THE PASSWORD ENTERED: err = ERROR_STATUS_CODE
	err = gcry_kdf_derive (pwd, strlen(pwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, SALT, strlen(SALT), NO_OF_ITER, hashLen, hashResult);
	
	key = (char *) malloc(sizeof(char) * ((hashLen*2)+1));	// CHAR* TO STORE THE KEY

	// FORMAT THE KEY AND STORE IN key IN HEX FORMAT
	for (i = 0; i < sizeof(hashResult); i++)
		sprintf(key + i*2, "%02X", hashResult[i]);
	
	// PRINT THE KEY
	keyLen = strlen(key);
	printf("KEY: ");	
	for (i = 0; i<strlen(key)/2; i+=2)
		printf("%c%c ", key[i], key[i+1]);

}


// AUTHENTICATE THE HASH DIGEST USING SHA-512 ENABLED WITH HMAC
void AuthenticateHash()
{
	// SHA-512 WITH HMAC FOR AUTHENTICATION
	redigest = NULL;			// TO STORE THE HASH DIGEST

	// COPY THE ENCRYPTED CIPHERTEXT IN A TEMPORARY BUFFER SO THAT SHA-512 CAN ACT ON IT TO PROVIDE A NEW HASH
	// THIS HASH WILL BE THEN APPENDED TO THE ENCRYPTED CIPHERTEXT TO FORM THE FINAL CIPHERTEXT
	gcry_md_hd_t gHandle;	// HANDLE

	int err = 0;

	// OPEN THE HANDLE
	err = gcry_md_open(&gHandle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	if (err)
		printf("SHA-512 with HMAC: ERROR in opening handle");
	
	// SET THE HMAC FLAG
	err = 0;	
	err = gcry_md_setkey (gHandle, key, keyLen);
	
	// CALL SHA-512
	gcry_md_write(gHandle, newCipher, strlen(newCipher));

	redigest = gcry_md_read(gHandle, 0);

	//free(outBuf);
	//free(digest);

	// AUTHENTICATE: COMPARE THE HASH VALUES AND IF EQUAL = AUTHENTICATED
	// NOT AUTHENTICATED, THEN EXIT THE FUNCTION AND DO NOT PROCEED

	//printf("\nRedigest\n%s", redigest);
	//printf("\nDigest\n%s", digest);

	if (strcmp(redigest, digest))
	{
		printf("Not Authenticated!\n");
		exit(0);
	}

}



// DECRYPT FILE USING AES
void AESDecrypt()
{
	// ONCE AUTHENTICATED, PROCEED WITH DECRYPTION
	// DECRYPT VIA AES
	int cipherLen = strlen(newCipher);
	const int AES_KEY_LEN = 128;			// 128 BITS

	// PREPARE THE BUFFER TO HOLD DECRYPTED CIPHERTEXT
	const int plainLen = ((strlen(newCipher) + AES_BLOCK_SIZE)/AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	plaintext = (unsigned char *) malloc(sizeof(unsigned char) *plainLen);
	memset(plaintext, 0, sizeof(plaintext));	// INITIALIZE WITH ZEROS (0)

	// PREPARE THE INITIALIZATION VECTOR
	unsigned char *IV_value = (unsigned char *) malloc(sizeof(unsigned char) *AES_BLOCK_SIZE);
	memset(IV_value, toascii(5844), AES_BLOCK_SIZE);

	// PREPARE THE AES KEY
	AES_KEY decKey;
	AES_set_decrypt_key(key, keyLen, &decKey);

	// AES-128 CBC DECRYPT
	AES_cbc_encrypt(newCipher, plaintext, cipherLen, &decKey, IV_value, AES_DECRYPT);
}



// PRINT THAT INVALID COMMAND-LINE ARGUMENTS HAVE BEEN SPECIFIED: PRINT OUT THE CORRECT FORMAT & EXIT THE PROGRAM
void InvalidArgs()
{
	printf("Incorrect number of arguments. Please enter in the following format:\n");
	printf("gatorcrypt <input file> [-d < IP-addr:port >][-l]");
	exit(0);
}



int main(int argc, char *argv[])
{
	/* gatordec <filename>  [-d < port >][-l]  */

	// argc should be atleast 3 for correct execution	
	if ( argc < 3 ) InvalidArgs();

	if (argc == 3)
		if (strcmp(argv[2],"-d") || strcmp(argv[2],"-l"))
			InvalidArgs();
		
	if ((!strcmp(argv[2],"-d")) && argv[3] == NULL)
		InvalidArgs();

/*
	// DAEMONIZE
	pid_t pid, sid;

	// Clone ourselves to make a child
	pid = fork(); 

	// If the pid is less than zero, something went wrong when forking
	if (pid < 0) exit(EXIT_FAILURE);

	// If the pid we got back was greater than zero, then the clone was successful and we are the parent
	if (pid > 0) exit(EXIT_SUCCESS);

	// If execution reaches this point we are the child - Set the umask to zero 
	umask(0);

	// Try to create our own process group
	sid = setsid();
	if (sid < 0) exit(EXIT_FAILURE);

	// Change the current working directory to root
	if ((chdir("/")) < 0) exit(EXIT_FAILURE);
	
	while (1) { }
*/


	inFilename = argv[1];

	int fileReceive = ListenAt(argv[3]);

	// CHECK IF THE INPUT FILE ALREADY EXISTS: RETURN WITH AN ERR CODE OF 33
	struct stat sb;   
	if (!stat (inFilename, &sb))
	{
		printf("The input file %s already exists\n", inFilename);
		exit(33);
	}


	// READ THE INPUT FILE TO BE DECRYPTED IN A BUFFER
	ReadFileToDecrypt();

	int i, err;

	/* CIPHERTEXT = ORIGINAL CIPHERTEXT + SHA-512 HASH DIGEST
	   ciphertext = origCipher + digest */

	// SHA-512 WITH HMAC FOR AUTHENTICATION
	hashLen = gcry_md_get_algo_dlen(GCRY_MD_SHA512);	//GET HASH LENGTH FOR SHA-512


	// COPY THE ENTIRE CIPHERTEXT INTO A TEMPORARY CHAR* newCipher
	newCipher = (char*)malloc(sizeof(char)*strlen(ciphertext));
	for (i=0; i<strlen(ciphertext); i++)
		newCipher[i] = ciphertext[i];

	newCipher[i] = '\0';	

	int count = 0;
	for(i=0; i<strlen(newCipher); i++)
	{
		if (newCipher[i] == '#')
			count++;
		if ((newCipher[i] != '#') && count)
			count++;
	}


	// SEPARATE THE ENCRYPTED DATA AND THE HASH DIGEST
	int index = (int)(strchr(ciphertext, '#') - ciphertext);			// FIND THE INDEX OF '#'
	//unsigned char digest[count+1];						// TO STORE THE HASH DIGEST
	digest = (char *) malloc(sizeof(char) * (count+1));						// TO STORE THE HASH DIGEST
	strncpy(digest, ciphertext+index+1, strlen(ciphertext)-index+1);		// EXTRACT THE HASH DIGEST
	

	// EXTRACT THE CIPHERTEXT FROM THE INPUT
	for (i=0; i<strlen(newCipher); i++)
	{	
		if (newCipher[i] == '#')
			break; 
	}

	newCipher[i] = '\0';

	//free (ciphertext);
	//free (newCipher);

	//printf("\nNew Cipher \n %s", newCipher);
	//printf("\nDigest \n %s", digest);

	printf("\nPlease enter a password: ");
	fgets(pwd, sizeof(pwd), stdin);

	// DERIVE KEY BASED ON PASSWORD: PBKDF2
	GetKeyByPBKDF2();

	printf("\n");

	// AUTHENTICATE USING SHA-512 WITH HMAC ENABLED
	AuthenticateHash();

	// DECRYPT THE FILE CONTENTS
	AESDecrypt();

	// WRITE THE DECRYPTED PLAINTEXT TO FILE
	FILE *fp = fopen(inFilename, "w+");
	if (fp !=NULL)
	{
		fwrite(plaintext, sizeof(char), strlen(plaintext), fp);
		fclose(fp);
		printf("Successfully received and decrypted %s (%zd bytes written)\n", inFilename, strlen(plaintext));
	}
	else
		printf("Error opening file %s for writing\n", inFilename);

	//free(IV_value);
	//free(plaintext);

	return 0;
	
}

