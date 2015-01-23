#include <stdio.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <gcrypt.h>
#include <openssl/aes.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

// DEFINE TRUE & FALSE
#define TRUE 1
#define FALSE 0

// DEFINE THE NUBMER OF ITERATIONS FOR PBKDF2
#define NO_OF_ITER 4096

#define MAX 50			// MAX PASSWORD LENGTH

#define MAX_CONN 5		// MAX NUMBER OF CONNECTION ACCEPTED AT A PORT

#define MAX_BUF_SIZE 1024	// MAX BUFFER SIZE

#define CONNECTION_ERROR 2	// SOCKET CONNECTION ERROR

unsigned char *ciphertext;
char *inFilename;
char *outFilename;
char* plaintext;
int hashLen;
size_t keyLen;
char *key;
unsigned char *digest;
unsigned char *outBuf;
char pwd[MAX];
int totalBytes;

// FUNCTION TO RECEIVE FILES
int SendEncFile(char addr[])
{
	int sockfd, portno;
	long int n;
	int i;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	totalBytes = 0;

	//printf("in prog");

	// SEPARATE THE PORT NUMBER FROM THE IP ADDRESS
	size_t index = (size_t)(strchr(addr, ':') - (size_t)addr);			// FIND THE INDEX OF ':'
	unsigned char port[4];								// TO STORE THE PORT NUMBER

	// EXTRACT THE PORT NUMBER
	for (i = 0; addr[index + 1 + i] != '\0'; i++)
		port[i] = addr[index+1+i];						


	// EXTRACT THE IP ADDRESS
	unsigned char *IPaddr = (char *) malloc(sizeof(char) * (index + 1));
	for (i = 0; i < index; i++)
		IPaddr[i] = addr[i];
	IPaddr[i] = '\0';

	portno = atoi(port);
	sockfd = socket(AF_INET,SOCK_STREAM,0);

	//create client socket
	//AF_INET: ARPANET FAMILY INTERNET- SOCKET FAMILY
	//SOCK_STREAM: TCP STREAMING SOCKETS -SOCKET TYPE
	//0 - Protocol
  
	if (sockfd < 0)
		printf("Error opening socket");

	//printf("\nClient online!\n");

	// GET THE SERVER			
	server = gethostbyname(IPaddr);			

	if(server == NULL)
	{
		fprintf(stderr,"Error, no such host\n");
		exit(1);
	}

	//printf("\nSERVER Online!\n");
	
	bzero((struct sockaddr_in *)&serv_addr,sizeof(serv_addr));	//Fills zero in the server IPaddr

	//create server address structure to connect to server
	serv_addr.sin_family = AF_INET;
	bcopy((int *) server->h_addr,(int *) &serv_addr.sin_addr.s_addr,server->h_length);
	serv_addr.sin_port = htons(portno);		//Set the server port number. htons is host to network byte order for short

	if(connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr)) < 0)
	{
		return CONNECTION_ERROR;
		printf("\nCONNECT ERROR: Error connecting to the socket\n");
	}

	//Write data to the socket
	FILE *fp = fopen(outFilename, "r");	// OPEN THE FILE IN A READ MODE
	if (fp == NULL)
	{
		printf("Error reading file");
		exit (0);
	}
	else
	{
		char buf[MAX_BUF_SIZE];
	
		// READ FILE CONTENTS INTO THE BUFFER
		
		printf("Transmitting file to %s", addr);

		while (fgets(buf, MAX_BUF_SIZE, fp) != NULL)
		//while ((c=fgetc(fp)) != EOF)
		{
			n = write(sockfd, buf, MAX_BUF_SIZE);
			totalBytes += n;
		}
			
		if (feof)
			n = write(sockfd, (void *)EOF, 1);			
			
		fclose(fp);
	}

	sleep(1);

	return 0;

}



// READ PLAINTEXT FROM FILE
void ReadPlaintext()
{
	// READ THE INPUT FILE TO BE ENCRYPTED IN A BUFFER
	plaintext = NULL;
	FILE *fp = fopen(inFilename, "r");	// OPEN THE FILE IN A READ MODE
	if (fp != NULL)
	{
		// GET THE FILE SIZE
		if (fseek(fp, 0, SEEK_END) == 0)
		{
			long fileSize = ftell(fp);
			
			if (fileSize == -1)
				printf("FILE READ: Error while computing fileSize\n");

			// ALLOCATE A BUFFER TO DUMP THE FILE CONTENTS
			plaintext = (char *)malloc(sizeof(char) *(fileSize+1));
			
			// GO BACK TO THE BEGINNING OF THE FILE TO START READING
			if (fseek(fp, 0, SEEK_SET) != 0)
				printf("FILE READ: Error while seeking to the beginning of the file\n");
	
			char buf[MAX_BUF_SIZE];
			while (fgets(buf, MAX_BUF_SIZE, fp) != NULL) 
	        		strcat(plaintext, buf);

        	}

		fclose(fp);		// CLOSE THE FILE
	}
	else
	{
		printf("File %s NOT found\n", inFilename);
		exit(0);
	}
}



// DERIVE THE KEY BY USING PBKDF2
void GetKeyByPBKDF2()
{
	int err = -1;
	hashLen = gcry_md_get_algo_dlen(GCRY_MD_SHA512);	//GET HASH LENGTH FOR SHA-512
	unsigned char hashResult[hashLen];
	const char* SALT = "NaCl";
	
	// DERIVE THE KEY BASED ON THE PASSWORD ENTERED: err = ERROR_STATUS_CODE
	err = gcry_kdf_derive (pwd, strlen(pwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, SALT, strlen(SALT), NO_OF_ITER, hashLen, hashResult);
	
	int i;
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



// AES ENCRYPTION
void AESEncrypt()
{
	int plainLen = strlen(plaintext);
	const int AES_KEY_LEN = 128;	// 128 BITS

	// PREPARE THE BUFFER TO HOLD ENCRYPTED CIPHERTEXT
	const int cipherLen = ((strlen(plaintext) + AES_BLOCK_SIZE)/AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	ciphertext = (unsigned char *) malloc(sizeof(unsigned char) *cipherLen);
	memset(ciphertext, 0, sizeof(ciphertext));	// INITIALIZE WITH ZEROS (0)

	// PREPARE THE INITIALIZATION VECTOR
	unsigned char *IV_value = (unsigned char *) malloc(sizeof(unsigned char) *AES_BLOCK_SIZE);
	memset(IV_value, toascii(5844), AES_BLOCK_SIZE);

	// PREPARE THE AES KEY
	AES_KEY aesKey;
	AES_set_encrypt_key(key, keyLen, &aesKey);

	// AES-128 CBC ENCRYPT
	AES_cbc_encrypt(plaintext, ciphertext, plainLen, &aesKey, IV_value, AES_ENCRYPT);
}


// AUTHENTICATE USING SHA-512 WITH HMAC ENABLED
void HashSHA_HMAC()
{
	// SHA-512 WITH HMAC FOR AUTHENTICATION
	digest = NULL;					// TO STORE THE HASH DIGEST

	// COPY THE ENCRYPTED CIPHERTEXT IN A TEMPORARY BUFFER SO THAT SHA-512 CAN ACT ON IT TO PROVIDE A NEW HASH
	// THIS HASH WILL BE THEN APPENDED TO THE ENCRYPTED CIPHERTEXT TO FORM THE FINAL CIPHERTEXT
	outBuf = (char *) malloc(sizeof(char) * ((hashLen*2) + 1));
	outBuf = ciphertext;		
	
	gcry_md_hd_t gHandle;	// HANDLE

	int err = 0;
	
	// OPEN THE HANDLE
	err = gcry_md_open(&gHandle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	if (err)
		printf("SHA-512 with HMAC: ERROR in opening handle");
	
	// SET THE HMAC FLAG
	err = 0;	
	err = gcry_md_setkey (gHandle, key, strlen(key));
	
	// CALL SHA-512
	gcry_md_write(gHandle, outBuf, strlen(outBuf));

	digest = gcry_md_read(gHandle, 0);
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

	/* gatorcrypt <input file> [-d < IP-addr:port >][-l]  */

	// argc should be atleast 3 for correct execution	
	if ( argc < 3 ) InvalidArgs();

	if (argc == 3)
		if (strcmp(argv[2],"-d") || strcmp(argv[2],"-l"))
			InvalidArgs();
		
	if ((!strcmp(argv[2],"-d")) && argv[3] == NULL)
		InvalidArgs();

	inFilename = argv[1];
	outFilename = (char *) malloc(sizeof(char)*(strlen(inFilename)+2));
	strcpy(outFilename, inFilename);
	strcat(outFilename, ".uf");

	// CHECK IF THE OUTPUT FILE ALREADY EXISTS: RETURN WITH AN ERR CODE OF 33
	struct stat sb;   
	if (!stat (outFilename, &sb))
	{
		printf("The output file %s already exists\n", outFilename);
		exit(33);
	}

	printf("Please enter a password: ");
	fgets(pwd, sizeof(pwd), stdin);

	// DERIVE THE KEY FROM THE PASSWORD ENTERED USING PBKDF2
	GetKeyByPBKDF2();

	//free(hashResult);

	// READ PLAINTEXT FROM FILE
	ReadPlaintext();	

	// ENCYPT THE FILE USING AES
	AESEncrypt();
	
	//free(IV_value);
	//free(plaintext);
	//free(ciphertext);
	
	// AUTHENTICATE USING SHA-512 WITH HMAC ENABLED
	HashSHA_HMAC();
	
	//free(outBuf);	
	//free(digest);

	// APPEND THIS SHA512-HMAC HASH DIGEST TO THE ORIGINAL ENCRYPTED CIPHERTEXT
	strcat(ciphertext, "#");
	strcat(ciphertext, digest);

	printf("\n");

	// FREE THE BUFFERS
	//free(digest);
	//free(outBuf);
	//free(digest);
	//free(IV_value);
	//free(ciphertext);
	//free(plaintext);
	//free(hashResult);

	// DUMP THE ENCRYPTED CONTENTS TO A FILE WITH SAME NAME WITH A ".UF" EXTENSION	
	FILE *fh = fopen(outFilename, "w+");
	if (fh !=NULL)
	{
		fwrite(ciphertext, sizeof(char), strlen(ciphertext), fh);
		fclose(fh);
		printf("Successfully encrypted %s to %s (%zd bytes written)\n", inFilename, outFilename, strlen(ciphertext));
	}
	else
		printf("Error opening file %s for writing\n", outFilename);

	//free(ciphertext);

	//printf("Ciphertext sent \n %s", ciphertext);

	// SEND ENCRYPTED FILE
	int err = -1;
	if (!(strcmp(argv[2], "-d")))
		err = SendEncFile(argv[3]);	

	if (!err)  printf("\nSuccessfully received\n");

	return 0;
}
