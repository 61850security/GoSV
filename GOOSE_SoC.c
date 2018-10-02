#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>

// Broadcast mac address
#define DEST_MAC0    0xFF
#define DEST_MAC1    0xFF
#define DEST_MAC2    0xFF
#define DEST_MAC3    0xFF
#define DEST_MAC4    0xFF
#define DEST_MAC5    0xFF

/* Enter your network adapter MAC address in hexadecimal values  
#define DEST_MAC0    0xXX
#define DEST_MAC1    0xXX
#define DEST_MAC2    0xXX
#define DEST_MAC3    0xXX
#define DEST_MAC4    0xXX
#define DEST_MAC5    0xXX
*/

#define DEFAULT_IF  "Enter the name of your network adapter"
#define BUF_SIZ     2048


 /* GOOSE payload fields */

char APPID_1 =0x00;         		/* Application identifier */           
char APPID_2 =0x01; 
char length_1 =0x00;        		/* length  */        
char length_2=0x91;
char resrv1_1=0x00; 	   		/* reservation1 - security related fields  */	     
char resrv1_2=0x00;                     
char resrv2_1=0x00;         		/* reservation2 - security related fields */		     
char resrv2_2=0x00;                  
char goosePDU_tag1=0x61;    		/* goosePDU tag  */
char goosePDU_tag2=0x81;    
char goosePDU_length=0x86;  		/* goosePDU length  */
char gocbRef_tag=0x80;      		/* gocbRef tag  */
char gocbRef_length=0x1A;   		/* gocbRef length  */
char gocbRef_value1=0x47;   		/* gocbRef value  */
char gocbRef_value2=0x45;
char gocbRef_value3=0x44;
char gocbRef_value4=0x65;
char gocbRef_value5=0x76;
char gocbRef_value6=0x69;
char gocbRef_value7=0x63;
char gocbRef_value8=0x65;
char gocbRef_value9=0x46;
char gocbRef_value10=0x36;
char gocbRef_value11=0x35;
char gocbRef_value12=0x30;
char gocbRef_value13=0x2F;
char gocbRef_value14=0x4C;
char gocbRef_value15=0x4C;
char gocbRef_value16=0x4E;
char gocbRef_value17=0x30;
char gocbRef_value18=0x24;
char gocbRef_value19=0x47;
char gocbRef_value20=0x4F;
char gocbRef_value21=0x24;
char gocbRef_value22=0x67;
char gocbRef_value23=0x63;
char gocbRef_value24=0x62;
char gocbRef_value25=0x30;
char gocbRef_value26=0x31;
char timeAllowedtoLive_tag=0x81;	/* timeAllowedtoLive tag  */
char timeAllowedtoLive_length=0x03;     /* timeAllowedtoLive length  */
char timeAllowedtoLive_value1=0x00;     /* timeAllowedtoLive value  */
char timeAllowedtoLive_value2=0x9C;
char timeAllowedtoLive_value3=0x40;
char dataset_tag=0x82;                  /* data set tag  */
char dataset_length=0x18;               /* data set length  */
char dataset_value1=0x47;		/* data set value  */
char dataset_value2=0x45;
char dataset_value3=0x44;
char dataset_value4=0x65;
char dataset_value5=0x76;
char dataset_value6=0x69;
char dataset_value7=0x63;
char dataset_value8=0x65;
char dataset_value9=0x46;
char dataset_value10=0x36;
char dataset_value11=0x35;
char dataset_value12=0x30;
char dataset_value13=0x2F;
char dataset_value14=0x4C;
char dataset_value15=0x4C;
char dataset_value16=0x4E;
char dataset_value17=0x30;
char dataset_value18=0x24;
char dataset_value19=0x47;
char dataset_value20=0x4F;
char dataset_value21=0x4F;
char dataset_value22=0x53;
char dataset_value23=0x45;
char dataset_value24=0x31;
char goID_tag=0x83;			/* goose ID tag */
char goID_length=0x0B;			/* goose ID length */
char goID_value1=0x46;			/* goose ID value */
char goID_value2=0x36;
char goID_value3=0x35;
char goID_value4=0x30;
char goID_value5=0x5F;
char goID_value6=0x47;
char goID_value7=0x4F;
char goID_value8=0x4F;
char goID_value9=0x53;
char goID_value10=0x45;
char goID_value11=0x31;
char time_tag=0x84;			/* time tag */
char time_length=0x08;			/* time length */
char time_value1=0x38;			/* time value */
char time_value2=0x6E;
char time_value3=0xBB;
char time_value4=0xF3;
char time_value5=0x42;
char time_value6=0x17;
char time_value7=0x28;
char time_value8=0x0A;
char st_Num_tag=0x85;			/* st_Num tag */
char st_Num_length=0x01;		/* st_Num length */
char st_Num_value=0x01;			/* st_Num value */
char sq_Num_tag=0x86;			/* sq_Num tag */
char sq_Num_length=0x01;                /* sq_Num length */
char sq_Num_value=0x0A;			/* sq_Num value */
char test_tag=0x87;			/* test tag */
char test_length=0x01;                  /* test length */
char test_value=0x00;                   /* test value */
char confRev_tag=0x88;                  /* confRev tag */
char confRev_length=0x01;		/* confRev length */
char confRev_value=0x01;		/* confRev value */
char ndsCom_tag=0x89;			/* ndsCom tag */
char ndsCom_length=0x01;		/* ndsCom length */
char ndsCom_value=0x00;			/* ndsCom value */
char numDatSetEntries_tag=0x8A;		/* numDatSetEntries tag */
char numDatSetEntries_length=0x01;	/* numDatSetEntries length */
char numDatSetEntries_value=0x08;	/* numDatSetEntries value */
char alldata_tag=0xAB;			/* all_data tag */
char alldata_length=0x20;		/* alldata length */
char alldata_value1=0x83;		/* alldata value */
char alldata_value2=0x01;
char alldata_value3=0x00;
char alldata_value4=0x84;
char alldata_value6=0x03;
char alldata_value5=0x03;
char alldata_value7=0x00;
char alldata_value8=0x00;
char alldata_value9=0x83;
char alldata_value10=0x01;
char alldata_value11=0x00;
char alldata_value12=0x84;
char alldata_value13=0x03;
char alldata_value14=0x03;
char alldata_value15=0x00;
char alldata_value16=0x00;
char alldata_value17=0x83;
char alldata_value18=0x01;
char alldata_value19=0x00;
char alldata_value20=0x84;
char alldata_value21=0x03;
char alldata_value22=0x03;
char alldata_value23=0x00;
char alldata_value24=0x00;
char alldata_value25=0x83;
char alldata_value26=0x01;
char alldata_value27=0x00;
char alldata_value28=0x84;
char alldata_value29=0x03;
char alldata_value30=0x03;
char alldata_value31=0x00;
char alldata_value32=0x00;

int main(int argc, char *argv[])
{
    int sfd, buf_len=0,i=0;
    struct ifreq if_idx,if_mac;
    struct sockaddr_ll socket_address; /* The sockaddr_ll structure is a device-independent physical-layer address.*/
    char ifName[IFNAMSIZ];
    char sendbuf[BUF_SIZ];

    /* Get interface name */
    if (argc > 1)
        strcpy(ifName, argv[1]);
    else
        strcpy(ifName, DEFAULT_IF);

    /* Open RAW socket to send on */
    if ((sfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) 
        perror("socket");


    /* Initializing the ifreq structure to zero */
    memset(&if_idx, 0, sizeof(struct ifreq));

    /* copying the interface name into ifName string */  
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);

    /* Retrieve the interface number using ioctl SIOCGIFINDEX */
    if (ioctl(sfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");

    // Loop forever generating GOOSE packet with custom values
    while(1) 
    {


        /* Buffer of BUF_SIZ bytes we'll construct our frame in. First, clear it all to zero. */
        memset(sendbuf, 0, BUF_SIZ);

        /* Construct the Ethernet header */

        /* Destination address */
        sendbuf[buf_len++] = DEST_MAC0;
        sendbuf[buf_len++] = DEST_MAC1;
        sendbuf[buf_len++] = DEST_MAC2;
        sendbuf[buf_len++] = DEST_MAC3;
        sendbuf[buf_len++] = DEST_MAC4;
        sendbuf[buf_len++] = DEST_MAC5;

        /* Create the source */
        sendbuf[buf_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
        sendbuf[buf_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
        sendbuf[buf_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
        sendbuf[buf_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
        sendbuf[buf_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
        sendbuf[buf_len++] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
  
        /* VLAN values */
        sendbuf[buf_len++] = 0x81;
        sendbuf[buf_len++] = 0x00;
        sendbuf[buf_len++] = 0x80;
        sendbuf[buf_len++] = 0x00;  

        /* Ethertype field GOOSE protocol*/
        sendbuf[buf_len++] = 0x88;
        sendbuf[buf_len++] = 0xB8;

        /*  PDU fields */
        sendbuf[buf_len++] = APPID_1;                  
        sendbuf[buf_len++] = APPID_2; 
        sendbuf[buf_len++] = length_1;                 
        sendbuf[buf_len++] = length_2;
        sendbuf[buf_len++] = resrv1_1;
	sendbuf[buf_len++] = resrv1_2;                   
	sendbuf[buf_len++] = resrv2_1;
        sendbuf[buf_len++] = resrv2_2;                  
        sendbuf[buf_len++] = goosePDU_tag1;
        sendbuf[buf_len++] = goosePDU_tag2;
        sendbuf[buf_len++] = goosePDU_length;
        sendbuf[buf_len++] = gocbRef_tag;
        sendbuf[buf_len++] = gocbRef_length;
        sendbuf[buf_len++] = gocbRef_value1;
        sendbuf[buf_len++] = gocbRef_value2;
        sendbuf[buf_len++] = gocbRef_value3;
        sendbuf[buf_len++] = gocbRef_value4;
        sendbuf[buf_len++] = gocbRef_value5;
        sendbuf[buf_len++] = gocbRef_value6;
        sendbuf[buf_len++] = gocbRef_value7;
        sendbuf[buf_len++] = gocbRef_value8;
        sendbuf[buf_len++] = gocbRef_value9;
        sendbuf[buf_len++] = gocbRef_value10;
	sendbuf[buf_len++] = gocbRef_value11;
	sendbuf[buf_len++] = gocbRef_value12;
	sendbuf[buf_len++] = gocbRef_value13;
	sendbuf[buf_len++] = gocbRef_value14;
	sendbuf[buf_len++] = gocbRef_value15;
	sendbuf[buf_len++] = gocbRef_value16;
	sendbuf[buf_len++] = gocbRef_value17;
	sendbuf[buf_len++] = gocbRef_value18;
	sendbuf[buf_len++] = gocbRef_value19;
	sendbuf[buf_len++] = gocbRef_value20;
	sendbuf[buf_len++] = gocbRef_value21;
	sendbuf[buf_len++] = gocbRef_value22;
	sendbuf[buf_len++] = gocbRef_value23;
	sendbuf[buf_len++] = gocbRef_value24;
	sendbuf[buf_len++] = gocbRef_value25;
	sendbuf[buf_len++] = gocbRef_value26;
	sendbuf[buf_len++] = timeAllowedtoLive_tag;
	sendbuf[buf_len++] = timeAllowedtoLive_length;
	sendbuf[buf_len++] = timeAllowedtoLive_value1;
	sendbuf[buf_len++] = timeAllowedtoLive_value2;
	sendbuf[buf_len++] = timeAllowedtoLive_value3;
	sendbuf[buf_len++] = dataset_tag;
	sendbuf[buf_len++] = dataset_length;
	sendbuf[buf_len++] = dataset_value1;
	sendbuf[buf_len++] = dataset_value2;
	sendbuf[buf_len++] = dataset_value3;
	sendbuf[buf_len++] = dataset_value4;
	sendbuf[buf_len++] = dataset_value5;
	sendbuf[buf_len++] = dataset_value6;
	sendbuf[buf_len++] = dataset_value7;
	sendbuf[buf_len++] = dataset_value8;
	sendbuf[buf_len++] = dataset_value9;
	sendbuf[buf_len++] = dataset_value10;
	sendbuf[buf_len++] = dataset_value11;
	sendbuf[buf_len++] = dataset_value12;
	sendbuf[buf_len++] = dataset_value13;
	sendbuf[buf_len++] = dataset_value14;
	sendbuf[buf_len++] = dataset_value15;
	sendbuf[buf_len++] = dataset_value16;
	sendbuf[buf_len++] = dataset_value17;
	sendbuf[buf_len++] = dataset_value18;
	sendbuf[buf_len++] = dataset_value19;
	sendbuf[buf_len++] = dataset_value20;
	sendbuf[buf_len++] = dataset_value21;
	sendbuf[buf_len++] = dataset_value22;
	sendbuf[buf_len++] = dataset_value23;
	sendbuf[buf_len++] = dataset_value24;
	sendbuf[buf_len++] = goID_tag;
	sendbuf[buf_len++] = goID_length;
	sendbuf[buf_len++] = goID_value1;
	sendbuf[buf_len++] = goID_value2;
	sendbuf[buf_len++] = goID_value3;
	sendbuf[buf_len++] = goID_value4;
	sendbuf[buf_len++] = goID_value5;
	sendbuf[buf_len++] = goID_value6;
	sendbuf[buf_len++] = goID_value7;
	sendbuf[buf_len++] = goID_value8;
	sendbuf[buf_len++] = goID_value9;
	sendbuf[buf_len++] = goID_value10;
	sendbuf[buf_len++] = goID_value11;
	sendbuf[buf_len++] = time_tag;
	sendbuf[buf_len++] = time_length;
	sendbuf[buf_len++] = time_value1;
	sendbuf[buf_len++] = time_value2;
	sendbuf[buf_len++] = time_value3;
	sendbuf[buf_len++] = time_value4;
	sendbuf[buf_len++] = time_value5;
	sendbuf[buf_len++] = time_value6;
	sendbuf[buf_len++] = time_value7;
	sendbuf[buf_len++] = time_value8;
	sendbuf[buf_len++] = st_Num_tag;
	sendbuf[buf_len++] = st_Num_length;
	sendbuf[buf_len++] = st_Num_value;
	sendbuf[buf_len++] = sq_Num_tag;
	sendbuf[buf_len++] = sq_Num_length;
	sendbuf[buf_len++] = sq_Num_value;
	sendbuf[buf_len++] = test_tag;
	sendbuf[buf_len++] = test_length;
	sendbuf[buf_len++] = test_value;
	sendbuf[buf_len++] = confRev_tag;
	sendbuf[buf_len++] = confRev_length;
	sendbuf[buf_len++] = confRev_value;
	sendbuf[buf_len++] = ndsCom_tag;
	sendbuf[buf_len++] = ndsCom_length;
	sendbuf[buf_len++] = ndsCom_value;
	sendbuf[buf_len++] = numDatSetEntries_tag;
	sendbuf[buf_len++] = numDatSetEntries_length;
	sendbuf[buf_len++] = numDatSetEntries_value;
	sendbuf[buf_len++] = alldata_tag;
	sendbuf[buf_len++] = alldata_length;
	sendbuf[buf_len++] = alldata_value1;
	sendbuf[buf_len++] = alldata_value2;
	sendbuf[buf_len++] = alldata_value3;
	sendbuf[buf_len++] = alldata_value4;
	sendbuf[buf_len++] = alldata_value6;
	sendbuf[buf_len++] = alldata_value5;
	sendbuf[buf_len++] = alldata_value7;
	sendbuf[buf_len++] = alldata_value8;
	sendbuf[buf_len++] = alldata_value9;
	sendbuf[buf_len++] = alldata_value10;
	sendbuf[buf_len++] = alldata_value11;
	sendbuf[buf_len++] = alldata_value12;
	sendbuf[buf_len++] = alldata_value13;
	sendbuf[buf_len++] = alldata_value14;
	sendbuf[buf_len++] = alldata_value15;
	sendbuf[buf_len++] = alldata_value16;
	sendbuf[buf_len++] = alldata_value17;
	sendbuf[buf_len++] = alldata_value18;
	sendbuf[buf_len++] = alldata_value19;
	sendbuf[buf_len++] = alldata_value20;
	sendbuf[buf_len++] = alldata_value21;
	sendbuf[buf_len++] = alldata_value22;
	sendbuf[buf_len++] = alldata_value23;
	sendbuf[buf_len++] = alldata_value24;
	sendbuf[buf_len++] = alldata_value25;
	sendbuf[buf_len++] = alldata_value26;
	sendbuf[buf_len++] = alldata_value27;
	sendbuf[buf_len++] = alldata_value28;
	sendbuf[buf_len++] = alldata_value29;
	sendbuf[buf_len++] = alldata_value30;
	sendbuf[buf_len++] = alldata_value31;
	sendbuf[buf_len++] = alldata_value32;


        /* Index of the network device */
        socket_address.sll_ifindex = if_idx.ifr_ifindex;  

       /* Length of Ethernet address */
        socket_address.sll_halen = ETH_ALEN;
 
        /* Setting Destination MAC */
        socket_address.sll_addr[0] = DEST_MAC0;
        socket_address.sll_addr[1] = DEST_MAC1;
        socket_address.sll_addr[2] = DEST_MAC2;
        socket_address.sll_addr[3] = DEST_MAC3;
        socket_address.sll_addr[4] = DEST_MAC4;
        socket_address.sll_addr[5] = DEST_MAC5;

        /* Send packet */
        if (sendto(sfd, sendbuf, buf_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
            printf("Send failed\n");
        else {
            printf("Sent :");
            for (i=0; i < buf_len; i++)
                printf("%02x:", sendbuf[i]);
            printf("\n");
        }
        /* Send packet for every 1 second */
        usleep(1000000);
    }
    return 0;
}

