#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void PrintData (const u_char * , int);
int elaborate_packet(const u_char * , int);

struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

int main(int argc, char **argv)
{

    if (argc < 2 || (strcmp(argv[1], "nsm") != 0 && strcmp(argv[1], "namespaces") != 0)) {
        printf("Usage: nsm or namespaces\n");
        return 0;
    }
    pcap_if_t *alldevsp , *device;
    pcap_t *handle; //Handle of the device that shall be sniffed

    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;

    if (strcmp(argv[1], "nsm") == 0) {
        //First get the list of available devices
        printf("Finding available devices ... ");
        if( pcap_findalldevs( &alldevsp , errbuf) )
        {
            printf("Error finding devices : %s" , errbuf);
            exit(1);
        }
        printf("Done");

        //Print the available devices
        printf("\nAvailable Devices are :\n");
        for(device = alldevsp ; device != NULL ; device = device->next)
        {
            printf("%d. %s - %s\n" , count , device->name , device->description);
            if(device->name != NULL)
            {
                if (strstr(device->name, "nsm"))
                    devname = device->name;
                strcpy(devs[count] , device->name);
            }
            count++;
        }

        //Open the device for sniffing
        printf("Opening NSM device with clinet %s for sniffing ... " , devname);
        handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
            exit(1);
        }
        printf("Done\n");

        //Put the device in sniff loop
        pcap_loop(handle , -1 , process_packet , NULL);
    } else {
        //First get the list of available devices
        printf("Finding available devices ... ");
        if( pcap_findalldevs( &alldevsp , errbuf) )
        {
            printf("Error finding devices : %s" , errbuf);
            exit(1);
        }
        printf("Done");

        //Print the available devices
        printf("\nAvailable Devices are :\n");
        for(device = alldevsp ; device != NULL ; device = device->next)
        {
            printf("%d. %s - %s\n" , count , device->name , device->description);
            if(device->name != NULL)
            {
                strcpy(devs[count] , device->name);
            }
            count++;
        }

        //Ask user which device to sniff
        printf("Enter the number of the device you want to sniff : ");
        scanf("%d" , &n);
        devname = devs[n];

        //Open the device for sniffing
        printf("Opening device %s for sniffing ... " , devname);
        handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
            exit(1);
        }
        printf("Done\n");

        //Put the device in sniff loop
        pcap_loop(handle , -1 , process_packet , NULL);
    }

    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            elaborate_packet( buffer , size);
            break;

        case 2:  //IGMP Protocol
            ++igmp;
            break;

        case 6:  //TCP Protocol
            ++tcp;
            elaborate_packet(buffer, size);
            break;

//        case 17: //UDP Protocol
//            ++udp;
//            print_udp_packet(buffer , size);
//            break;

        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}


int elaborate_packet(const u_char * Buffer, int Size)
{

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    char *source_addr = inet_ntoa(source.sin_addr);


    if (!strstr(source_addr, "172.16") && !strstr(source_addr, "10.100")) {
        printf("Source ip %s not allowed\n", source_addr);
        return 1;
    }

}
