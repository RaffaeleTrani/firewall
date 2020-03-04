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
int elaborate_packet(const u_char *);

struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;

pcap_t *handle_in, *handle_out; //Handle of the device that shall be sniffed

int main(int argc, char **argv)
{

    if (argc < 2 || (strcmp(argv[1], "nsm") != 0 && strcmp(argv[1], "namespaces") != 0)) {
        printf("Usage: nsm or namespaces\n");
        return 0;
    }
    pcap_if_t *alldevsp , *device;

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
        printf("Opening NSM device %s for sniffing ... " , devname);
        handle_in = pcap_open_live("veth1" , 65536 , 1 , 0 , errbuf);
        handle_out = pcap_open_live("veth2" , 65536 , 1 , 0 , errbuf);

        if (handle_in == NULL)
        {
            fprintf(stderr, "Couldn't open device veth1 : %s\n", errbuf);
            exit(1);
        }
        if (handle_out == NULL)
        {
            fprintf(stderr, "Couldn't open device veth2 : %s\n", errbuf);
            exit(1);
        }
        printf("Done\n");

        //Put the device in sniff loop
        pcap_loop(handle_in, -1, process_packet, NULL);
        pcap_loop(handle_out, -1, process_packet, NULL);
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

        //Open the device for sniffing
        printf("Opening NSM device veth1 for sniffing ... ");
        handle_in = pcap_open_live("veth1" , 65536 , 1 , 0 , errbuf);
        printf("Opening NSM device veth2 for sniffing ... ");
        handle_out = pcap_open_live("veth2" , 65536 , 1 , 0 , errbuf);

        if (handle_in == NULL)
        {
            fprintf(stderr, "Couldn't open device veth1 : %s\n", errbuf);
            exit(1);
        }
        if (handle_out == NULL)
        {
            fprintf(stderr, "Couldn't open device veth2 : %s\n", errbuf);
            exit(1);
        }
        printf("Done\n");


        //Put the device in sniff loop
        pcap_loop(handle_in , -1 , process_packet , NULL);
        pcap_loop(handle_out, -1, process_packet, NULL);
    }

    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
    int res = elaborate_packet(buffer);
    if (res == 1) {
        return;
    }
    if (pcap_sendpacket(handle_out, buffer, strlen(buffer)) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle_out));
        return;
    }
    printf("Packet sent to dest interface.\n");
}


int elaborate_packet(const u_char * Buffer)
{

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    char *source_addr = inet_ntoa(source.sin_addr);

    int a,b,c,d;

    sscanf(source_addr,"%d.%d.%d.%d", &a, &b, &c, &d);

    if ((a != 10 && a != 172) || (b != 100 && b != 16)) {
        printf("Source ip %s not allowed\n", source_addr);
        return 1;
    }
}
