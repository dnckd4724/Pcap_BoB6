#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev="eth0";			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;   /* The actual packet */
    const u_char *pkt_data;
    struct ether_header *ph;
    struct iphdr * ip;
    struct tcphdr * tcp;
    char * Data;
    char buf[40];
    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    while(1){
        if(packet = pcap_next_ex(handle, &header, &pkt_data)==1){
            ph = pkt_data;
            ip = (struct iphdr *)(pkt_data+14);
            tcp = (struct tcphdr *)(pkt_data+(14+(*(pkt_data+14)&0x0f)*4));
            Data = (pkt_data+(14+ntohs(ip->tot_len)));
            if(ntohs(ph->ether_type)==0x0800 && ip->protocol==6){
                /* Print its length */
                printf("Destination Mac  :");
                for(int i=0; i<6; i++){
                    printf("%02x", ph->ether_dhost[i]);
                    if(i<5)printf(":");
                }
                printf("\nSource Mac       :");
                for(int i=0; i<6; i++){
                    printf("%02x", ph->ether_shost[i]);
                    if(i<5)printf(":");
                }
                printf("\nType             :");
                printf("%04x", ntohs(ph->ether_type));
                inet_ntop(AF_INET, &ip->saddr, buf, sizeof(buf));
                printf("\nSource ip        :");
                printf("%s", buf);

                inet_ntop(AF_INET, &ip->daddr, buf, sizeof(buf));
                printf("\nDestination ip   :");
                printf("%s", buf);
                printf("\nProtocal         :%d", ip->protocol);

                printf("\nDestination Port :%d", ntohs(tcp->th_dport));
                printf("\nSource Port      :%d", ntohs(tcp->th_sport));

                printf("\nData : \n");
                for(int i=1; i<50; i++){
                    printf("%02x ", *(Data+(i-1)));
                    if(i!=0){if(i%8==0)printf("\n");}
                }
                printf("\n");
                /* And close the session */
            }
        }else if(packet = pcap_next_ex(handle, &header, &pkt_data)!=1)
            continue;
    }
    pcap_close(handle);
    return(0);
}

