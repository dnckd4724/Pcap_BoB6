#include <pcap.h>
#include <stdio.h>

    int main(int argc, char *argv[])
    {
       pcap_t *handle;              /* Session handle */
       char *dev="eth0";			/* The device to sniff on */
       char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
       struct bpf_program fp;		/* The compiled filter */
       char filter_exp[] = "port 80";	/* The filter expression */
       bpf_u_int32 mask;		/* Our netmask */
       bpf_u_int32 net;		/* Our IP */
       struct pcap_pkthdr *header;	/* The header that pcap gives us */
       const u_char *pkt_data;
       const u_char *packet;
       const u_char *packet_data;/* The actual packet */
       int i, k=1;
       u_short res_1[]={0};
       u_short res[]={0};


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
       handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
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
      packet_data=pcap_next_ex(handle, &header, &pkt_data);
      packet = pkt_data;

      if((*(pkt_data+23)==6) && (*(pkt_data+12)==8) && (*(pkt_data+13)==0)){
      printf("\nDestination MAC: ");
      for(int i = 0; i < 6; i++){
          printf("%02x:",  *(pkt_data+i));
        }
      printf("\nSource MAC: ");
        for(int i = 6; i < 12; i++){
          printf("%02x:",  *(pkt_data+i));
        }
      printf("\nType: ");
        for(int i = 12; i < 14; i++){
           printf("%02x",  *(pkt_data+i));
        }
      printf("\nProtocol: ");
         for(int i = 23; i < 24; i++){
            printf("%02x",  *(pkt_data+i));
        }
      printf("\nSourec ip: ");
         for(int i = 26; i < 30; i++){
            printf("%02d.",  *(pkt_data+i));
         }
       printf("\nDestination ip: ");
         for(int i = 30; i < 34; i++){
            printf("%02d.",  *(pkt_data+i));
         }

       res[0] = (u_short)*(pkt_data+(14+(((*(pkt_data+14))&0x0f)*4)));
       res[0] = (u_short)res[0] << 8;
       res[1] = (u_short)*(pkt_data+(15+(((*(pkt_data+14))&0x0f)*4)));
       res[0] = res[0] | res[1];
       printf("\nSourec Port: %d", res[0]);

       res_1[0] = (u_short)*(pkt_data+(16+(((*(pkt_data+14))&0x0f)*4)));
       res_1[0] = (u_short)res_1[0] << 8;
       res_1[1] = (u_short)*(pkt_data+(17+(((*(pkt_data+14))&0x0f)*4)));
       res_1[0] = res_1[0] | res_1[1];
       printf("\nDestination Port: %d", res_1[0]);

       printf("\nData : \n");
        i=14+(((*(pkt_data+14))&0x0f)*4)+(((*(pkt_data+45))&0xf0)/4);

        for(int j=i; j<i+100 ;j++){

            printf("%02x", *(packet+j));
            if(k%8==0)printf("\n");
            k++;
        }

            }else return(2);
        }


       /* And close the session */
        pcap_close(handle);
       return(0);
   }

