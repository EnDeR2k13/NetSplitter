#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>


/**
*This expression needs to be researched to accommodate all incoming packets which takes network bandwidth. 
*For example : p2p, http, ftp, etc.,
*But packets like arp need to be ignored since they don't use internet bandwidth
*/
#define FILTER_EXPRESSION "ip && port 80"

/* pcap buffer size */
#define BUFFER_SIZE 524288


void start_sniffing(char* dev, void * packet_received_callback){


  printf("\n\n*****************************************Starting Sniffing*****************************************\n\n");

  char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
  pcap_t *handle;				/* packet capture handle */

  char filter_exp[] = FILTER_EXPRESSION;		/* filter expression [3] */
  struct bpf_program fp;			/* compiled filter program (expression) */
  bpf_u_int32 mask;			/* subnet mask */
  bpf_u_int32 net;			/* ip */
  int num_packets = 0;			/* number of packets to capture. 0 means infinity */


  /* get network number and mask associated with capture device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
	    dev, errbuf);
    net = 0;
    mask = 0;
  }

  /* print capture info */
  printf("Sniffing on Interface: %s\n", dev);
  printf("Filter expression: %s\n", filter_exp);

  /* open capture device */
  handle = pcap_create(dev, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  /*Set the buffer size to be 512Kb*/
  pcap_set_buffer_size(handle, BUFFER_SIZE);
  
  /*Activate the handler*/
  if(pcap_activate(handle) != 0){
    fprintf(stderr, "Couldn't activate handler %s: %s\n",
	    filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
	    filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
	    filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* now we can set our callback function */
  pcap_loop(handle, num_packets, packet_received_callback, NULL);

  /* cleanup */
  pcap_freecode(&fp);
  pcap_close(handle);

  printf("\nCapture complete.\n");
}
