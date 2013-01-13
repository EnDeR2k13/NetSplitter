#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

/**
 *Initiates the sniffing given the name of the device/interface to sniff on
 */
void 
start_sniffing(char* dev, void *function_pointer_to_packet_received_callback);
