#include <pcap.h>
#include <malloc.h>
#include "interfacer.h"
#include "interface_analyser.h"
#include "packet_sniffer.h"
#include "packet_analyser.h"


/**
 *Acts as a controller the packet capture module. This dictates the sequence of steps
 *to be followed by this module.
 */
int main(int argc, char **argv){

  /* Get the list of interfaces available on the user's machine*/
  struct ifconf *ifc = malloc(sizeof(struct ifconf*));
  get_interfaces_list(ifc);

  /* Analyse the available interfaces and return the best interface to run sniffer on*/
  char *interface_name = malloc(sizeof(char *));
  interface_name = get_interface_to_sniff(ifc);
  printf("\nInterface to sniff : %s\n", interface_name);

  /*Start sniffing packets on this interface and populate the packets*/
  start_sniffing(interface_name,got_packet);


  /* Store the captures packets for later analysis*/

}
