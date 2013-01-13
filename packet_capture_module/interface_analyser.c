#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include "global_functions.h"
/* Include sockio.h if needed */
#ifndef SIOCGIFCONF
#include <sys/sockio.h>
#endif
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <malloc.h>


char *get_interface_to_sniff(struct ifconf *ifc){

  int i = 0;
  char* interface_name;
  int sck = get_pf_inet_socket();
  
  struct ifreq *interface_list = ifc->ifc_req;
  
  int nInterfaces = ifc->ifc_len/sizeof(struct ifreq);
  printf("\nNumber of interfaces : %d \n", nInterfaces);
  
  /* Loop throught each interface and apply ruleset */
  for(i = 0; i < nInterfaces; i++){
    struct ifreq current_interface = interface_list[i];
    printf("Interface name : %s\t\t",current_interface.ifr_name);
    if(ioctl(sck, SIOCGIFHWADDR, &current_interface) < 0) {
      fatal_perror("ioctl(SIOCGIFHWADDR)");
    }
    int interface_type = current_interface.ifr_hwaddr.sa_family;
    printf("Interface type : ");

    switch(interface_type){
    case ARPHRD_ETHER: //This is what we need. All other interfaces will be ignored. We need to decide what to do if there are more of ethernet devices
      printf("Ethernet/Wlan Interface");
      interface_name = malloc(strlen(current_interface.ifr_name)+1);
      strncpy(interface_name, current_interface.ifr_name, strlen(current_interface.ifr_name));
      interface_name[strlen(current_interface.ifr_name)] = '\0';
      break;
    case ARPHRD_LOOPBACK:
      printf("Loopback Interface");
      break;
    default:
      printf("Unsupported Interface");
    }
    printf("\n");
  }
  if(interface_name == 0){
    return "No interface Matched";
  }
  else{
    return interface_name;
  }
}
