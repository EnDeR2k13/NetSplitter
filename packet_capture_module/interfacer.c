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

/* On platforms that have variable length 
   ifreq use the old fixed length interface instead */
#ifdef OSIOCGIFCONF
#undef SIOCGIFCONF
#define SIOCGIFCONF OSIOCGIFCONF
#undef SIOCGIFADDR
#define SIOCGIFADDR OSIOCGIFADDR
#undef SIOCGIFBRDADDR
#define SIOCGIFBRDADDR OSIOCGIFBRDADDR
#endif

void get_interfaces_list(struct ifconf *ifc){

  char            buf[8192] = {0};
  int sck = get_pf_inet_socket();

  /* Query available interfaces. */
  ifc->ifc_len = sizeof(buf);
  ifc->ifc_buf = buf;
  if(ioctl(sck, SIOCGIFCONF, ifc) < 0) {
    fatal_perror("ioctl(SIOCGIFCONF)");
  }
}
