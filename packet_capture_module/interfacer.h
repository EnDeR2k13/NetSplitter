#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>

/**
 *Given ifconf structure, it populates it with array of ifreq structures (contains information about each interface)
 */
void 
get_interfaces_list(struct ifconf *ifc);
