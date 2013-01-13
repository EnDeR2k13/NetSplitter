#include <stdlib.h>
#include <sys/ioctl.h>
/* Include sockio.h if needed */
#ifndef SIOCGIFCONF
#include <sys/sockio.h>
#endif
#include <netinet/in.h>


void fatal_perror(const char *X);
int get_pf_inet_socket();
