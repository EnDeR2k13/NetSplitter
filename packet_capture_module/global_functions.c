#include <stdlib.h>
#include <sys/ioctl.h>
/* Include sockio.h if needed */
#ifndef SIOCGIFCONF
#include <sys/sockio.h>
#endif
#include <netinet/in.h>



void fatal_perror(const char *X)
{ 
  perror(X);
  exit(1); 
}

int get_pf_inet_socket(){
  int PF_INET_SOCKET_GLOBAL = socket(PF_INET, SOCK_DGRAM, 0);
  if(PF_INET_SOCKET_GLOBAL < 0){
    fatal_perror("Socket Connection could not be established");
    return -1; 
  }else{
    return PF_INET_SOCKET_GLOBAL;
  }
}
