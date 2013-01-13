
/**
 *Given the ifconf struct pointer, it analyses each ifreq struct (each interface)
 *and returns the name of the interface which needs to be sniffed on. This will be decided
 *based on some rule sets.
 * 
 *The rule sets are yet to be fully researched
 */
char *
get_interface_to_sniff(struct ifconf *ifc);

