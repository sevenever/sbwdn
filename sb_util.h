#ifndef _SB_UTIL_H_
#define _SB_UTIL_H_

#include <sys/socket.h>

#define SB_NOT_USED(x) (void)(x)

/* compare two address and port. support ipv4 and ipv6
 * return 0 if families are equal, addresses are equal and ports are equal
 * return -1 otherwise
 */
int sb_util_sockaddr_cmp(struct sockaddr * addr1, struct sockaddr * addr2);


/* return a human readable representation of addr such as 192.168.1.1
 * the return porinter point to a static memory area. This funcion is not reentrant.
 * if family is AF_INET, addr should be struct in_addr *
 * if family is AF_INET6, addr should be struct in6_addr *
 */
const char * sb_util_human_addr(int family, void * addr);


/* return a human readable representation of addr such as 192.168.1.1:812
 * the return porinter point to a static memory area. This funcion is not reentrant.
 */
const char * sb_util_human_endpoint(struct sockaddr * addr);


/* like strerrno, but include errno */
const char * sb_util_strerror(int eno);

/* generate random bytes into a memory area
 * return -1 if errno
 * return 0 if succeed
 */
int sb_util_random(char * data, unsigned int len);

#endif
