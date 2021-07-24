## in_addr

**IP Address**

    typedef struct in_addr {
        union {
            struct {
                UCHAR s_b1;
                UCHAR s_b2;
                UCHAR s_b3;
                UCHAR s_b4;
            } S_un_b;
            struct {
                USHORT s_w1;
                USHORT s_w2;
            } S_un_w;
            ULONG S_addr;
        } S_un;
    } IN_ADDR, *PIN_ADDR, *LPIN_ADDR;


## socket_addr_in
**Socket address IP Address with port**

    struct sockaddr_in {
        short int            sin_family;
        unsigned short int   sin_port;
        struct in_addr       sin_addr;
        unsigned char        sin_zero[8];
    };

## struct ip


**Definitions for internet protocol version 4.Per RFC 791, September 1981. Structure of an internet header, naked of options.**

    struct ip
    {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned int ip_hl:4;                /* header length */
        unsigned int ip_v:4;                /* version */
    #endif
    #if __BYTE_ORDER == __BIG_ENDIAN
        unsigned int ip_v:4;                /* version */
        unsigned int ip_hl:4;                /* header length */
    #endif
        u_int8_t ip_tos;                        /* type of service */
        u_short ip_len;                        /* total length */
        u_short ip_id;                        /* identification */
        u_short ip_off;                        /* fragment offset field */
    #define        IP_RF 0x8000                        /* reserved fragment flag */
    #define        IP_DF 0x4000                        /* dont fragment flag */
    #define        IP_MF 0x2000                        /* more fragments flag */
    #define        IP_OFFMASK 0x1fff                /* mask for fragmenting bits */
        u_int8_t ip_ttl;                        /* time to live */
        u_int8_t ip_p;                        /* protocol */
        u_short ip_sum;                        /* checksum */
        struct in_addr ip_src, ip_dst;        /* source and dest address */
    };


## htons

        #include <arpa/inet.h>
        uint32_t htonl(uint32_t hostlong);   // "Host TO Network Long"
        uint16_t htons(uint16_t hostshort);  // "Host TO Network Short"


These functions “convert values between host and network byte order”, where “Network byte order is big endian, or most significant byte first.” There are equivalent inverse functions ntohl and ntohs.

What is meant by “network byte order”? I don’t think it’s very well defined. I think it refers to the fact that a variety of network things use MSB order, including Ethernet frames and IPv4 packets. Presumably, we have to convert our numbers to MSB order because the kernel wants to copy them byte-for-byte into the IP packet.

## inet_pton

convert IPv4 and IPv6 addresses from text to binary form

    int inet_pton(int af, const char *restrict src, void *restrict dst);

This function converts the character string src into a network
address structure in the af address family, then copies the
network address structure to dst.  The af argument must be either
AF_INET or AF_INET6.  dst is written in network byte order.


    AF_INET
            src points to a character string containing an IPv4
            network address in dotted-decimal format,
            "ddd.ddd.ddd.ddd", where ddd is a decimal number of up to
            three digits in the range 0 to 255.  The address is
            converted to a struct in_addr and copied to dst, which
            must be sizeof(struct in_addr) (4) bytes (32 bits) long.


## Socket creation:

    int sockfd = socket(domain, type, protocol)

* **sockfd**: socket descriptor, an integer (like a file-handle)

* **domain**: integer, communication domain e.g., AF_INET (IPv4 protocol) , AF_INET6 (IPv6 protocol)

* **type**: communication  
**SOCK_RAW**:   Raw sockets allow new IPv4 protocols to be implemented in user space.  A raw socket receives or sends the raw datagram not including link level headers.  
**SOCK_STREAM**: TCP(reliable, connection oriented)  
**SOCK_DGRAM**: UDP(unreliable, connectionless)

* **protocol**: Protocol value for Internet Protocol(IP), which is 0. This is the same number which appears on protocol field in the IP header of a packet.

**IPPROTO_RAW** : If you use IPPROTO_RAW, you will be able to interact directly with layer 3 (IP). This means you are more low level. For example, you can edit the header and payload of your IP packet

## Setsockopt:
This helps in manipulating options for the socket referred by the file descriptor sockfd. This is completely optional, but it helps in reuse of address and port. Prevents error such as: “address already in use”.

    int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

**level**

The level at which the option is defined (for example, IPPROTO_IP).  
The socket
option level for IP is IPPROTO_IP.  A boolean integer flag is
zero when it is false, otherwise true.

**optname**

The socket option for which the value is to be set (for example, IP_HDRINCL). The optname parameter must be a socket option defined within the specified level, or behavior is undefined.

IP_HDRINCL  
(since Linux 2.0)
If enabled, the user supplies an IP header in front of the
user data.  Valid only for SOCK_RAW sockets;  When this flag is enabled, the
values set by IP_OPTIONS, IP_TTL, and IP_TOS are ignored.

**optval**

A pointer to the buffer in which the value for the requested option is specified.

**optlen**

The size, in bytes, of the buffer pointed to by the optval parameter.

### IPVERSION
ipversion implemented in netinet/ip.h

    #define	IPVERSION	4

### IP_ID
In IPv4, the Identification (ID) field is a 16-bit value that is unique for every datagram for a given source address, destination address, and protocol, such that it does not repeat within the maximum datagram lifetime (MDL) 
