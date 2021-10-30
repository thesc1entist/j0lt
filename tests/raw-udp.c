// https://datatracker.ietf.org/doc/html/rfc1700 (NUMBERS)
// https://www.rfc-editor.org/rfc/rfc768.html (UDP)
// https://www.rfc-editor.org/rfc/rfc760 (IP)
// use ctrl + ` to bring up a terminal then $ unshare -rn. This will give you suid to test this 

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>

#include <stdio.h> 
#include <ctype.h>
#include <stdarg.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Type of Service
 *
 *  Bits 0-2:  Precedence.
 *  Bit    3:  Stream or Datagram.
 *  Bits 4-5:  Reliability.
 *  Bit    6:  Speed over Reliability.
 *  Bits   7:  Speed.
 *
 *     0     1     2     3     4     5     6     7
 *  +-----+-----+-----+-----+-----+-----+-----+-----+
 *  |                 |     |           |     |     |
 *  |   PRECEDENCE    | STRM|RELIABILITY| S/R |SPEED|
 *  |                 |     |           |     |     |
 *  +-----+-----+-----+-----+-----+-----+-----+-----+
 *
 *  PRECEDENCE          STRM      RELIABILITY  S/R      SPEED
 *  111-Flash Override  1-STREAM  11-highest   1-speed  1-high
 *  110-Flash           0-DTGRM   10-higher    0-rlblt  0-low
 *  11X-Immediate                 01-lower
 *  01X-Priority                  00-lowest
 *  00X-Routine
 */
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

/* IP
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct __attribute__((packed, aligned(1))) J0LT_IPHDR
{
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t    version : 4; // format of the internet header (ipv4)
    uint8_t    ihl : 4;     // len of internet header in 32 bit words,
                            // and thus points to the beginning of the data.
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    uint8_t    ihl : 4;
    uint8_t    version : 4;
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

/* UDP
 * 0      7 8     15 16    23 24    31
 * +--------+--------+--------+--------+
 * |     Source      |   Destination   |
 * |      Port       |      Port       |
 * +--------+--------+--------+--------+
 * |                 |                 |
 * |     Length      |    Checksum     |
 * +--------+--------+--------+--------+
 * |
 * |          data octets ...
 * +---------------- ...
 */
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

/* Various Control Flags
*
* Bit 0: reserved, must be zero
* Bit 1: Don't Fragment This Datagram (DF).
* Bit 2: More Fragments Flag (MF).
*
*   0   1   2
* +---+---+---+
* |   | D | M |
* | 0 | F | F |
* +---+---+---+
*/
// START control flags
#define     FLAGS_DF 0b010
#define     FLAGS_MF 0b001
// END control Flags

#define     BUF_MAX 0x200
#define     IPVER 4

int main(int argc, char** argv)
{
    struct J0LT_IPHDR iphdr;
    struct sockaddr_in sin;
    uint8_t pktbuf[ BUF_MAX ];
    int raw_socket;

    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (raw_socket == -1) {
        perror("socket error");
    }

    memset(&iphdr, 0, sizeof(struct J0LT_IPHDR));
    iphdr.version = IPVER;
    iphdr.id = htonl(0x1337);
    iphdr.offset = 0;
    iphdr.flags = 0;
    iphdr.ttl = 0xff;
    iphdr.protocol = getprotobyname("udp")->p_proto;
    iphdr.checksum = 0;

    return 0;
}

/* Compute Internet Checksum for "count" bytes
 * beginning at location "addr".
 */
uint16_t checksum(const long* addr, int count)
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
