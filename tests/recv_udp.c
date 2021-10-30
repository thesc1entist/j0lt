// uint8_t recvbuf[ BUF_MAX ];
// struct J0LT_DNSHDR recvheader;

bool
retrieve_dns_packet(uint8_t recvbuf[ ], size_t* buflen,
        struct J0LT_DNSHDR* recvheader)
{
    uint8_t* curpos = recvbuf;
    size_t stepsz;

    stepsz = sizeof(struct J0LT_DNSHDR);
    if (stepsz > *buflen) {
        return false;
    }

    memcpy(recvheader, ( struct J0LT_DNSHDR* ) curpos, stepsz);
    recvheader = ( struct J0LT_DNSHDR* ) curpos;
    recvheader->id = ntohs(recvheader->id);
    recvheader->qdcount = ntohs(recvheader->qdcount);
    recvheader->ancount = ntohs(recvheader->ancount);
    recvheader->nscount = ntohs(recvheader->nscount);
    recvheader->arcount = ntohs(recvheader->arcount);
    curpos += stepsz;
    *buflen -= stepsz;

    return true;
}

uint8_t
remove_byte(uint8_t** buf, size_t* buflen)
{
    uint8_t retval;
    if (*buflen < 1) {
        return -1;
    }

    retval = *(*buf)++;
    *buflen--;

    return retval;
}

uint16_t
remove_word(uint8_t** buf, size_t* buflen)
{
    uint16_t retval;

    if (*buflen < 2) {
        return -1;
    }

    retval = *(*buf)++ << 8;
    retval |= *(*buf)++;

    *buflen -= 2;

    return retval;
}
