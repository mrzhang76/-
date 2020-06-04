#define ETHER_ADDR_LEN 6 
#define ETHERTYPE_PUP           0x0200          /* Xerox PUP */  
#define ETHERTYPE_SPRITE        0x0500          /* Sprite */  
#define ETHERTYPE_IP            0x0800          /* IP */  
#define ETHERTYPE_ARP           0x0806          /* Address resolution */  
#define ETHERTYPE_REVARP        0x8035          /* Reverse ARP */  
#define ETHERTYPE_AT            0x809B          /* AppleTalk protocol */  
#define ETHERTYPE_AARP          0x80F3          /* AppleTalk ARP */  
#define ETHERTYPE_VLAN          0x8100          /* IEEE 802.1Q VLAN tagging */  
#define ETHERTYPE_IPX           0x8137          /* IPX */  
#define ETHERTYPE_IPV6          0x86dd          /* IP protocol version 6 */  
#define ETHERTYPE_LOOPBACK      0x9000          /* used to test interfaces */  

struct   ether_header { //以太网数据头
    u_char   ether_dhost[ETHER_ADDR_LEN]; //target mac
    u_char   ether_shost[ETHER_ADDR_LEN]; //source mac
    u_short   ether_type;  //如果上一层为IP协议。则ether_type的值就是0x0800  
};

struct ip_header  //IP数据头 小端模式__LITTLE_ENDIAN  
{
    unsigned   char     ihl : 4;              //ip   header   length  
    unsigned   char     version : 4;          //version  
    u_char              tos;                //type   of   service  
    u_short             tot_len;            //total   length  
    u_short             id;                 //identification  
    u_short             frag_off;           //fragment   offset  
    u_char              ttl;                //time   to   live  
    u_char              protocol;           //protocol   type  
    u_short             check;              //check   sum  
    u_int               saddr;              //source   address  
    u_int               daddr;              //destination   address  
};


struct udphdr //UDP数据头
{
    u_int16_t source;         /* source port */
    u_int16_t dest;         /* destination port */
    u_int16_t len;            /* udp length */
    u_int16_t checkl;         /* udp checksum */
};



u_int16_t in_cksum(u_int16_t* addr, int len)
{
    int     nleft = len;
    u_int32_t sum = 0;
    u_int16_t* w = addr;
    u_int16_t answer = 0;

    /*
    * Our algorithm is simple, using a 32 bit accumulator (sum), we add
    * sequential 16 bit words to it, and at the end, fold back all the
    * carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);     /* add carry */
    answer = ~sum;     /* truncate to 16 bits */
    return (answer);
}
struct Psd_Header {
    ULONG sourceip; //源IP地址  
    ULONG destip; //目的IP地址  
    BYTE mbz; //置空(0)  
    BYTE ptcl; //协议类型  
    USHORT plen; //TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节)  
};